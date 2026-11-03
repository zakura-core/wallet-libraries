//! Blocking delivery of scan results, with a soft queued-payload count.
//!
//! Each transaction has one receiver and a sender clone per output. A sender
//! sends at most once; outputs that do not decrypt simply drop their sender.
//! The final sender drop completes the receiver, including an empty result.

use std::sync::{
    Arc, Mutex, PoisonError,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};

pub(super) struct Sender<T> {
    inner: mpsc::Sender<T>,
    queued: Arc<AtomicUsize>,
}

// Implement this explicitly so cloning a sender does not require T: Clone.
impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            queued: Arc::clone(&self.queued),
        }
    }
}

pub(super) struct Receiver<T> {
    // Only into_iter accesses this receiver. The mutex preserves Sync for a
    // Send payload, matching the receiver used by the async scanning path.
    inner: Mutex<mpsc::Receiver<T>>,
    queued: Arc<AtomicUsize>,
}

pub(super) fn unbounded<T>() -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = mpsc::channel();
    let queued = Arc::new(AtomicUsize::new(0));
    (
        Sender {
            inner: sender,
            queued: Arc::clone(&queued),
        },
        Receiver {
            inner: Mutex::new(receiver),
            queued,
        },
    )
}

impl<T> Sender<T> {
    pub(super) fn send(&self, item: T) -> Result<(), mpsc::SendError<T>> {
        // Count before publishing so a concurrent receive cannot underflow.
        // The count can briefly include an in-flight send; failed sends undo
        // it. At most one result is sent per transaction output, so even the
        // in-flight count is bounded by the output count, which fits usize.
        self.queued.fetch_add(1, Ordering::Relaxed);
        let result = self.inner.send(item);
        if result.is_err() {
            self.queued.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }
}

impl<T> Receiver<T> {
    pub(super) fn len(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    pub(super) fn into_iter(self) -> impl Iterator<Item = T> {
        let Self { inner, queued } = self;
        inner
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .into_iter()
            .inspect(move |_| {
                queued.fetch_sub(1, Ordering::Relaxed);
            })
    }
}

// Dropping the receiver or its iterator discards buffered results through MPSC.
// No count is read afterward; remaining senders only make failing sends, whose
// temporary increments are balanced. The last endpoint drops the shared count.

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        sync::{Arc, Barrier, Mutex, atomic::Ordering, mpsc},
        thread,
        time::Duration,
    };

    use super::{Receiver, Sender, unbounded};

    #[derive(Debug, PartialEq)]
    struct ResultValue(usize);

    #[derive(Debug)]
    struct DropProbe {
        index: usize,
        dropped: Arc<Mutex<Vec<usize>>>,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.dropped.lock().unwrap().push(self.index);
        }
    }

    fn buffered_probes() -> (
        Sender<DropProbe>,
        Receiver<DropProbe>,
        Arc<Mutex<Vec<usize>>>,
    ) {
        let dropped = Arc::new(Mutex::new(Vec::new()));
        let (sender, receiver) = unbounded();
        for index in 0..3 {
            sender
                .clone()
                .send(DropProbe {
                    index,
                    dropped: Arc::clone(&dropped),
                })
                .unwrap();
        }
        (sender, receiver, dropped)
    }

    #[test]
    fn an_empty_result_completes_when_its_sender_drops() {
        let (sender, receiver) = unbounded::<ResultValue>();
        assert_eq!(receiver.len(), 0);
        drop(sender);
        assert!(receiver.into_iter().next().is_none());
    }

    #[test]
    fn cloned_senders_deliver_indices_and_non_clone_payloads() {
        let (sender, receiver) = unbounded();
        let other = sender.clone();
        sender.send((2, ResultValue(11))).unwrap();
        other.send((7, ResultValue(19))).unwrap();
        assert_eq!(receiver.len(), 2);
        drop(sender);
        drop(other);
        assert_eq!(
            receiver.into_iter().collect::<Vec<_>>(),
            [(2, ResultValue(11)), (7, ResultValue(19))],
        );
    }

    #[test]
    fn completion_waits_for_a_sender_that_produces_no_result() {
        let (sender, receiver) = unbounded();
        let no_result = sender.clone();
        sender.send(ResultValue(5)).unwrap();
        drop(sender);

        let (first, received_first) = mpsc::channel();
        let (completed, received_completion) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut results = receiver.into_iter();
            first.send(results.next()).unwrap();
            completed.send(results.next().is_none()).unwrap();
        });
        assert_eq!(
            received_first.recv_timeout(Duration::from_secs(5)).unwrap(),
            Some(ResultValue(5)),
        );
        assert!(matches!(
            received_completion.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        drop(no_result);
        assert!(
            received_completion
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
        );
        reader.join().unwrap();
    }

    #[test]
    fn receiving_results_reduces_the_payload_count() {
        let (sender, receiver) = unbounded();
        let other = sender.clone();
        sender.send(ResultValue(1)).unwrap();
        other.send(ResultValue(2)).unwrap();
        drop(sender);
        drop(other);
        let queued = Arc::clone(&receiver.queued);
        let mut results = receiver.into_iter();
        assert_eq!(queued.load(Ordering::Relaxed), 2);
        assert_eq!(results.next(), Some(ResultValue(1)));
        assert_eq!(queued.load(Ordering::Relaxed), 1);
        assert_eq!(results.next(), Some(ResultValue(2)));
        assert_eq!(queued.load(Ordering::Relaxed), 0);
        assert!(results.next().is_none());
        assert_eq!(queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_dropped_receiver_returns_the_unsent_payload_without_counting_it() {
        let (sender, receiver) = unbounded();
        drop(receiver);
        assert_eq!(sender.send(ResultValue(23)).unwrap_err().0, ResultValue(23));
        assert_eq!(sender.queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dropping_a_receiver_discards_buffered_payloads_with_a_sender_alive() {
        let (sender, receiver, dropped) = buffered_probes();
        assert_eq!(receiver.len(), 3);
        drop(receiver);
        dropped.lock().unwrap().sort_unstable();
        assert_eq!(*dropped.lock().unwrap(), [0, 1, 2]);

        let unsent = sender
            .send(DropProbe {
                index: 3,
                dropped: Arc::clone(&dropped),
            })
            .unwrap_err();
        assert_eq!(*dropped.lock().unwrap(), [0, 1, 2]);
        drop(unsent);
        assert_eq!(*dropped.lock().unwrap(), [0, 1, 2, 3]);
    }

    #[test]
    fn dropping_a_partial_iterator_discards_buffered_payloads_with_a_sender_alive() {
        let (sender, receiver, dropped) = buffered_probes();
        let mut results = receiver.into_iter();
        let first = results.next().unwrap();
        assert_eq!(first.index, 0);
        assert!(dropped.lock().unwrap().is_empty());
        drop(first);
        assert_eq!(*dropped.lock().unwrap(), [0]);
        drop(results);
        dropped.lock().unwrap().sort_unstable();
        assert_eq!(*dropped.lock().unwrap(), [0, 1, 2]);

        let unsent = sender
            .send(DropProbe {
                index: 3,
                dropped: Arc::clone(&dropped),
            })
            .unwrap_err();
        drop(unsent);
        assert_eq!(*dropped.lock().unwrap(), [0, 1, 2, 3]);
    }

    #[test]
    fn concurrent_producers_and_draining_preserve_every_result_and_balance_the_count() {
        const PRODUCERS: usize = 8;
        const ROUNDS: usize = 32;

        let (sender, receiver) = unbounded();
        let queued = Arc::clone(&receiver.queued);
        let barrier = Barrier::new(PRODUCERS + 1);
        let producer_senders: Vec<Vec<_>> = (0..PRODUCERS)
            .map(|_| (0..ROUNDS).map(|_| sender.clone()).collect())
            .collect();
        drop(sender);

        let (mut received, drained_counts) = thread::scope(|scope| {
            for (producer, senders) in producer_senders.into_iter().enumerate() {
                let barrier = &barrier;
                scope.spawn(move || {
                    for (round, sender) in senders.into_iter().enumerate() {
                        barrier.wait();
                        sender.send(producer * ROUNDS + round).unwrap();
                        barrier.wait();
                    }
                });
            }

            let mut received = Vec::new();
            let mut drained_counts = Vec::new();
            let mut results = receiver.into_iter();
            for _ in 0..ROUNDS {
                barrier.wait();
                for _ in 0..PRODUCERS {
                    received.push(results.next().unwrap());
                }
                drained_counts.push(queued.load(Ordering::Relaxed));
                barrier.wait();
            }
            assert!(results.next().is_none());
            (received, drained_counts)
        });

        // Check accounting after the producers join, so a failed assertion
        // cannot leave them waiting at a barrier.
        assert!(drained_counts.into_iter().all(|count| count == 0));
        received.sort_unstable();
        assert_eq!(received, (0..PRODUCERS * ROUNDS).collect::<Vec<_>>());
        assert_eq!(queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn endpoints_remain_send_and_sync_without_a_sync_payload() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Sender<Cell<usize>>>();
        assert_send_sync::<Receiver<Cell<usize>>>();
    }

    #[test]
    fn scan_receivers_and_runners_retain_their_auto_traits() {
        use sapling::{
            bundle::{GrothProofBytes, OutputDescription},
            note_encryption::SaplingDomain,
        };

        use crate::scan::{BatchReceiver, BatchRunner, FullDecryptor};

        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BatchReceiver<Cell<usize>, SaplingDomain, ()>>();
        assert_send_sync::<
            BatchRunner<
                usize,
                SaplingDomain,
                OutputDescription<GrothProofBytes>,
                FullDecryptor,
                (),
            >,
        >();
    }
}
