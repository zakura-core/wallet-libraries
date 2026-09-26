//! Public status source using the existing lightwalletd `GetTransaction` RPC.
//! The payload is validated against the requested txid and then discarded.
use crate::{StatusError, StatusObservation, StatusRequest, StatusSession, StatusSource};
use std::{future::Future, time::Duration};
use tonic::{Code, Request, transport::Channel};
use zcash_client_backend::proto::service::{
    RawTransaction, TxFilter, compact_tx_streamer_client::CompactTxStreamerClient,
};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId};

const TIMEOUT: Duration = Duration::from_secs(20);

/// The opener is called only when public status is selected. This lets a
/// private reader hold a public endpoint without connecting to it.
pub struct LightwalletdSource<Open, Cancel> {
    open: Open,
    cancelled: Cancel,
}

impl<Open, Cancel> LightwalletdSource<Open, Cancel> {
    pub fn new(open: Open, cancelled: Cancel) -> Self {
        Self { open, cancelled }
    }
}

pub struct LightwalletdSession<Cancel> {
    client: CompactTxStreamerClient<Channel>,
    cancelled: Cancel,
}

impl<Open, Fut, Cancel> StatusSource for LightwalletdSource<Open, Cancel>
where
    Open: FnOnce() -> Fut,
    Fut: Future<Output = Result<CompactTxStreamerClient<Channel>, StatusError>>,
    Cancel: Fn() -> bool + Sync,
{
    type Session = LightwalletdSession<Cancel>;

    async fn open(self) -> Result<Self::Session, StatusError> {
        let Self { open, cancelled } = self;
        let client = guarded(open(), &cancelled).await?;
        Ok(LightwalletdSession { client, cancelled })
    }
}

impl<Cancel: Fn() -> bool + Sync> StatusSession for LightwalletdSession<Cancel> {
    async fn observe(&mut self, request: StatusRequest) -> Result<StatusObservation, StatusError> {
        let client = &mut self.client;
        let response = guarded(
            async { Ok(get_transaction(client, request.txid).await) },
            &self.cancelled,
        )
        .await?;
        decode_response(request.txid, response)
    }
}

/// Every network step, including opening the source, is bounded by both the
/// caller's cancellation and `TIMEOUT`.
async fn guarded<T>(
    future: impl Future<Output = Result<T, StatusError>>,
    cancelled: &impl Fn() -> bool,
) -> Result<T, StatusError> {
    if cancelled() {
        return Err(StatusError::Cancelled);
    }
    let result = tokio::select! {
        biased;
        _ = async {
            while !cancelled() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        } => return Err(StatusError::Cancelled),
        result = tokio::time::timeout(TIMEOUT, future) => {
            result.unwrap_or(Err(StatusError::Timeout))
        }
    };
    if cancelled() {
        return Err(StatusError::Cancelled);
    }
    result
}

async fn get_transaction(
    client: &mut CompactTxStreamerClient<Channel>,
    txid: TxId,
) -> Result<RawTransaction, tonic::Status> {
    let mut request = Request::new(TxFilter {
        block: None,
        index: 0,
        hash: txid.as_ref().to_vec(),
    });
    request.set_timeout(TIMEOUT);
    client
        .get_transaction(request)
        .await
        .map(|response| response.into_inner())
}

fn decode_response(
    txid: TxId,
    response: Result<RawTransaction, tonic::Status>,
) -> Result<StatusObservation, StatusError> {
    match response {
        Ok(raw) => decode(txid, raw),
        Err(error) if error.code() == Code::NotFound => Ok(StatusObservation::NotFound),
        Err(error) => Err(error.into()),
    }
}

/// The payload must be exactly one transaction with the requested txid.
fn decode(txid: TxId, raw: RawTransaction) -> Result<StatusObservation, StatusError> {
    let mut data = &raw.data[..];
    let transaction =
        Transaction::read(&mut data, BranchId::Sapling).map_err(|_| StatusError::Malformed)?;
    if !data.is_empty() || transaction.txid() != txid {
        return Err(StatusError::Malformed);
    }
    Ok(match raw.height {
        0 => StatusObservation::Mempool,
        u64::MAX => StatusObservation::Forked,
        1..=0xffff_ffff => StatusObservation::Mined(BlockHeight::from_u32(raw.height as u32)),
        _ => return Err(StatusError::Malformed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_not_found_means_absence() {
        let txid = TxId::from_bytes([0; 32]);
        assert_eq!(
            decode_response(txid, Err(tonic::Status::not_found("private txid"))),
            Ok(StatusObservation::NotFound)
        );
        for code in [Code::Unavailable, Code::DeadlineExceeded, Code::Cancelled] {
            let error =
                decode_response(txid, Err(tonic::Status::new(code, "private txid"))).unwrap_err();
            assert_ne!(error, StatusError::Malformed);
            assert!(!error.to_string().contains("private txid"));
        }
    }

    #[test]
    fn payload_must_match_requested_txid() {
        use zcash_primitives::transaction::{Authorized, TransactionData, TxVersion};
        let transaction = TransactionData::<Authorized>::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            BlockHeight::from_u32(1),
            None,
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();
        let mut data = Vec::new();
        transaction.write(&mut data).unwrap();
        let raw = RawTransaction { data, height: 42 };
        assert_eq!(
            decode(txid_other(), raw.clone()),
            Err(StatusError::Malformed)
        );
        let mut trailing = raw.clone();
        trailing.data.push(0);
        assert_eq!(
            decode(transaction.txid(), trailing),
            Err(StatusError::Malformed)
        );
        assert_eq!(
            decode(transaction.txid(), raw),
            Ok(StatusObservation::Mined(BlockHeight::from_u32(42)))
        );
    }

    fn txid_other() -> TxId {
        TxId::from_bytes([0; 32])
    }

    #[tokio::test]
    async fn cancellation_prevents_request() {
        let mut ran = false;
        let result = guarded(
            async {
                ran = true;
                Ok(())
            },
            &|| true,
        )
        .await;
        assert_eq!(result, Err(StatusError::Cancelled));
        assert!(!ran);
    }

    #[tokio::test(start_paused = true)]
    async fn opening_is_bounded_by_the_status_timeout() {
        let source = LightwalletdSource::new(
            std::future::pending::<Result<CompactTxStreamerClient<Channel>, StatusError>>,
            || false,
        );
        assert!(matches!(source.open().await, Err(StatusError::Timeout)));
    }
}
