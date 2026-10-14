//! Immutable prepared publications and atomic, reorg-fenced serving state.
use axum::{body::Bytes, http::StatusCode};
use receiver_directory::{
    Hash, RECORD_BYTES, Record,
    snapshot::{Manifest, ROW_BYTES, SLOTS},
    witness::WitnessSnapshot,
};
use receiver_pir::server::Server;
use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

/// One revision prepared for serving, with its optional common witness file and the
/// owner's report on the index it was built from.
pub struct Publication {
    pub(crate) server: Server,
    pub(crate) witnesses: Option<Bytes>,
    pub(crate) id: Hash,
    pub(crate) report: Option<serde_json::Value>,
}

impl Publication {
    /// Prepare a complete immutable revision. The caller must separately accept its chain anchor.
    /// A witness file must bind to the publication and hold a path to its root for every
    /// record in the rows.
    pub fn new(server: Server, witnesses: Option<Vec<u8>>) -> Result<Self, receiver_pir::Error> {
        if let Some(proof) = &witnesses {
            let proof = WitnessSnapshot::decode(proof, &server.manifest().directory)?;
            let rows = server.rows();
            let mut leaves = Vec::new();
            for row in rows.as_chunks::<ROW_BYTES>().0 {
                // Bytes after the last slot are row padding, not a record.
                for slot in row[..SLOTS * RECORD_BYTES].as_chunks::<RECORD_BYTES>().0 {
                    if let Some(record) = Record::decode(slot)? {
                        // `Server::new` validated every record, so positions are in the tree.
                        leaves.push((record.payment.position as u32, record.payment.cmx));
                    }
                }
            }
            proof.check_paths(leaves)?;
        }
        Ok(Self {
            id: server.id(),
            server,
            witnesses: witnesses.map(Into::into),
            report: None,
        })
    }

    /// Attaches the owner's report, such as feed freshness, which health serves with
    /// this publication's ID for monitoring, so the two activate together.
    pub fn with_report(mut self, report: serde_json::Value) -> Self {
        self.report = Some(report);
        self
    }

    /// The directory manifest this publication serves.
    pub fn manifest(&self) -> &Manifest {
        &self.server.manifest().directory
    }
}

/// How long a displaced revision keeps serving the sessions that began on it.
const GRACE: Duration = Duration::from_secs(60);

#[derive(Default)]
struct State {
    epoch: u64,
    current: Option<Arc<Publication>>,
    previous: Option<(Arc<Publication>, Instant)>,
}

impl State {
    /// The previous revision and the end of its grace, while that has not passed.
    fn live_previous(&self) -> Option<&(Arc<Publication>, Instant)> {
        self.previous
            .as_ref()
            .filter(|(_, until)| *until > Instant::now())
    }

    /// When the previous revision's grace ends, if it has not yet.
    fn grace_until(&self) -> Option<Instant> {
        self.live_previous().map(|(_, until)| *until)
    }

    /// The revisions that accept new requests, current first.
    fn live(&self) -> impl Iterator<Item = &Arc<Publication>> {
        self.current
            .iter()
            .chain(self.live_previous().map(|(p, _)| p))
    }

    /// See [`Publications::anchors`].
    fn anchors(&self) -> Vec<(u32, Hash)> {
        self.live()
            .map(|p| (p.manifest().end_height, p.manifest().end_hash))
            .collect()
    }

    /// Drops the previous revision once its grace has ended, freeing its rows and PIR
    /// state; queries still running on it keep their own reference.
    fn expire(&mut self) {
        if self.live_previous().is_none() {
            self.previous = None;
        }
    }

    /// See [`Publications::revoke`].
    fn revoke(&mut self) {
        self.epoch = self.epoch.checked_add(1).expect("recovery epoch exhausted");
        (self.current, self.previous) = (None, None);
    }
}

/// One current and one briefly retained canonical revision. Revocation also fences in-flight work.
#[derive(Clone, Default)]
pub struct Publications(Arc<RwLock<State>>);

impl Publications {
    /// Runs [`State::expire`]. Every read path calls it, including the owner's periodic
    /// [`Self::anchors`] check, so an idle service frees it within a poll; [`Self::publish`]
    /// expires under its own lock.
    fn expire(&self) {
        let state = self.0.read().unwrap();
        if state.previous.is_some() && state.live_previous().is_none() {
            drop(state);
            self.0.write().unwrap().expire();
        }
    }

    /// The recovery epoch. Every revocation advances it.
    pub fn epoch(&self) -> u64 {
        self.0.read().unwrap().epoch
    }

    /// Anchors that still accept new requests, current first. Validate independently of
    /// expensive preparation.
    pub fn anchors(&self) -> Vec<(u32, Hash)> {
        self.serving().1
    }

    /// The recovery epoch and [`Self::anchors`], read together for
    /// [`Self::revoke_serving`].
    pub fn serving(&self) -> (u64, Vec<(u32, Hash)>) {
        self.expire();
        let state = self.0.read().unwrap();
        (state.epoch, state.anchors())
    }

    /// The current session's ID with its report, and the recovery epoch, read together
    /// so health never pairs one state's session with another's epoch.
    pub(crate) fn health(&self) -> (Option<(Hash, Option<serde_json::Value>)>, u64) {
        let state = self.0.read().unwrap();
        let serving = state.current.as_ref().map(|p| (p.id, p.report.clone()));
        (serving, state.epoch)
    }

    /// When the next revision may activate, if the previous one is still in its grace.
    /// Activating only after it ends gives every displaced revision its full grace, so
    /// two quick rotations cannot strand a session.
    pub fn ready_at(&self) -> Option<Instant> {
        self.expire();
        self.0.read().unwrap().grace_until()
    }

    /// Install only if no revocation occurred since the caller began preparing and validating,
    /// no earlier revision is still in its grace (see [`Self::ready_at`]), and the current
    /// revision ends no higher: within one epoch the chain only extends, so a lower end
    /// comes from a preparation that a newer publish overtook. A publication with the
    /// current session's ID replaces it in place, keeping the epoch and any predecessor's
    /// grace. It expects one serial publisher (the indexer awaits each publish), so
    /// equal-height preparations need no further ordering.
    /// The caller must verify the new canonical anchor and revoke before replacing forked coverage.
    pub fn publish(&self, publication: Publication, expected_epoch: u64) -> bool {
        let mut state = self.0.write().unwrap();
        if state.epoch != expected_epoch {
            return false;
        }
        state.expire();
        if state
            .current
            .as_ref()
            .is_some_and(|p| p.id == publication.id)
        {
            state.current = Some(Arc::new(publication));
            return true;
        }
        let end = publication.manifest().end_height;
        if state.grace_until().is_some()
            || state
                .current
                .as_ref()
                .is_some_and(|p| p.manifest().end_height > end)
        {
            return false;
        }
        state.previous = state.current.take().map(|p| (p, Instant::now() + GRACE));
        state.current = Some(Arc::new(publication));
        true
    }

    /// Conservatively invalidate all sessions, including CPU work that started before the reorg.
    pub fn revoke(&self) {
        self.0.write().unwrap().revoke();
    }

    /// For a check that read `epoch` and `anchor` from [`Self::serving`] and found the
    /// anchor off the chain: revokes as [`Self::revoke`] does, but atomically only if
    /// `epoch` is still current and `anchor` still accepts requests, so a publication
    /// made after a revocation, or after `anchor`'s grace ended, survives the stale
    /// result. An anchor in its grace still revokes every session. Returns whether it
    /// revoked.
    pub fn revoke_serving(&self, epoch: u64, anchor: (u32, Hash)) -> bool {
        let mut state = self.0.write().unwrap();
        if state.epoch != epoch || !state.anchors().contains(&anchor) {
            return false;
        }
        state.revoke();
        true
    }

    /// The publication `id` names, or the current one for `None`, with the current
    /// epoch. An id not served now, whether unknown, revoked or expired, is `GONE`.
    pub(crate) fn select(&self, id: Option<Hash>) -> Result<(Arc<Publication>, u64), StatusCode> {
        self.expire();
        let state = self.0.read().unwrap();
        if let Some(id) = id {
            return match state.live().find(|p| p.id == id) {
                Some(p) => Ok((p.clone(), state.epoch)),
                None => Err(StatusCode::GONE),
            };
        }
        state
            .current
            .clone()
            .map(|p| (p, state.epoch))
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty prepared publication whose salt starts with `salt`.
    fn publication(salt: u8) -> Publication {
        publication_at(salt, 3)
    }

    /// An empty prepared publication whose salt starts with `salt`, ending at a block
    /// hash of `hash` bytes.
    fn publication_at(salt: u8, hash: u8) -> Publication {
        let mut manifest = crate::common::manifest(receiver_pir::MIN_ROWS);
        manifest.salt[0] = salt;
        manifest.end_hash = [hash; 32];
        let snapshot = receiver_directory::snapshot::Snapshot::build(manifest, &[], &[]).unwrap();
        Publication::new(Server::new(snapshot).unwrap(), None).unwrap()
    }

    /// A check that found an anchor off the chain revokes only while its epoch is
    /// current and the anchor still accepts requests.
    #[test]
    fn a_stale_check_revokes_only_while_its_anchor_is_served() {
        let (a, b) = ((101, [1; 32]), (101, [2; 32]));
        let publications = Publications::default();
        assert!(publications.publish(publication_at(1, 1), 0));
        // A check reads A, then a revocation and B's publication overtake it.
        let (epoch, anchors) = publications.serving();
        assert_eq!(anchors, [a]);
        publications.revoke();
        assert!(publications.publish(publication_at(2, 2), epoch + 1));
        assert!(!publications.revoke_serving(epoch, a));
        assert_eq!(publications.serving(), (epoch + 1, vec![b]));
        // An ordinary rotation keeps the epoch, but once A's grace ends a check that
        // read A no longer revokes C.
        let publications = Publications::default();
        assert!(publications.publish(publication_at(1, 1), 0));
        let (epoch, _) = publications.serving();
        assert!(publications.publish(publication_at(3, 3), 0));
        let ended = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        publications.0.write().unwrap().previous.as_mut().unwrap().1 = ended;
        assert!(!publications.revoke_serving(epoch, a));
        assert_eq!(publications.anchors(), [(101, [3; 32])]);
        // A served anchor off the chain still revokes every session.
        assert!(publications.revoke_serving(epoch, (101, [3; 32])));
        assert_eq!(publications.serving(), (epoch + 1, vec![]));
    }

    /// A preparation overtaken by a newer publish cannot replace it, even once the
    /// newer one's predecessor has left its grace.
    #[test]
    fn an_overtaken_preparation_is_not_published() {
        let publications = Publications::default();
        assert!(publications.publish(publication_at(1, 1), 0));
        let mut newer = crate::common::manifest(receiver_pir::MIN_ROWS);
        (newer.end_height, newer.end_hash) = (102, [2; 32]);
        let snapshot = receiver_directory::snapshot::Snapshot::build(newer, &[], &[]).unwrap();
        let newer = Publication::new(Server::new(snapshot).unwrap(), None).unwrap();
        assert!(publications.publish(newer, 0));
        let ended = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        publications.0.write().unwrap().previous.as_mut().unwrap().1 = ended;
        assert!(!publications.publish(publication_at(3, 3), 0));
        assert_eq!(publications.anchors(), [(102, [2; 32])]);
    }

    /// An anchor still in its grace revokes the current publication with it.
    #[test]
    fn an_anchor_in_its_grace_still_revokes_every_session() {
        let publications = Publications::default();
        assert!(publications.publish(publication_at(1, 1), 0));
        let (epoch, _) = publications.serving();
        assert!(publications.publish(publication_at(2, 2), 0));
        assert!(publications.revoke_serving(epoch, (101, [1; 32])));
        assert!(publications.anchors().is_empty());
    }

    /// A displaced revision is dropped once its grace ends, not kept until the next
    /// publication, and its id is then 410.
    #[test]
    fn an_expired_previous_publication_is_dropped() {
        let publications = Publications::default();
        assert!(publications.publish(publication(1), 0));
        let first = Arc::downgrade(publications.0.read().unwrap().current.as_ref().unwrap());
        let id = first.upgrade().unwrap().id;
        assert!(publications.publish(publication(2), 0));
        assert!(publications.select(Some(id)).is_ok());
        assert!(first.upgrade().is_some());
        let ended = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        publications.0.write().unwrap().previous.as_mut().unwrap().1 = ended;
        assert_eq!(publications.anchors().len(), 1);
        assert!(first.upgrade().is_none());
        assert!(matches!(
            publications.select(Some(id)),
            Err(StatusCode::GONE)
        ));
    }

    /// Republishing the current session replaces it without a new grace or epoch, keeps
    /// a predecessor's deadline, and still honors the epoch fence.
    #[test]
    fn republishing_the_current_session_replaces_it_in_place() {
        let publications = Publications::default();
        assert!(publications.publish(publication(1), 0));
        assert!(!publications.publish(publication(1), 1));
        assert!(publications.publish(publication(1), 0));
        assert_eq!(publications.epoch(), 0);
        assert!(publications.ready_at().is_none());
        // With no grace pending, a new session activates at once.
        assert!(publications.publish(publication(2), 0));
        let ready = publications.ready_at().unwrap();
        assert!(publications.publish(publication(2), 0));
        assert_eq!(publications.ready_at(), Some(ready));
        assert_eq!(publications.anchors().len(), 2);
    }

    /// A publication with records at positions 0 and 5 of an 8-leaf tree, and the
    /// witness file built from `tree` for those positions.
    fn witnessed(tree: &[Hash]) -> (receiver_directory::snapshot::Snapshot, Vec<u8>) {
        let mut manifest = crate::common::manifest(receiver_pir::MIN_ROWS);
        manifest.start_position = 0;
        manifest.end_position = 8;
        let records: Vec<_> = [0u8, 5]
            .into_iter()
            .enumerate()
            .map(|(page, position)| {
                let mut record = crate::common::record(page as u32, 2);
                record.payment.position = position.into();
                record.payment.cmx = [position + 1; 32];
                record
            })
            .collect();
        let snapshot =
            receiver_directory::snapshot::Snapshot::build(manifest, &records, &[]).unwrap();
        let positions = [0, 5].into_iter().collect();
        let proof = WitnessSnapshot::build(&snapshot.manifest, tree, &positions)
            .unwrap()
            .encode();
        (snapshot, proof)
    }

    /// A file that binds to the publication but lacks a sibling a record needs, or
    /// whose tree holds another commitment at a record's position, is refused.
    #[test]
    fn witnesses_must_prove_every_served_record() {
        use receiver_directory::Error::{Coverage, Malformed};
        use receiver_pir::Error::Directory;
        let tree: Vec<Hash> = (1..=8).map(|i| [i; 32]).collect();
        let publish =
            |snapshot, proof| Publication::new(Server::new(snapshot).unwrap(), Some(proof));
        let (snapshot, proof) = witnessed(&tree);
        publish(snapshot.clone(), proof.clone()).unwrap();
        // Drop position 5's level-0 sibling, (0, 4), which position 0 does not use, and
        // correct the node count, without going through the builder.
        let mut incomplete = proof;
        let node = incomplete[152..]
            .chunks_exact(37)
            .position(|n| n[0] == 0 && n[1..5] == 4u32.to_le_bytes())
            .unwrap();
        incomplete.drain(152 + node * 37..152 + (node + 1) * 37);
        let count = u32::from_le_bytes(incomplete[148..152].try_into().unwrap()) - 1;
        incomplete[148..152].copy_from_slice(&count.to_le_bytes());
        let decoded = WitnessSnapshot::decode(&incomplete, &snapshot.manifest).unwrap();
        decoded.path(0, tree[0]).unwrap();
        assert!(decoded.path(5, tree[5]).is_err());
        assert!(matches!(
            publish(snapshot, incomplete),
            Err(Directory(Coverage))
        ));
        let mut other = tree;
        other[5] = [9; 32];
        let (snapshot, proof) = witnessed(&other);
        assert!(matches!(
            publish(snapshot, proof),
            Err(Directory(Malformed))
        ));
    }
}
