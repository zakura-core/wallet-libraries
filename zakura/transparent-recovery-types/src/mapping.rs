//! Explicit hash conversion at a wallet integration boundary. No records are validated here.
use super::*;

impl<Hash> ChainPoint<Hash> {
    /// Changes only the hash representation; does not establish local chain acceptance.
    pub fn map_block_hash<Other>(self, mut map: impl FnMut(Hash) -> Other) -> ChainPoint<Other> {
        ChainPoint {
            height: self.height,
            hash: map(self.hash),
        }
    }
}

impl<Hash> PublicationAnchor<Hash> {
    /// Changes only the hash representation; the anchor remains a publisher assertion.
    pub fn map_block_hash<Other>(
        self,
        mut map: impl FnMut(Hash) -> Other,
    ) -> PublicationAnchor<Other> {
        PublicationAnchor {
            height: self.height,
            hash: map(self.hash),
        }
    }
}

impl<Hash> RecoveryRevision<Hash> {
    /// Preserves the source, revision, lineage and sealing while converting its anchor.
    pub fn map_block_hash<Other>(self, map: impl FnMut(Hash) -> Other) -> RecoveryRevision<Other> {
        RecoveryRevision {
            source: self.source,
            revision: self.revision,
            lineage: self.lineage,
            sealed: self.sealed,
            publication: self.publication.map_block_hash(map),
        }
    }
}

impl<Hash> PendingPage<Hash> {
    /// Preserves the page request and converts both recorded chain positions.
    pub fn map_block_hash<Other>(self, mut map: impl FnMut(Hash) -> Other) -> PendingPage<Other> {
        PendingPage {
            request: self.request,
            revision: self.revision.map_block_hash(&mut map),
            target: self.target.map_block_hash(map),
        }
    }
}

impl<AccountId, Hash> TransparentRecoveryContext<AccountId, Hash> {
    /// Preserves the captured account, lifecycle and policy generation while converting its target.
    pub fn map_block_hash<Other>(
        self,
        map: impl FnMut(Hash) -> Other,
    ) -> TransparentRecoveryContext<AccountId, Other> {
        TransparentRecoveryContext {
            account: self.account,
            lifecycle: self.lifecycle,
            policy_generation: self.policy_generation,
            target: self.target.map_block_hash(map),
        }
    }
}

impl<AccountId, Hash> TransparentAddressWatchSet<AccountId, Hash> {
    /// Preserves the captured watch set and converts every target and pending-page anchor.
    pub fn map_block_hash<Other>(
        self,
        mut map: impl FnMut(Hash) -> Other,
    ) -> TransparentAddressWatchSet<AccountId, Other> {
        TransparentAddressWatchSet {
            account: self.account,
            lifecycle: self.lifecycle,
            policy_generation: self.policy_generation,
            addresses: self.addresses,
            target: self.target.map(|point| point.map_block_hash(&mut map)),
            pending_pages: self
                .pending_pages
                .into_iter()
                .map(|page| page.map_block_hash(&mut map))
                .collect(),
        }
    }
}

impl<AccountId, Hash> TransparentLedgerCommit<AccountId, Hash> {
    /// Converts the context, publication and accepted anchor without changing any candidate facts.
    pub fn map_block_hash<Other>(
        self,
        mut map: impl FnMut(Hash) -> Other,
    ) -> TransparentLedgerCommit<AccountId, Other> {
        TransparentLedgerCommit {
            context: self.context.map_block_hash(&mut map),
            revision: self.revision.map_block_hash(&mut map),
            anchor: self.anchor.map_block_hash(map),
            receives: self.receives,
            spends: self.spends,
            coverage: self.coverage,
            unsupported: self.unsupported,
            opened_pages: self.opened_pages,
            completed_pages: self.completed_pages,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transparent::address::TransparentAddress;

    #[test]
    fn mapping_preserves_context_pending_pages_and_commit_facts() {
        let point = ChainPoint {
            height: 23u32.into(),
            hash: RecoveryBlockHash([1; 32]),
        };
        let revision = RecoveryRevision {
            source: vec![2],
            revision: vec![3],
            lineage: 4,
            sealed: false,
            publication: PublicationAnchor {
                height: 22u32.into(),
                hash: RecoveryBlockHash([5; 32]),
            },
        };
        let address = TransparentAddress::PublicKeyHash([6; 20]);
        let page = PageRequest {
            page: vec![7],
            addresses: vec![address],
            from: 20u32.into(),
            through: 22u32.into(),
        };
        let watch = TransparentAddressWatchSet {
            account: 8u32,
            lifecycle: AccountLifecycle::Candidate,
            policy_generation: 9,
            target: Some(point),
            addresses: vec![WatchedAddress {
                address,
                origin: WatchOrigin::Standalone,
                required_from: 20u32.into(),
            }],
            pending_pages: vec![PendingPage {
                request: page.clone(),
                revision: revision.clone(),
                target: point,
            }],
        };
        let mapped = watch.clone().map_block_hash(|hash| hash.0);
        assert_eq!(mapped.target.unwrap().hash, [1; 32]);
        assert_eq!(mapped.pending_pages[0].revision.publication.hash, [5; 32]);
        assert_eq!(mapped.map_block_hash(RecoveryBlockHash), watch);

        let commit = TransparentLedgerCommit {
            context: watch.context().unwrap(),
            revision,
            anchor: point,
            receives: vec![],
            spends: vec![],
            coverage: vec![AddressRange {
                address,
                from: 20u32.into(),
                through: 22u32.into(),
            }],
            unsupported: vec![],
            opened_pages: vec![page],
            completed_pages: vec![vec![10]],
        };
        let mapped = commit.clone().map_block_hash(|hash| hash.0);
        assert_eq!(mapped.context.target.hash, [1; 32]);
        assert_eq!(mapped.revision.publication.hash, [5; 32]);
        assert_eq!(mapped.map_block_hash(RecoveryBlockHash), commit);
    }
}
