//! Where the wallet gets what it still needs, and how a backend is chosen.
//!
//! [`ChainSource`] answers "give me this transaction". That is one shape of
//! question, and it is the shape a public server serves. A private retrieval
//! answers a different one — "give me the item at this position" — and it is
//! not a transaction fetch under a different transport: the response is a
//! single action, selected by a key chosen precisely so that the transaction is
//! never named.
//!
//! [`Retrieval`] is that seam. A backend declares which [`Locator`] kinds it
//! serves, answers a batch of requests, and the write path is reached the same
//! way whichever backend answered.
//!
//! Two properties are carried by types here rather than by convention:
//!
//! - Only [`Request::locator`] may be sent. [`Request::guard`] is the local
//!   identity the applying transaction rechecks, and it exists so that a
//!   response cannot be attached to whatever now occupies a position after a
//!   reorg.
//! - `Ok(None)` for one item is a *positive negative* — the source asserts it
//!   cannot supply it — and starts an expiry clock. A transport failure is
//!   `Err` for that item and asserts nothing. Conflating the two expires live
//!   transactions and hands back the notes they spend.

use std::future::Future;

use zakura_wallet_core::retrieval::{ActionRecord, Guard, Locator, LocatorKinds};

use crate::source::{ChainSource, FetchedTransaction};

/// One thing to retrieve, with the local identity its answer is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// What is being asked for. The only part that reaches a server.
    pub locator: Locator,
    /// What the answer must reproduce, for the kinds that can be checked.
    ///
    /// Captured before the request goes out, never sent, and rechecked inside
    /// the transaction that applies the answer.
    pub guard: Option<Guard>,
}

/// What a backend gave back.
#[derive(Debug, Clone)]
pub enum Retrieved {
    /// A whole transaction, with what the source says about where it sits.
    Transaction(FetchedTransaction),
    /// One action's fields, as private retrieval returns them.
    Action(ActionRecord),
    /// One compact block.
    Block(Box<zakura_wallet_core::CompactBlock>),
}

/// A source of the things the wallet still needs.
pub trait Retrieval {
    /// What can go wrong talking to this backend.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Which locator kinds this backend serves.
    ///
    /// A static capability rather than a per-request negotiation: discovering
    /// per request that a backend cannot serve something would mean discovering
    /// it after the request had been sent, which for a private backend is
    /// exactly the disclosure it exists to prevent.
    fn serves(&self) -> LocatorKinds;

    /// Answers a batch of requests, one result per request, in order.
    fn retrieve(
        &self,
        requests: &[Request],
    ) -> impl Future<Output = Vec<Result<Option<Retrieved>, Self::Error>>> + Send;
}

/// The public backend, over an ordinary [`ChainSource`].
///
/// It serves every locator kind except an action: a lightwalletd server has no
/// way to return one action without being told which transaction it belongs to,
/// which is the disclosure the action locator exists to avoid. Asking this
/// backend for one is a programming error rather than a runtime negotiation,
/// and [`Retrieval::serves`] is what lets the caller not make it.
#[derive(Debug, Clone)]
pub struct PublicRetrieval<S> {
    source: S,
}

impl<S> PublicRetrieval<S> {
    /// Wraps a chain source as a retrieval backend.
    pub fn new(source: S) -> Self {
        Self { source }
    }

    /// The source underneath.
    pub fn source(&self) -> &S {
        &self.source
    }
}

impl<S> Retrieval for PublicRetrieval<S>
where
    S: std::ops::Deref + Sync,
    S::Target: ChainSource + Sync,
{
    type Error = <S::Target as ChainSource>::Error;

    fn serves(&self) -> LocatorKinds {
        LocatorKinds {
            status: true,
            transaction: true,
            // Not served, and deliberately: see the type's documentation.
            action: false,
            block: true,
        }
    }

    async fn retrieve(
        &self,
        requests: &[Request],
    ) -> Vec<Result<Option<Retrieved>, Self::Error>> {
        let mut out = Vec::with_capacity(requests.len());
        for request in requests {
            out.push(self.one(request).await);
        }
        out
    }
}

impl<S> PublicRetrieval<S>
where
    S: std::ops::Deref + Sync,
    S::Target: ChainSource + Sync,
{
    async fn one(
        &self,
        request: &Request,
    ) -> Result<Option<Retrieved>, <S::Target as ChainSource>::Error> {
        match request.locator {
            Locator::Status(txid) | Locator::Transaction(txid) => Ok(self
                .source
                .transaction(txid)
                .await?
                .map(Retrieved::Transaction)),
            Locator::Block { height, .. } => {
                let blocks = self
                    .source
                    .fetch(
                        height..(height + 1),
                        crate::source::ByteBudget::MOBILE,
                        crate::source::Direction::Ascending,
                    )
                    .await?;
                // An empty answer is a positive negative only in the sense that
                // the source had nothing at that height; the caller counts it
                // as an attempt rather than as proof of anything, because a
                // block that exists cannot go missing.
                Ok(blocks
                    .into_iter()
                    .next()
                    .map(|block| Retrieved::Block(Box::new(block))))
            }
            // Unreachable through a caller that consults `serves`. Returning a
            // negative rather than panicking keeps a mistake here from looking
            // like a chain event, and the caller's attempt counter bounds it.
            Locator::Action { .. } => Ok(None),
        }
    }
}
