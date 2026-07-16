
use alloc::collections::{BTreeMap, BTreeSet};
use bitcoin::{absolute, Txid, Transaction, Amount};
use bitcoin::constants::ChainHash;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};
use lightning_types::features::InitFeatures;
use secp256k1_musig::musig;

use core::marker::PhantomData;
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::chain::channelmonitor::ChannelMonitorUpdate;
use crate::chain::transaction::OutPoint;
// :vomit_emoji:
use crate::prelude::*;

use crate::ln::eltoo::chain;
use crate::ln::types::ChannelId;
use crate::ln::channelmanager::{self, InterceptId, InboundChannelRequest, MonitorUpdateCompletionAction, RAAMonitorUpdateBlockingAction};
use crate::ln::inbound_payment;
use crate::ln::outbound_payment::{
	OutboundPayments,
};
use crate::ln::msgs::{self, MessageSendEvent, BaseMessageHandler};
use crate::chain::{BlockLocator, ChannelMonitorUpdateStatus, Confirm};
use crate::chain::chaininterface::{ BroadcasterInterface, FeeEstimator, LowerBoundedFeeEstimator, };

use crate::events;

use crate::onion_message::messenger::{
	MessageRouter, MessageSendInstructions, Responder, ResponseInstruction,
};

use crate::routing::gossip::NetworkGraph;
use crate::routing::router::{
	BlindedTail, FixedRouter, InFlightHtlcs, Path, Payee, PaymentParameters, Route,
	RouteParameters, RouteParametersConfig, Router, DefaultRouter,
};

use crate::sign::{EntropySource, NodeSigner, Recipient, SignerProvider, KeysManager};

use crate::sync::{Arc, FairRwLock, LockHeldState, LockTestExt, Mutex, RwLock, RwLockReadGuard};
use crate::util::logger::{Level, Logger, WithContext};
use crate::util::wakers::{Future, Notifier};

#[cfg(not(c_bindings))]
use crate::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters};

struct MilliSatoshi(u64);

impl MilliSatoshi {
    pub fn from_msat(msat: u64) -> Self { Self(msat) }

    pub fn to_amount(self) -> (Amount, MilliSatoshi) {
        (
            Amount::from_sat(self.0 / 1000),
            Self(self.0 % 1000),
        )
    }

    pub fn to_msat(self) -> u64 { self.0 }
}

struct ChannelFunding {
    transaction: Transaction,
    vout: usize,
}

struct ChannelParty {
    settlement_pubkey: PublicKey,

    balance: MilliSatoshi,

    pub max_htlc_value_in_flight: MilliSatoshi,

    pub max_accepted_htlcs: u16,

    /// Last public nonce received for this channel party and the update number it is valid for
    pub last_nonce: Option<(u64, musig::PublicNonce)>,
}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
struct HtlcId {
    /// offering party index
    pub offerer: usize,
    /// durable id assigned by the offering party
    pub id: u64,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
struct Htlc {
    pub to: usize,
    pub expiry: absolute::Height,
    pub hash: sha256::Hash,
}

const DUST_LIMIT: Amount = Amount::from_sat(330);

struct ChannelConfig {
    pub shared_delay: absolute::LockTime,
}

struct FundedChannel {
    funding: ChannelFunding,

	parties: Vec<ChannelParty>,

    htlcs: BTreeMap<HtlcId, Htlc>,

    preimages: BTreeMap<sha256::Hash, [u8; 32]>,

    self_party: usize,
}

enum ChannelPhase {
    UnfundedInboundChannel(ChannelFunding),
    UnfundedOutboundChannel(ChannelFunding),
    Funded(FundedChannel),
}

struct Channel<SP: SignerProvider> {
    _phantom: PhantomData<SP>,
    phase: ChannelPhase,
}

pub(super) struct PeerState<SP: SignerProvider> {
	/// `channel_id` -> `Channel`
	///
	/// Holds all channels where the peer is the counterparty.
	pub(super) channel_by_id: HashMap<ChannelId, Channel<SP>>,
	/// `temporary_channel_id` -> `InboundChannelRequest`.
	///
	/// Holds all unaccepted inbound channels where the peer is the counterparty.
	/// If the channel is accepted, then the entry in this table is removed and a Channel is
	/// created and placed in the `channel_by_id` table. If the channel is rejected, then
	/// the entry is simply removed.
	pub(super) inbound_channel_request_by_id: HashMap<ChannelId, InboundChannelRequest>,
	latest_features: InitFeatures,
	//pub(super) pending_msg_events: Vec<MessageSendEvent>,
	/// Map from Channel IDs to pending [`ChannelMonitorUpdate`]s which have been passed to the
	/// user but which have not yet completed. We still keep the funding outpoint around to backfill
	/// the legacy TLV field to support downgrading.
	///
	/// Note that the channel may no longer exist. For example if the channel was closed but we
	/// later needed to claim an HTLC which is pending on-chain, we may generate a monitor update
	/// for a missing channel.
	///
	/// Note that any pending [`BackgroundEvent::MonitorUpdateRegeneratedOnStartup`]s which are
	/// sitting in [`ChannelManager::pending_background_events`] will *also* be tracked here. This
	/// avoids a race condition during [`ChannelManager::pending_background_events`] processing
	/// where we complete one [`ChannelMonitorUpdate`] (but there are more pending as background
	/// events) but we conclude all pending [`ChannelMonitorUpdate`]s have completed and its safe
	/// to run post-completion actions.
	in_flight_monitor_updates: BTreeMap<ChannelId, (OutPoint, Vec<ChannelMonitorUpdate>)>,
	/// Map from a specific channel to some action(s) that should be taken when all pending
	/// [`ChannelMonitorUpdate`]s for the channel complete updating.
	///
	/// Note that because we generally only have one entry here a HashMap is pretty overkill. A
	/// BTreeMap currently stores more than ten elements per leaf node, so even up to a few
	/// channels with a peer this will just be one allocation and will amount to a linear list of
	/// channels to walk, avoiding the whole hashing rigmarole.
	///
	/// Note that the channel may no longer exist. For example, if a channel was closed but we
	/// later needed to claim an HTLC which is pending on-chain, we may generate a monitor update
	/// for a missing channel. While a malicious peer could construct a second channel with the
	/// same `temporary_channel_id` (or final `channel_id` in the case of 0conf channels or prior
	/// to funding appearing on-chain), the downstream `ChannelMonitor` set is required to ensure
	/// duplicates do not occur, so such channels should fail without a monitor update completing.
	///
	/// Note that these run after all *non-blocked* [`ChannelMonitorUpdate`]s have been persisted.
	/// Thus, they're primarily useful for (and currently only used for) claims, where the
	/// [`ChannelMonitorUpdate`] we care about is a preimage update, which bypass the monitor
	/// update blocking logic entirely and can never be blocked.
	monitor_update_blocked_actions: BTreeMap<ChannelId, Vec<MonitorUpdateCompletionAction>>,
	/// If another channel's [`ChannelMonitorUpdate`] needs to complete before a channel we have
	/// with this peer can complete an RAA [`ChannelMonitorUpdate`] (e.g. because the RAA update
	/// will remove a preimage that needs to be durably in an upstream channel first), we put an
	/// entry here to note that the channel with the key's ID is blocked on a set of actions.
	actions_blocking_raa_monitor_updates: BTreeMap<ChannelId, Vec<RAAMonitorUpdateBlockingAction>>,
	/// The latest [`ChannelMonitor::get_latest_update_id`] value for all closed channels as they
	/// exist on-disk/in our [`chain::Watch`].
	///
	/// If there are any updates pending in [`Self::in_flight_monitor_updates`] this will contain
	/// the highest `update_id` of all the pending in-flight updates (note that any pending updates
	/// not yet applied sitting in [`ChannelManager::pending_background_events`] will also be
	/// considered as they are also in [`Self::in_flight_monitor_updates`]).
	///
	/// Note that channels which were closed prior to LDK 0.1 may have a value here of `u64::MAX`.
	closed_channel_monitor_update_ids: BTreeMap<ChannelId, u64>,
	/// The peer is currently connected (i.e. we've seen a
	/// [`BaseMessageHandler::peer_connected`] and no corresponding
	/// [`BaseMessageHandler::peer_disconnected`].
	pub is_connected: bool,
	/// Holds the peer storage data for the channel partner on a per-peer basis.
	peer_storage: Vec<u8>,
}

// Mirror non-eltoo channel manager
pub struct ChannelManager<
	M: chain::Watch,
	T: BroadcasterInterface,
	ES: EntropySource,
	NS: NodeSigner,
	SP: SignerProvider,
	F: FeeEstimator,
	R: Router,
	L: Logger,
>
{
	chain_hash: ChainHash,
	fee_estimator: LowerBoundedFeeEstimator<F>,
	chain_monitor: M,
	tx_broadcaster: T,
	router: R,

	// FIXME: no BOLT-12 for now
	//#[cfg(test)]
	//pub(super) flow: OffersMessageFlow<MR, L>,
	//#[cfg(not(test))]
	//flow: OffersMessageFlow<MR, L>,

	#[cfg(any(test, feature = "_test_utils"))]
	pub(super) best_block: RwLock<BlockLocator>,
	#[cfg(not(any(test, feature = "_test_utils")))]
	best_block: RwLock<BlockLocator>,

	// XXX: I suspect we don't need the "vanilla" context but we'll do both for now
	pub(super) musig_secp_ctx: Secp256k1<secp256k1::All>,
	// XXX: I suspect we won't need this one
	pub(super) secp_ctx: Secp256k1<secp256k1::All>,

	pending_outbound_payments: OutboundPayments,

	#[cfg(test)]
	pub(super) forward_htlcs: Mutex<HashMap<HtlcId, Vec<channelmanager::HTLCForwardInfo>>>,
	#[cfg(not(test))]
	forward_htlcs: Mutex<HashMap<HtlcId, Vec<channelmanager::HTLCForwardInfo>>>,

	pending_intercepted_htlcs: Mutex<HashMap<InterceptId, channelmanager::PendingAddHTLCInfo>>,

	decode_update_add_htlcs: Mutex<HashMap<HtlcId, Vec<msgs::UpdateAddHTLC>>>,

	// FIXME: Will be important soon
	//claimable_payments: Mutex<ClaimablePayments>,

	outbound_scid_aliases: Mutex<HashSet<u64>>,

	#[cfg(test)]
	pub(super) short_to_chan_info: FairRwLock<HashMap<u64, (PublicKey, ChannelId)>>,
	#[cfg(not(test))]
	short_to_chan_info: FairRwLock<HashMap<u64, (PublicKey, ChannelId)>>,

	our_network_pubkey: PublicKey,

	inbound_payment_key: inbound_payment::ExpandedKey,

	fake_scid_rand_bytes: [u8; 32],

	probing_cookie_secret: [u8; 32],

	inbound_payment_id_secret: [u8; 32],

	highest_seen_timestamp: AtomicUsize,

	#[cfg(not(any(test, feature = "_test_utils")))]
	per_peer_state: FairRwLock<HashMap<PublicKey, Mutex<PeerState<SP>>>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(super) per_peer_state: FairRwLock<HashMap<PublicKey, Mutex<PeerState<SP>>>>,

	#[cfg(test)]
	pub(crate) skip_monitor_update_assertion: AtomicBool,

	// XXX: Implementation detail from vanilla ChannelManager, will evaluate if it makes sense to
	// emulate
	//#[cfg(not(any(test, feature = "_test_utils")))]
	//pending_events: Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,
	//#[cfg(any(test, feature = "_test_utils"))]
	//pub(crate) pending_events: Mutex<VecDeque<(events::Event, Option<EventCompletionAction>)>>,

	//pending_events_processor: AtomicBool,

	pending_htlc_forwards_processor: AtomicBool,

	funding_batch_states: Mutex<BTreeMap<Txid, Vec<(ChannelId, PublicKey, bool)>>>,

	background_events_processed_since_startup: AtomicBool,

	event_persist_notifier: Notifier,
	needs_persist_flag: AtomicBool,

	pending_broadcast_messages: Mutex<Vec<MessageSendEvent>>,

	#[cfg(test)]
	pub(super) entropy_source: ES,
	#[cfg(not(test))]
	entropy_source: ES,
	node_signer: NS,
	#[cfg(test)]
	pub(super) signer_provider: SP,
	#[cfg(not(test))]
	signer_provider: SP,

	logger: L,
}

impl<
	M: chain::Watch,
	T: BroadcasterInterface,
	ES: EntropySource,
	NS: NodeSigner,
	SP: SignerProvider,
	F: FeeEstimator,
	R: Router,
	L: Logger,
> BaseMessageHandler for ChannelManager<M, T, ES, NS, SP, F, R, L> {
    fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
        todo!()
    }

    fn peer_disconnected(&self, their_node_id: PublicKey) {
        todo!()
    }

    fn provided_node_features(&self) -> lightning_types::features::NodeFeatures {
        todo!()
    }

    fn provided_init_features(&self, their_node_id: PublicKey) -> InitFeatures {
        todo!()
    }

    fn peer_connected(&self, their_node_id: PublicKey, msg: &msgs::Init, inbound: bool)
		    -> Result<(), ()> {
        todo!()
    }
}

impl<
	M: chain::Watch,
	T: BroadcasterInterface,
	ES: EntropySource,
	NS: NodeSigner,
	SP: SignerProvider,
	F: FeeEstimator,
	R: Router,
	L: Logger,
> super::ChannelMessageHandler for ChannelManager<M, T, ES, NS, SP, F, R, L> {
    fn handle_open_channel_eltoo(&self, their_node_id: PublicKey, msg: &super::OpenChannel) {
        todo!()
    }

    fn handle_accept_channel_eltoo(&self, their_node_id: PublicKey, msg: &super::AcceptChannel) {
        todo!()
    }

    fn handle_funding_created_eltoo(&self, their_node_id: PublicKey, msg: &super::FundingCreated) {
        todo!()
    }

    fn handle_funding_signed_eltoo(&self, their_node_id: PublicKey, msg: &super::FundingSigned) {
        todo!()
    }

    fn handle_channel_ready_eltoo(&self, their_node_id: PublicKey, msg: &super::ChannelReady) {
        todo!()
    }

    fn handle_shutdown_eltoo(&self, their_node_id: PublicKey, msg: &super::Shutdown) {
        todo!()
    }

    fn handle_closing_signed_eltoo(&self, their_node_id: PublicKey, msg: &super::ClosingSigned) {
        todo!()
    }

    fn handle_update_add_htlc(&self, their_node_id: PublicKey, msg: &msgs::UpdateAddHTLC) {
        todo!()
    }

    fn handle_update_fulfill_htlc(&self, their_node_id: PublicKey, msg: msgs::UpdateFulfillHTLC) {
        todo!()
    }

    fn handle_update_fail_htlc(&self, their_node_id: PublicKey, msg: &msgs::UpdateFailHTLC) {
        todo!()
    }

    fn handle_update_fail_malformed_htlc(
		    &self, their_node_id: PublicKey, msg: &msgs::UpdateFailMalformedHTLC,
	    ) {
        todo!()
    }

    fn handle_update_signed(&self, their_node_id: PublicKey, msg: &super::UpdateSigned) {
        todo!()
    }

    fn handle_update_signed_ack(&self, their_node_id: PublicKey, msg: &super::UpdateSignedAck) {
        todo!()
    }

    fn handle_announcement_signatures(
		    &self, their_node_id: PublicKey, msg: &msgs::AnnouncementSignatures,
	    ) {
        todo!()
    }

    fn handle_channel_reestablish(&self, their_node_id: PublicKey, msg: &super::ChannelReestablish) {
        todo!()
    }

    fn handle_error(&self, their_node_id: PublicKey, msg: &msgs::ErrorMessage) {
        todo!()
    }

    fn get_chain_hashes(&self) -> Option<Vec<ChainHash>> {
        todo!()
    }

    fn message_received(&self) {
        todo!()
    }
}

#[cfg(not(c_bindings))]
pub type SimpleRefChannelManager<'a, 'b, 'c, 'd, 'e, 'f, 'g, 'h, M, T, F, L> = ChannelManager<
	&'a M,
	&'b T,
	&'c KeysManager,
	&'c KeysManager,
	&'c KeysManager,
	&'d F,
	&'e DefaultRouter<
		&'f NetworkGraph<&'g L>,
		&'g L,
		&'c KeysManager,
		&'h RwLock<ProbabilisticScorer<&'f NetworkGraph<&'g L>, &'g L>>,
		ProbabilisticScoringFeeParameters,
		ProbabilisticScorer<&'f NetworkGraph<&'g L>, &'g L>,
	>,
	&'g L,
>;

#[cfg(not(c_bindings))]
pub type SimpleArcChannelManager<M, T, F, L> = ChannelManager<
	Arc<M>,
	Arc<T>,
	Arc<KeysManager>,
	Arc<KeysManager>,
	Arc<KeysManager>,
	Arc<F>,
	Arc<
		DefaultRouter<
			Arc<NetworkGraph<Arc<L>>>,
			Arc<L>,
			Arc<KeysManager>,
			Arc<RwLock<ProbabilisticScorer<Arc<NetworkGraph<Arc<L>>>, Arc<L>>>>,
			ProbabilisticScoringFeeParameters,
			ProbabilisticScorer<Arc<NetworkGraph<Arc<L>>>, Arc<L>>,
		>,
	>,
	Arc<L>,
>;
