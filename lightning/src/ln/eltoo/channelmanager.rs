
use alloc::collections::{BTreeMap, BTreeSet};
use bitcoin::{absolute, relative, Txid, Transaction, Amount};
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

use crate::ln::eltoo::msgs::{self, AcceptChannel, ChannelMessageHandler, ChannelReady, ClosingSigned, FundingCreated, FundingSigned, OpenChannel, MilliSatoshi, Shutdown};
use crate::ln::eltoo::chain;
use crate::ln::eltoo::events::Event;
use crate::ln::types::ChannelId;
use crate::ln::channelmanager::{self, InterceptId, MonitorUpdateCompletionAction, RAAMonitorUpdateBlockingAction};
use crate::ln::inbound_payment;
use crate::ln::outbound_payment::{
	OutboundPayments,
};
use crate::ln::msgs::{MessageSendEvent, BaseMessageHandler, UpdateAddHTLC, UpdateFulfillHTLC, UpdateFailHTLC, UpdateFailMalformedHTLC, AnnouncementSignatures, ErrorMessage, Init};
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

// XXX: Expect this to grow into something similar to [`MsgHandleErrorInternal`]
struct ChannelErrorAction {
	fail_channel: bool,
	close_connection: bool,
}

impl ChannelErrorAction {
	fn new() -> Self { Self { fail_channel: false, close_connection: false } }
	fn fail_channel(self) -> Self { Self { fail_channel: true, close_connection: self.close_connection } }
	fn close_connection(self) -> Self { Self { fail_channel: self.fail_channel, close_connection: true } }
}

pub struct ChannelFunding {
    transaction: Transaction,
    vout: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelParty {
    funding_pubkey: PublicKey,
    settlement_pubkey: PublicKey,

    balance: MilliSatoshi,

    pub max_htlc_value_in_flight: MilliSatoshi,
    pub htlc_minimum_value: MilliSatoshi,

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
    pub shared_delay: relative::Height,
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

struct InboundChannelRequest {
	msg: OpenChannel,
	ticks: u32,
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

	decode_update_add_htlcs: Mutex<HashMap<HtlcId, Vec<UpdateAddHTLC>>>,

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

	// TODO: in the vanilla ChannelManager the second item in the tuple is a continuation
	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_events: Mutex<VecDeque<(Event, Option<()>)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_events: Mutex<VecDeque<(Event, Option<()>)>>,

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

    fn peer_connected(&self, their_node_id: PublicKey, msg: &Init, inbound: bool) -> Result<(), ()> {
		let mut per_peer_state = self.per_peer_state.write().unwrap();

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
> ChannelMessageHandler for ChannelManager<M, T, ES, NS, SP, F, R, L> {
    fn handle_open_channel_eltoo(&self, their_node_id: PublicKey, msg: &OpenChannel) {
		match self.internal_open_channel(their_node_id, msg) {
			Ok(_) => todo!(),
			Err(_) => {
				// TOOD: log error
				self.fail_channel(their_node_id, msg.temporary_channel_id);
			}
		}
    }

    fn handle_accept_channel_eltoo(&self, their_node_id: PublicKey, msg: &AcceptChannel) {
		match self.internal_accept_channel(their_node_id, msg.temporary_channel_id) {
			Ok(_) => todo!(),
			Err(_) => {
				// TOOD: log error
				self.fail_channel(their_node_id, msg.temporary_channel_id);
			}
		}
    }

    fn handle_funding_created_eltoo(&self, their_node_id: PublicKey, msg: &FundingCreated) {
        todo!()
    }

    fn handle_funding_signed_eltoo(&self, their_node_id: PublicKey, msg: &FundingSigned) {
        todo!()
    }

    fn handle_channel_ready_eltoo(&self, their_node_id: PublicKey, msg: &ChannelReady) {
        todo!()
    }

    fn handle_shutdown_eltoo(&self, their_node_id: PublicKey, msg: &Shutdown) {
        todo!()
    }

    fn handle_closing_signed_eltoo(&self, their_node_id: PublicKey, msg: &ClosingSigned) {
        todo!()
    }

    fn handle_update_add_htlc(&self, their_node_id: PublicKey, msg: &UpdateAddHTLC) {
        todo!()
    }

    fn handle_update_fulfill_htlc(&self, their_node_id: PublicKey, msg: UpdateFulfillHTLC) {
        todo!()
    }

    fn handle_update_fail_htlc(&self, their_node_id: PublicKey, msg: &UpdateFailHTLC) {
        todo!()
    }

    fn handle_update_fail_malformed_htlc(
		    &self, their_node_id: PublicKey, msg: &UpdateFailMalformedHTLC,
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
		    &self, their_node_id: PublicKey, msg: &AnnouncementSignatures,
	    ) {
        todo!()
    }

    fn handle_channel_reestablish(&self, their_node_id: PublicKey, msg: &super::ChannelReestablish) {
        todo!()
    }

    fn handle_error(&self, their_node_id: PublicKey, msg: &ErrorMessage) {
		if !msg.channel_id.is_zero() {

		}
        todo!()
    }

    fn get_chain_hashes(&self) -> Option<Vec<ChainHash>> {
        todo!()
    }

    fn message_received(&self) {
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
> ChannelManager<M, T, ES, NS, SP, F, R, L> {
	fn internal_open_channel(&self, counterparty_node_id: PublicKey, msg: &super::OpenChannel) -> Result<(), ChannelErrorAction> {
        let funding_msat: MilliSatoshi = msg.funding_amount.try_into()
			.map_err(|_| ChannelErrorAction::new().fail_channel())?;

        let remote_msat = funding_msat.checked_sub(msg.push_value)
			.ok_or(ChannelErrorAction::new().fail_channel())?;

		// Channel type is required
		let channel_type = msg.channel_type
			.clone()
			.ok_or(ChannelErrorAction::new().fail_channel())?;

        let remote_channel_party_config = ChannelParty {
            funding_pubkey: msg.funding_pubkey,
            settlement_pubkey: msg.settlement_pubkey,
            balance: remote_msat,
            max_htlc_value_in_flight: msg.max_htlc_value_in_flight,
            htlc_minimum_value: msg.htlc_minimum_value,
            max_accepted_htlcs: msg.max_accepted_htlcs,
            last_nonce: Some((0, msg.next_nonce)),
        };

		let mut pending_events = self.pending_events.lock().unwrap();
		pending_events.push_back(
			(
				Event::OpenChannelRequest {
					temporary_channel_id: msg.temporary_channel_id,
					counterparty_node_id,
					funding_satoshis: msg.funding_amount,
					channel_type,
					max_htlc_value_in_flight: msg.max_htlc_value_in_flight,
					htlc_minimum_value: msg.htlc_minimum_value,
					shared_delay: msg.shared_delay,
					max_accepted_htlcs: msg.max_accepted_htlcs,
					remote_channel_party_config,
				},
				None
			)
		);

		Ok(())
	}

	fn internal_accept_channel(&self, their_node_id: PublicKey, channel_id: ChannelId) -> Result<(), ChannelErrorAction> {
		let mut per_peer_state = self.per_peer_state.write().unwrap();

		let mut peer_state = per_peer_state.get_mut(&their_node_id)
			.ok_or(ChannelErrorAction::new().close_connection())?;

		todo!()
	}

	fn fail_channel(&self, their_node_id: PublicKey, channel_id: ChannelId) {
		todo!("fail channel");
	}

	fn close_channel(&self, channel_id: ChannelId) {

	}

	fn accept_channel(&self, temporary_channel_id: ChannelId, counterparty_node_id: PublicKey, user_channel_id: u128) -> Result<(), ()> {
		todo!()
	}

	fn open_channel(&self, their_node_id: PublicKey, amount: Amount, push_amount: MilliSatoshi) -> Result<(), ()> {
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
