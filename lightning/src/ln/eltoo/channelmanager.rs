
use alloc::collections::BTreeMap;
use bitcoin::Txid;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// :vomit_emoji:
use crate::prelude::*;

use crate::ln::eltoo::chain;
use crate::ln::types::ChannelId;
use crate::ln::channelmanager::{self, InterceptId};
use crate::ln::inbound_payment;
use crate::ln::outbound_payment::{
	OutboundPayments,
};
use crate::ln::msgs::{self, MessageSendEvent};
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

// FIXME: Stub
pub struct PeerState {

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
	pub(super) forward_htlcs: Mutex<HashMap<u64, Vec<channelmanager::HTLCForwardInfo>>>,
	#[cfg(not(test))]
	forward_htlcs: Mutex<HashMap<u64, Vec<channelmanager::HTLCForwardInfo>>>,

	pending_intercepted_htlcs: Mutex<HashMap<InterceptId, channelmanager::PendingAddHTLCInfo>>,

	decode_update_add_htlcs: Mutex<HashMap<u64, Vec<msgs::UpdateAddHTLC>>>,

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
	per_peer_state: FairRwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(super) per_peer_state: FairRwLock<HashMap<PublicKey, Mutex<PeerState>>>,

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
