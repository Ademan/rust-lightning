use bitcoin::OutPoint;
use bitcoin::{secp256k1::PublicKey, Amount};
use lightning_types::features::ChannelTypeFeatures;

use crate::events::ClosureReason;
use crate::ln::types::ChannelId;
use crate::ln::eltoo::channelmanager::ChannelParty;

use super::msgs::MilliSatoshi;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
	OpenChannelRequest {
		temporary_channel_id: ChannelId,
		counterparty_node_id: PublicKey,
		funding_satoshis: Amount,
		channel_type: ChannelTypeFeatures,
		max_htlc_value_in_flight: MilliSatoshi,
		htlc_minimum_value: MilliSatoshi,
		shared_delay: u16,
		max_accepted_htlcs: u16,
		remote_channel_party_config: ChannelParty,
	},

	ChannelReady {
		channel_id: ChannelId,
		user_channel_id: u128,
		counterparty_node_id: PublicKey,
		funding_utxo: OutPoint,
		channel_type: ChannelTypeFeatures,
	},

	ChannelClosed {
		channel_id: ChannelId,
		user_channel_id: u128,
		reason: ClosureReason,
		counterparty_node_id: Option<PublicKey>,
		channel_capacity_sats: Option<u64>,

		channel_funding_utxo: Option<OutPoint>,

		last_local_balance_msat: Option<u64>,
	}
}
