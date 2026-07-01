//! Eltoo wire messages

use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};

use secp256k1_musig::musig;

use crate::io;
use crate::ln::msgs::{ClosingSignedFeeRange, DecodeError};
use crate::ln::types::ChannelId;
use crate::prelude::*;
use crate::types::features::ChannelTypeFeatures;

use crate::util::ser::{
	LengthLimitedRead, LengthReadable, Readable, WithoutLength, Writeable, Writer,
};

/// An [`open_channel_eltoo`] message to be sent to or received from a peer.
///
/// [`open_channel_eltoo`]: https://github.com/instagibbs/bolts/blob/2026-01-eltoo_th/XX-eltoo-peer-protocol.md#the-open_channel_eltoo-message
pub struct OpenChannel {
	/// The genesis hash of the blockchain where the channel is to be opened
	pub chain_hash: ChainHash,

	/// A temporary channel ID
	pub temporary_channel_id: ChannelId,

	pub funding_amount: Amount,

	pub push_msat: u64,

	/// The maximum inbound HTLC value in flight towards channel initiator, in milli-satoshi
	pub max_htlc_value_in_flight_msat: u64,
	/// The minimum HTLC size incoming to channel initiator, in milli-satoshi
	pub htlc_minimum_msat: u64,
	/// The delay before a settlement transaction may spend an on-chain update transaction
	pub shared_delay: u16,
	/// The maximum number of inbound HTLCs towards channel initiator
	pub max_accepted_htlcs: u16,

	/// The channel initiator's key controlling the funding transaction
	pub funding_pubkey: PublicKey,
	/// Pubkey for settling HTLCs and the funder's balance
	pub settlement_pubkey: PublicKey,

	/// The channel flags to be used
	pub channel_flags: u8,
	/// Pre-exchange the nonce required for the first update transaction
	pub next_nonce: musig::PublicNonce,

	/// Optionally, a request to pre-set the to-channel-initiator output's scriptPubkey for when we
	/// collaboratively close
	pub shutdown_scriptpubkey: Option<ScriptBuf>,

	/// The channel type that this channel will represent. As defined in the latest
	/// specification, this field is required. However, it is an `Option` for legacy reasons.
	pub channel_type: Option<ChannelTypeFeatures>,
}

/// An [`accept_channel_eltoo`] message to be sent to or received from a peer.
///
/// [`accept_channel_eltoo`]: https://github.com/instagibbs/bolts/blob/2026-01-eltoo_th/XX-eltoo-peer-protocol.md#the-accept_channel_eltoo-message
pub struct AcceptChannel {
	/// A temporary channel ID
	pub temporary_channel_id: ChannelId,

	/// The maximum inbound HTLC value in flight towards channel initiator, in milli-satoshi
	pub max_htlc_value_in_flight_msat: u64,
	/// The minimum HTLC size incoming to channel initiator, in milli-satoshi
	pub htlc_minimum_msat: u64,
	/// The minimum number of confirmations the funding transaction must achieve before the channel
	/// is considered ready
	pub minimum_depth: u32,
	/// The delay before a settlement transaction may spend an on-chain update transaction
	pub shared_delay: u16,
	/// The maximum number of inbound HTLCs towards channel accepter
	pub max_accepted_htlcs: u16,

	/// The channel accepter's key controlling the funding transaction
	pub funding_pubkey: PublicKey,
	/// Pubkey for settling HTLCs and the fundee's balance
	pub settlement_pubkey: PublicKey,

	/// Pre-exchange the nonce required for the first update transaction
	pub next_nonce: musig::PublicNonce,

	/// Optionally, a request to pre-set the to-channel-initiator output's scriptPubkey for when we
	/// collaboratively close
	pub shutdown_scriptpubkey: Option<ScriptBuf>,

	/// The channel type that this channel will represent. As defined in the latest
	/// specification, this field is required. However, it is an `Option` for legacy reasons.
	pub channel_type: Option<ChannelTypeFeatures>,
}

/// An [`funding_created_eltoo`] message to be sent to or received from a peer.
///
/// [`funding_created_eltoo`]: https://github.com/instagibbs/bolts/blob/2026-01-eltoo_th/XX-eltoo-peer-protocol.md#the-funding_created_eltoo-message
pub struct FundingCreated {
	/// A temporary channel ID
	pub temporary_channel_id: ChannelId,

	pub funding_outpoint: OutPoint,

	pub update_partial_signature: musig::PartialSignature,

	/// Pre-exchange the nonce required for the next update transaction
	pub next_nonce: musig::PublicNonce,
}

/// An [`funding_signed_eltoo`] message to be sent to or received from a peer.
///
/// [`funding_signed_eltoo`]: https://github.com/instagibbs/bolts/blob/2026-01-eltoo_th/XX-eltoo-peer-protocol.md#the-funding_signed_eltoo-message
pub struct FundingSigned {
	/// Channel ID
	pub channel_id: ChannelId,

	pub update_partial_signature: musig::PartialSignature,

	/// Pre-exchange the nonce required for the next update transaction
	pub next_nonce: musig::PublicNonce,
}

/// A [`channel_ready_eltoo`] message to be sent to or received from a peer.
///
/// [`channel_ready_eltoo`]: https://github.com/instagibbs/bolts/blob/2026-01-eltoo_th/XX-eltoo-peer-protocol.md#the-channel_ready_eltoo-message
pub struct ChannelReady {
	/// Channel ID
	pub channel_id: ChannelId,
}

/// A [`shutdown_eltoo`] message to be sent to or received from a peer.
///
/// [`shutdown_eltoo`]: https://github.com/instagibbs/bolts/blob/2026-01-eltoo_th/XX-eltoo-peer-protocol.md#closing-initiation-shutdown
pub struct Shutdown {
	/// Channel ID
	pub channel_id: ChannelId,

	/// script_pubkey to lock funds for sender
	pub script_pubkey: ScriptBuf,

	/// Pre-exchange the nonce required for the next update transaction
	pub next_nonce: musig::PublicNonce,
}

/// A [`closing_signed_eltoo`] message to be sent to or received from a peer.
///
/// [`closing_signed_eltoo`]: https://github.com/instagibbs/bolts/blob/2026-01-eltoo_th/XX-eltoo-peer-protocol.md#closing-negotiation-closing_signed
pub struct ClosingSigned {
	/// Channel ID
	pub channel_id: ChannelId,

	/// Fee proposal amount
	pub fee: Amount,

	/// The minimum and maximum fees which the sender is willing to accept, provided only by new
	/// nodes.
	pub fee_range: Option<ClosingSignedFeeRange>,

	// FIXME: In the docs this is plural, why?!
	pub nonce: Option<musig::PublicNonce>,

	pub partial_signature: Option<musig::PartialSignature>,
}

/// An [`update_signed`] message to be sent to or received from a peer.
///
/// [`update_signed`]: https://github.com/instagibbs/bolts/blob/2026-01-eltoo_th/XX-eltoo-peer-protocol.md#committing-updates-so-far-update_signed
pub struct UpdateSigned {
	/// Channel ID
	pub channel_id: ChannelId,

	pub update_partial_signature: musig::PartialSignature,

	/// Pre-exchange the nonce required for the next update transaction
	pub next_nonce: musig::PublicNonce,
}

// XXX: Tempted to merge with UpdateSigned
/// An [`update_signed_ack`] message to be sent to or received from a peer.
///
/// [`update_signed_ack`]: https://github.com/instagibbs/bolts/blob/2026-01-eltoo_th/XX-eltoo-peer-protocol.md#finalizing-the-update-update_signed_ack
pub struct UpdateSignedAck {
	/// Channel ID
	pub channel_id: ChannelId,

	pub update_partial_signature: musig::PartialSignature,

	/// Pre-exchange the nonce required for the next update transaction
	pub next_nonce: musig::PublicNonce,
}

/// An [`channel_reestablish_eltoo`] message to be sent to or received from a peer.
///
/// [`channel_reestablish_eltoo`]: https://github.com/instagibbs/bolts/blob/2026-01-eltoo_th/XX-eltoo-peer-protocol.md#message-retransmission-for-eltoo
pub struct ChannelReestablish {
	/// Channel ID
	pub channel_id: ChannelId,

	pub last_update_number: u64,

	pub update_partial_signature: musig::PartialSignature,

	/// Pre-exchange the nonce required for the next update transaction
	pub fresh_nonce: musig::PublicNonce,
}

impl LengthReadable for OpenChannel {
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(r: &mut R) -> Result<Self, DecodeError> {
		let chain_hash: ChainHash = Readable::read(r)?;
		let temporary_channel_id: ChannelId = Readable::read(r)?;
		let funding_amount: Amount = Readable::read(r)?;
		let push_msat: u64 = Readable::read(r)?;
		let max_htlc_value_in_flight_msat: u64 = Readable::read(r)?;
		let htlc_minimum_msat: u64 = Readable::read(r)?;
		let shared_delay: u16 = Readable::read(r)?;
		let max_accepted_htlcs: u16 = Readable::read(r)?;
		let funding_pubkey: PublicKey = Readable::read(r)?;
		let settlement_pubkey: PublicKey = Readable::read(r)?;
		let channel_flags: u8 = Readable::read(r)?;
		let next_nonce: musig::PublicNonce = Readable::read(r)?;

		let mut shutdown_scriptpubkey: Option<ScriptBuf> = None;
		let mut channel_type: Option<ChannelTypeFeatures> = None;

		decode_tlv_stream!(r, {
			(0, shutdown_scriptpubkey, (option, encoding: (ScriptBuf, WithoutLength))),
			(1, channel_type, option),
		});

		Ok(Self {
			chain_hash,
			temporary_channel_id,
			funding_amount,
			push_msat,
			max_htlc_value_in_flight_msat,
			htlc_minimum_msat,
			shared_delay,
			max_accepted_htlcs,
			funding_pubkey,
			settlement_pubkey,
			channel_flags,
			next_nonce,
			shutdown_scriptpubkey,
			channel_type,
		})
	}
}

impl Writeable for OpenChannel {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.chain_hash.write(w)?;
		self.temporary_channel_id.write(w)?;
		self.funding_amount.write(w)?;
		self.push_msat.write(w)?;
		self.max_htlc_value_in_flight_msat.write(w)?;
		self.htlc_minimum_msat.write(w)?;
		self.shared_delay.write(w)?;
		self.max_accepted_htlcs.write(w)?;
		self.funding_pubkey.write(w)?;
		self.settlement_pubkey.write(w)?;
		self.channel_flags.write(w)?;
		self.next_nonce.write(w)?;

		encode_tlv_stream!(w, {
			(0, self.shutdown_scriptpubkey.as_ref().map(|s| WithoutLength(s)), option), // Don't encode length twice.
			(1, self.channel_type, option),
		});

		Ok(())
	}
}

impl LengthReadable for AcceptChannel {
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(r: &mut R) -> Result<Self, DecodeError> {
		let temporary_channel_id: ChannelId = Readable::read(r)?;
		let max_htlc_value_in_flight_msat: u64 = Readable::read(r)?;
		let htlc_minimum_msat: u64 = Readable::read(r)?;
		let minimum_depth: u32 = Readable::read(r)?;
		let shared_delay: u16 = Readable::read(r)?;
		let max_accepted_htlcs: u16 = Readable::read(r)?;
		let funding_pubkey: PublicKey = Readable::read(r)?;
		let settlement_pubkey: PublicKey = Readable::read(r)?;
		let next_nonce: musig::PublicNonce = Readable::read(r)?;

		let mut shutdown_scriptpubkey: Option<ScriptBuf> = None;
		let mut channel_type: Option<ChannelTypeFeatures> = None;

		decode_tlv_stream!(r, {
			(0, shutdown_scriptpubkey, (option, encoding: (ScriptBuf, WithoutLength))),
			(1, channel_type, option),
		});

		Ok(Self {
			temporary_channel_id,
			max_htlc_value_in_flight_msat,
			htlc_minimum_msat,
			minimum_depth,
			shared_delay,
			max_accepted_htlcs,
			funding_pubkey,
			settlement_pubkey,
			next_nonce,
			shutdown_scriptpubkey,
			channel_type,
		})
	}
}

impl Writeable for AcceptChannel {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.temporary_channel_id.write(w)?;
		self.max_htlc_value_in_flight_msat.write(w)?;
		self.htlc_minimum_msat.write(w)?;
		self.minimum_depth.write(w)?;
		self.shared_delay.write(w)?;
		self.max_accepted_htlcs.write(w)?;
		self.funding_pubkey.write(w)?;
		self.settlement_pubkey.write(w)?;
		self.next_nonce.write(w)?;

		encode_tlv_stream!(w, {
			(0, self.shutdown_scriptpubkey.as_ref().map(|s| WithoutLength(s)), option), // Don't encode length twice.
			(1, self.channel_type, option),
		});

		Ok(())
	}
}

impl LengthReadable for FundingCreated {
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(r: &mut R) -> Result<Self, DecodeError> {
		let temporary_channel_id: ChannelId = Readable::read(r)?;
		let funding_txid: Txid = Readable::read(r)?;
		let funding_output_index: u16 = Readable::read(r)?;
		let update_partial_signature: musig::PartialSignature = Readable::read(r)?;
		let next_nonce: musig::PublicNonce = Readable::read(r)?;

		Ok(Self {
			temporary_channel_id,
			funding_outpoint: OutPoint { txid: funding_txid, vout: funding_output_index.into() },
			update_partial_signature,
			next_nonce,
		})
	}
}

impl Writeable for FundingCreated {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.temporary_channel_id.write(w)?;
		self.funding_outpoint.txid.write(w)?;
		let funding_output_index: u16 =
			self.funding_outpoint.vout.try_into().expect("Funding output index fits in 16 bits");
		funding_output_index.write(w)?;
		self.update_partial_signature.write(w)?;
		self.next_nonce.write(w)?;

		Ok(())
	}
}

impl_writeable_msg!(FundingSigned, {
	channel_id,
	update_partial_signature,
	next_nonce,
}, {});

impl_writeable_msg!(ChannelReady, {
	channel_id,
}, {});

impl_writeable_msg!(Shutdown, {
	channel_id,
	script_pubkey,
	next_nonce,
}, {});

impl_writeable_msg!(ClosingSigned, {
	channel_id,
	fee,
}, {
	(0, fee_range, option),
	(2, nonce, option),
	(3, partial_signature, option),
});

impl_writeable_msg!(UpdateSigned, {
	channel_id,
	update_partial_signature,
	next_nonce,
}, {});

impl_writeable_msg!(UpdateSignedAck, {
	channel_id,
	update_partial_signature,
	next_nonce,
}, {});

impl_writeable_msg!(ChannelReestablish, {
	channel_id,
	last_update_number,
	update_partial_signature,
	fresh_nonce,
}, {});
