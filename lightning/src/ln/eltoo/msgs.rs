//! Eltoo wire messages

use core::ops::Deref;

use bitcoin::constants::ChainHash;
use bitcoin::io::Read;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};

use secp256k1_musig::musig;

use crate::io;
use crate::ln::types::ChannelId;
use crate::ln::wire::{Type, Encode};
use crate::prelude::*;
use crate::types::features::ChannelTypeFeatures;

use crate::ln::msgs::{
    AnnouncementSignatures, BaseMessageHandler, ClosingSignedFeeRange, DecodeError,
    ErrorMessage, UpdateAddHTLC, UpdateFailHTLC, UpdateFailMalformedHTLC, UpdateFulfillHTLC,
};

use crate::util::ser::{
	BigSize, FixedLengthReader, HighZeroBytesDroppedBigSize, Hostname, LengthLimitedRead,
	LengthReadable, LengthReadableArgs, Readable, ReadableArgs, WithoutLength, Writeable, Writer,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MilliSatoshi(u64);

impl MilliSatoshi {
	pub const ZERO: MilliSatoshi = Self(0);

    pub fn from_msat(msat: u64) -> Self { Self(msat) }

    pub fn to_amount(self) -> (Amount, MilliSatoshi) {
        (
            Amount::from_sat(self.0 / 1000),
            Self(self.0 % 1000),
        )
    }

    pub fn to_msat(self) -> u64 { self.0 }

    pub fn checked_sub(&self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0)
            .map(|msat| Self::from_msat(msat))
    }

    pub fn checked_add(&self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0)
            .map(|msat| Self::from_msat(msat))
    }
}

#[derive(Debug)]
pub struct MilliSatoshiOverflow;

impl TryFrom<Amount> for MilliSatoshi {
    type Error = MilliSatoshiOverflow;

    fn try_from(amount: Amount) -> Result<Self, Self::Error> {
        amount.to_sat().checked_mul(1000)
            .map(Self)
            .ok_or(MilliSatoshiOverflow)

    }
}

impl Readable for MilliSatoshi {
	fn read<R: Read>(r: &mut R) -> Result<Self, DecodeError> {
		let msat: u64 = Readable::read(r)?;
		Ok(Self(msat))
	}
}

impl Writeable for MilliSatoshi {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.0.write(w)
	}

	#[inline]
	fn serialized_length(&self) -> usize {
		self.0.serialized_length()
	}
}

/// An [`open_channel_eltoo`] message to be sent to or received from a peer.
///
/// [`open_channel_eltoo`]: https://github.com/instagibbs/bolts/blob/2026-01-eltoo_th/XX-eltoo-peer-protocol.md#the-open_channel_eltoo-message
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct OpenChannel {
	/// The genesis hash of the blockchain where the channel is to be opened
	pub chain_hash: ChainHash,

	/// A temporary channel ID
	pub temporary_channel_id: ChannelId,

	pub funding_amount: Amount,

	pub push_value: MilliSatoshi,

	/// The maximum inbound HTLC value in flight towards channel initiator, in milli-satoshi
	pub max_htlc_value_in_flight: MilliSatoshi,
	/// The minimum HTLC size incoming to channel initiator, in milli-satoshi
	pub htlc_minimum_value: MilliSatoshi,
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
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AcceptChannel {
	/// A temporary channel ID
	pub temporary_channel_id: ChannelId,

	/// The maximum inbound HTLC value in flight towards channel initiator, in milli-satoshi
	pub max_htlc_value_in_flight: MilliSatoshi,
	/// The minimum HTLC size incoming to channel initiator, in milli-satoshi
	pub htlc_minimum_value: MilliSatoshi,
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
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
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
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
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
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ChannelReady {
	/// Channel ID
	pub channel_id: ChannelId,
}

/// A [`shutdown_eltoo`] message to be sent to or received from a peer.
///
/// [`shutdown_eltoo`]: https://github.com/instagibbs/bolts/blob/2026-01-eltoo_th/XX-eltoo-peer-protocol.md#closing-initiation-shutdown
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
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
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
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
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
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
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
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
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
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
		let push_value: MilliSatoshi = Readable::read(r)?;
		let max_htlc_value_in_flight: MilliSatoshi = Readable::read(r)?;
		let htlc_minimum_value: MilliSatoshi = Readable::read(r)?;
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
			push_value,
			max_htlc_value_in_flight,
			htlc_minimum_value,
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
		self.push_value.write(w)?;
		self.max_htlc_value_in_flight.write(w)?;
		self.htlc_minimum_value.write(w)?;
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
		let max_htlc_value_in_flight: MilliSatoshi = Readable::read(r)?;
		let htlc_minimum_value: MilliSatoshi = Readable::read(r)?;
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
			max_htlc_value_in_flight,
			htlc_minimum_value,
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
		self.max_htlc_value_in_flight.write(w)?;
		self.htlc_minimum_value.write(w)?;
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

#[derive(Clone, Debug)]
pub enum Message {
	OpenChannel(OpenChannel),
	AcceptChannel(AcceptChannel),
	FundingCreated(FundingCreated),
	FundingSigned(FundingSigned),
	ChannelReady(ChannelReady),
	Shutdown(Shutdown),
	ClosingSigned(ClosingSigned),
	UpdateSigned(UpdateSigned),
	UpdateSignedAck(UpdateSignedAck),
	ChannelReestablish(ChannelReestablish),
}

impl Message {
	pub fn channel_id(&self) -> ChannelId {
		match self {
			Message::OpenChannel(msg) => msg.temporary_channel_id,
			Message::AcceptChannel(msg) => msg.temporary_channel_id,
			Message::FundingCreated(msg) => msg.temporary_channel_id,
			Message::FundingSigned(msg) => msg.channel_id,
			Message::ChannelReady(msg) => msg.channel_id,
			Message::Shutdown(msg) => msg.channel_id,
			Message::ClosingSigned(msg) => msg.channel_id,
			Message::UpdateSigned(msg) => msg.channel_id,
			Message::UpdateSignedAck(msg) => msg.channel_id,
			Message::ChannelReestablish(msg) => msg.channel_id,
		}
	}
}

impl Writeable for Message {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			Message::OpenChannel(ref msg) => msg.write(writer),
			Message::AcceptChannel(ref msg) => msg.write(writer),
			Message::FundingCreated(ref msg) => msg.write(writer),
			Message::FundingSigned(ref msg) => msg.write(writer),
			Message::ChannelReady(ref msg) => msg.write(writer),
			Message::Shutdown(ref msg) => msg.write(writer),
			Message::ClosingSigned(ref msg) => msg.write(writer),
			Message::UpdateSigned(ref msg) => msg.write(writer),
			Message::UpdateSignedAck(ref msg) => msg.write(writer),
			Message::ChannelReestablish(ref msg) => msg.write(writer),
		}
	}
}

// XXX: Arguably should be in a separate module
impl Encode for OpenChannel {
	const TYPE: u16 = 32778;
}

impl Encode for AcceptChannel {
	const TYPE: u16 = 32769;
}

impl Encode for FundingCreated {
	const TYPE: u16 = 32770;
}

impl Encode for FundingSigned {
	const TYPE: u16 = 32771;
}

impl Encode for ChannelReady {
	const TYPE: u16 = 32772;
}

impl Encode for Shutdown {
	const TYPE: u16 = 32773;
}

impl Encode for ClosingSigned {
	const TYPE: u16 = 32774;
}

impl Encode for UpdateSigned {
	const TYPE: u16 = 32775;
}

impl Encode for UpdateSignedAck {
	const TYPE: u16 = 32776;
}

impl Encode for ChannelReestablish {
	const TYPE: u16 = 32777;
}

impl Type for Message {
	/// Returns the type that was used to decode the message payload.
	fn type_id(&self) -> u16 {
		match self {
			Message::OpenChannel(ref msg) => msg.type_id(),
			Message::AcceptChannel(ref msg) => msg.type_id(),
			Message::FundingCreated(ref msg) => msg.type_id(),
			Message::FundingSigned(ref msg) => msg.type_id(),
			Message::ChannelReady(ref msg) => msg.type_id(),
			Message::Shutdown(ref msg) => msg.type_id(),
			Message::ClosingSigned(ref msg) => msg.type_id(),
			Message::UpdateSigned(ref msg) => msg.type_id(),
			Message::UpdateSignedAck(ref msg) => msg.type_id(),
			Message::ChannelReestablish(ref msg) => msg.type_id(),
		}
	}
}

// XXX: Cargo culting the handler pattern from the existing peer manager code, hopefully that will
// prove prudent.
// XXX: Waffling on keeping the _eltoo suffix on ambiguous methods. On the one hand it will make
// things clearer, but on the other hand it's kind of noise in all of the contexts I can think of.
pub trait ChannelMessageHandler: BaseMessageHandler {
	// Channel init:
	/// Handle an incoming `open_channel_eltoo` message from the given peer.
	fn handle_open_channel_eltoo(&self, their_node_id: PublicKey, msg: &OpenChannel);
	/// Handle an incoming `accept_channel_eltoo` message from the given peer.
	fn handle_accept_channel_eltoo(&self, their_node_id: PublicKey, msg: &AcceptChannel);

	/// Handle an incoming `funding_created_eltoo` message from the given peer.
	fn handle_funding_created_eltoo(&self, their_node_id: PublicKey, msg: &FundingCreated);
	/// Handle an incoming `funding_signed_eltoo` message from the given peer.
	fn handle_funding_signed_eltoo(&self, their_node_id: PublicKey, msg: &FundingSigned);

	/// Handle an incoming `channel_ready_eltoo` message from the given peer.
	fn handle_channel_ready_eltoo(&self, their_node_id: PublicKey, msg: &ChannelReady);

	// Channel close:
	/// Handle an incoming `shutdown_eltoo` message from the given peer.
	fn handle_shutdown_eltoo(&self, their_node_id: PublicKey, msg: &Shutdown);
	/// Handle an incoming `closing_signed_eltoo` message from the given peer.
	fn handle_closing_signed_eltoo(&self, their_node_id: PublicKey, msg: &ClosingSigned);

	// HTLC handling:
	/// Handle an incoming `update_add_htlc` message from the given peer.
	fn handle_update_add_htlc(&self, their_node_id: PublicKey, msg: &UpdateAddHTLC);
	/// Handle an incoming `update_fulfill_htlc` message from the given peer.
	fn handle_update_fulfill_htlc(&self, their_node_id: PublicKey, msg: UpdateFulfillHTLC);
	/// Handle an incoming `update_fail_htlc` message from the given peer.
	fn handle_update_fail_htlc(&self, their_node_id: PublicKey, msg: &UpdateFailHTLC);
	/// Handle an incoming `update_fail_malformed_htlc` message from the given peer.
	fn handle_update_fail_malformed_htlc(
		&self, their_node_id: PublicKey, msg: &UpdateFailMalformedHTLC,
	);
	/// Handle an incoming `update_signed` message from the given peer.
	fn handle_update_signed(&self, their_node_id: PublicKey, msg: &UpdateSigned);

	/// Handle an incoming `update_signed_ack` message from the given peer.
	fn handle_update_signed_ack(&self, their_node_id: PublicKey, msg: &UpdateSignedAck);

	// Channel-to-announce:
	/// Handle an incoming `announcement_signatures` message from the given peer.
	fn handle_announcement_signatures(
		&self, their_node_id: PublicKey, msg: &AnnouncementSignatures,
	);

	// Channel reestablish:
	/// Handle an incoming `channel_reestablish` message from the given peer.
	fn handle_channel_reestablish(&self, their_node_id: PublicKey, msg: &ChannelReestablish);

	// Error:
	/// Handle an incoming `error` message from the given peer.
	fn handle_error(&self, their_node_id: PublicKey, msg: &ErrorMessage);

	// Handler information:
	/// Gets the chain hashes for this `ChannelMessageHandler` indicating which chains it supports.
	///
	/// If it's `None`, then no particular network chain hash compatibility will be enforced when
	/// connecting to peers.
	fn get_chain_hashes(&self) -> Option<Vec<ChainHash>>;

	/// Indicates that a message was received from any peer for any handler.
	/// Called before the message is passed to the appropriate handler.
	/// Useful for indicating that a network connection is active.
	///
	/// Note: Since this function is called frequently, it should be as
	/// efficient as possible for its intended purpose.
	fn message_received(&self);
}

impl<T: ChannelMessageHandler + ?Sized, C: Deref<Target = T>> ChannelMessageHandler for C {
	fn handle_open_channel_eltoo(&self, their_node_id: PublicKey, msg: &OpenChannel) {
		self.deref().handle_open_channel_eltoo(their_node_id, msg)
	}

	fn handle_accept_channel_eltoo(&self, their_node_id: PublicKey, msg: &AcceptChannel) {
		self.deref().handle_accept_channel_eltoo(their_node_id, msg)
	}

	fn handle_funding_created_eltoo(&self, their_node_id: PublicKey, msg: &FundingCreated) {
		self.deref().handle_funding_created_eltoo(their_node_id, msg)
	}

	fn handle_funding_signed_eltoo(&self, their_node_id: PublicKey, msg: &FundingSigned) {
		self.deref().handle_funding_signed_eltoo(their_node_id, msg)
	}

	fn handle_channel_ready_eltoo(&self, their_node_id: PublicKey, msg: &ChannelReady) {
		self.deref().handle_channel_ready_eltoo(their_node_id, msg)
	}

	fn handle_shutdown_eltoo(&self, their_node_id: PublicKey, msg: &Shutdown) {
		self.deref().handle_shutdown_eltoo(their_node_id, msg)
	}

	fn handle_closing_signed_eltoo(&self, their_node_id: PublicKey, msg: &ClosingSigned) {
		self.deref().handle_closing_signed_eltoo(their_node_id, msg)
	}

	fn handle_update_add_htlc(&self, their_node_id: PublicKey, msg: &UpdateAddHTLC) {
		self.deref().handle_update_add_htlc(their_node_id, msg)
	}

	fn handle_update_fulfill_htlc(&self, their_node_id: PublicKey, msg: UpdateFulfillHTLC) {
		self.deref().handle_update_fulfill_htlc(their_node_id, msg)
	}

	fn handle_update_fail_htlc(&self, their_node_id: PublicKey, msg: &UpdateFailHTLC) {
		self.deref().handle_update_fail_htlc(their_node_id, msg)
	}

	fn handle_update_fail_malformed_htlc(
		&self, their_node_id: PublicKey, msg: &UpdateFailMalformedHTLC,
	) {
		self.deref().handle_update_fail_malformed_htlc(their_node_id, msg)
	}

	fn handle_update_signed(&self, their_node_id: PublicKey, msg: &UpdateSigned) {
		self.deref().handle_update_signed(their_node_id, msg)
	}

	fn handle_update_signed_ack(&self, their_node_id: PublicKey, msg: &UpdateSignedAck) {
		self.deref().handle_update_signed_ack(their_node_id, msg)
	}

	fn handle_announcement_signatures(
		&self, their_node_id: PublicKey, msg: &AnnouncementSignatures,
	) {
		self.deref().handle_announcement_signatures(their_node_id, msg)
	}

	fn handle_channel_reestablish(&self, their_node_id: PublicKey, msg: &ChannelReestablish) {
		self.deref().handle_channel_reestablish(their_node_id, msg)
	}

	fn handle_error(&self, their_node_id: PublicKey, msg: &ErrorMessage) {
		self.deref().handle_error(their_node_id, msg)
	}

	fn get_chain_hashes(&self) -> Option<Vec<ChainHash>> {
		self.deref().get_chain_hashes()
	}

	fn message_received(&self) {
		self.deref().message_received()
	}
}
