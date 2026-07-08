#![allow(missing_docs)] // FIXME: XXX: Remove later

pub mod msgs;

// Re-export to enable convenient usage as [`eltoo::*`]
pub use msgs::{
	AcceptChannel, ChannelReady, ChannelReestablish, ClosingSigned, FundingCreated, FundingSigned,
	OpenChannel, Shutdown, UpdateSigned, UpdateSignedAck,
};
