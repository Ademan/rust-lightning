#![allow(missing_docs)] // FIXME: XXX: Remove later

pub mod chain;
pub mod channelmanager;
pub mod msgs;

// Re-export to enable convenient usage as [`eltoo::*`]
pub use msgs::{
	Message,
	AcceptChannel, ChannelReady, ChannelReestablish, ClosingSigned, FundingCreated, FundingSigned,
	OpenChannel, Shutdown, UpdateSigned, UpdateSignedAck,
};

pub use msgs::{
	ChannelMessageHandler,
};

pub use channelmanager::{
	ChannelManager,
	SimpleArcChannelManager,
	SimpleRefChannelManager,
};
