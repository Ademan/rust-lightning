use secp256k1_musig::{
    All,
    musig,
	PublicKey,
    Secp256k1,
	SecretKey,
    Signing,
    Verification,
};

// XXX: Generalize later
pub struct ChannelSigner {
	secp: Secp256k1<All>,

	update_secret: SecretKey,

	update_agg_pk: PublicKey,
}

impl ChannelSigner {

}
