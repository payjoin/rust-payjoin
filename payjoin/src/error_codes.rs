//! Well-known error codes as defined in BIP-78
//! See: <https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#receivers-well-known-errors>

/// The payjoin endpoint is not available for now.
pub const UNAVAILABLE: &str = "unavailable";

/// The receiver added some inputs but could not bump the fee of the payjoin proposal.
pub const NOT_ENOUGH_MONEY: &str = "not-enough-money";

/// This version of payjoin is not supported.
pub const VERSION_UNSUPPORTED: &str = "version-unsupported";

/// The receiver rejected the original PSBT.
pub const ORIGINAL_PSBT_REJECTED: &str = "original-psbt-rejected";
