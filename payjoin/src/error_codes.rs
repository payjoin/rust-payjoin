//! Well-known error codes as defined in BIP-78
//! See: <https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#receivers-well-known-errors>

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ErrorCode {
    /// The payjoin endpoint is not available for now.
    Unavailable,
    /// The receiver added some inputs but could not bump the fee of the payjoin proposal.
    NotEnoughMoney,
    /// This version of payjoin is not supported.
    VersionUnsupported,
    /// The receiver rejected the original PSBT.
    OriginalPsbtRejected,
}

impl ErrorCode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::NotEnoughMoney => "not-enough-money",
            Self::VersionUnsupported => "version-unsupported",
            Self::OriginalPsbtRejected => "original-psbt-rejected",
        }
    }
}

impl core::str::FromStr for ErrorCode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unavailable" => Ok(Self::Unavailable),
            "not-enough-money" => Ok(Self::NotEnoughMoney),
            "version-unsupported" => Ok(Self::VersionUnsupported),
            "original-psbt-rejected" => Ok(Self::OriginalPsbtRejected),
            _ => Err(()),
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
