use std::borrow::Borrow;
use std::fmt;

use crate::fee_rate::FeeRate;

#[derive(Debug)]
pub(crate) struct Params {
    // version
    // v: usize,
    // disableoutputsubstitution
    pub disable_output_substitution: bool,
    // maxadditionalfeecontribution, additionalfeeoutputindex
    pub additional_fee_contribution: Option<(bitcoin::Amount, usize)>,
    // minfeerate
    pub min_feerate: FeeRate,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            disable_output_substitution: false,
            additional_fee_contribution: None,
            min_feerate: FeeRate::ZERO,
        }
    }
}

impl Params {
    #[cfg(feature = "receiver")]
    pub fn from_query_pairs<K, V, I>(pairs: I) -> Result<Self, Error>
    where
        I: Iterator<Item = (K, V)>,
        K: Borrow<str> + Into<String>,
        V: Borrow<str> + Into<String>,
    {
        let mut params = Params::default();

        let mut additional_fee_output_index = None;
        let mut max_additional_fee_contribution = None;

        for (k, v) in pairs {
            match (k.borrow(), v.borrow()) {
                ("v", v) =>
                    if v != "1" {
                        return Err(Error::UnknownVersion);
                    },
                ("additionalfeeoutputindex", index) =>
                    if let Ok(index) = index.parse::<usize>() {
                        additional_fee_output_index = Some(index);
                    },
                ("maxadditionalfeecontribution", fee) => {
                    max_additional_fee_contribution =
                        bitcoin::Amount::from_str_in(&fee, bitcoin::Denomination::Bitcoin).ok();
                }
                ("minfeerate", feerate) =>
                    params.min_feerate = match feerate.parse::<u64>() {
                        Ok(rate) => FeeRate::from_sat_per_vb(rate),
                        Err(e) => return Err(Error::FeeRate(e)),
                    },
                ("disableoutputsubstitution", v) =>
                    params.disable_output_substitution = v == "true",
                _ => (),
            }
        }
        if let (Some(amount), Some(index)) =
            (max_additional_fee_contribution, additional_fee_output_index)
        {
            params.additional_fee_contribution = Some((amount, index));
        }

        Ok(params)
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    UnknownVersion,
    FeeRate(std::num::ParseIntError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UnknownVersion => write!(f, "unknown version"),
            Error::FeeRate(_) => write!(f, "could not parse feerate"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::FeeRate(error) => Some(error),
            _ => None,
        }
    }
}
