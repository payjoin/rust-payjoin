use std::borrow::Borrow;
use std::fmt;

use bitcoin::FeeRate;
use log::warn;

use crate::output_substitution::OutputSubstitution;
use crate::Version;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct Params {
    // version
    pub v: Version,
    // disableoutputsubstitution
    pub output_substitution: OutputSubstitution,
    // maxadditionalfeecontribution, additionalfeeoutputindex
    pub additional_fee_contribution: Option<(bitcoin::Amount, usize)>,
    // minfeerate
    pub min_fee_rate: FeeRate,
    #[cfg(feature = "_multiparty")]
    /// Opt in to optimistic psbt merge
    pub optimistic_merge: bool,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            v: Version::One,
            output_substitution: OutputSubstitution::Enabled,
            additional_fee_contribution: None,
            min_fee_rate: FeeRate::BROADCAST_MIN,
            #[cfg(feature = "_multiparty")]
            optimistic_merge: false,
        }
    }
}

impl Params {
    /// Warn when only one parameter is present rather than failing the entire payjoin process.
    ///
    /// This allows for graceful degradation and doesn't halt the payjoin process
    /// due to incomplete optional parameters, while still alerting about the unusual
    /// configuration that prevents fee adjustment capability.
    fn handle_additonal_fee_param(
        &mut self,
        max_additional_fee_contribution: Option<bitcoin::Amount>,
        additional_fee_output_index: Option<usize>,
    ) {
        match (max_additional_fee_contribution, additional_fee_output_index) {
            (Some(amount), Some(index)) => {
                self.additional_fee_contribution = Some((amount, index));
            }
            (Some(_), None) | (None, Some(_)) => {
                warn!("Only one additional fee parameter specified, proceeding without fee adjustment capability. Both maxadditionalfeecontribution and additionalfeeoutputindex must be present for receiver to alter sender's output: {self:?}");
            }
            (None, None) => (), // Neither parameter provided, normal case
        }
    }

    pub fn from_query_pairs<K, V, I>(
        pairs: I,
        supported_versions: &'static [Version],
    ) -> Result<Self, Error>
    where
        I: Iterator<Item = (K, V)>,
        K: Borrow<str> + Into<String>,
        V: Borrow<str> + Into<String>,
    {
        let mut params = Params::default();

        let mut additional_fee_output_index = None;
        let mut max_additional_fee_contribution = None;

        for (key, v) in pairs {
            match (key.borrow(), v.borrow()) {
                ("v", version) =>
                    params.v = match version {
                        "1" => Version::One,
                        "2" => Version::Two,
                        _ => return Err(Error::UnknownVersion { supported_versions }),
                    },
                ("additionalfeeoutputindex", index) =>
                    additional_fee_output_index = match index.parse::<usize>() {
                        Ok(index) => Some(index),
                        Err(_error) => {
                            warn!("bad `additionalfeeoutputindex` query value '{index}': {_error}");
                            None
                        }
                    },
                ("maxadditionalfeecontribution", fee) =>
                    max_additional_fee_contribution =
                        match bitcoin::Amount::from_str_in(fee, bitcoin::Denomination::Satoshi) {
                            Ok(contribution) => Some(contribution),
                            Err(_error) => {
                                warn!(
                                "bad `maxadditionalfeecontribution` query value '{fee}': {_error}"
                            );
                                None
                            }
                        },
                ("minfeerate", fee_rate) =>
                    params.min_fee_rate = match fee_rate.parse::<f32>() {
                        Ok(fee_rate_sat_per_vb) => {
                            // TODO Parse with serde when rust-bitcoin supports it
                            let fee_rate_sat_per_kwu = fee_rate_sat_per_vb * 250.0_f32;
                            // since it's a minimum, we want to round up
                            FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu.ceil() as u64)
                        }
                        Err(_) => return Err(Error::FeeRate),
                    },
                ("disableoutputsubstitution", v) =>
                    params.output_substitution = if v == "true" {
                        OutputSubstitution::Disabled
                    } else {
                        OutputSubstitution::Enabled
                    },
                #[cfg(feature = "_multiparty")]
                ("optimisticmerge", v) => params.optimistic_merge = v == "true",
                _ => (),
            }
        }

        params.handle_additonal_fee_param(
            max_additional_fee_contribution,
            additional_fee_output_index,
        );

        log::debug!("parsed optional parameters: {params:?}");
        Ok(params)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    UnknownVersion { supported_versions: &'static [Version] },
    FeeRate,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UnknownVersion { .. } => write!(f, "unknown version"),
            Error::FeeRate => write!(f, "could not parse feerate"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

#[cfg(test)]
pub(crate) mod test {
    use bitcoin::{Amount, FeeRate};

    use super::*;
    use crate::receive::optional_parameters::Params;
    use crate::Version;

    #[test]
    fn test_parse_params() {
        let pairs = url::form_urlencoded::parse(b"&maxadditionalfeecontribution=182&additionalfeeoutputindex=0&minfeerate=2&disableoutputsubstitution=true&optimisticmerge=true");
        let params = Params::from_query_pairs(pairs, &[Version::One])
            .expect("Could not parse params from query pairs");
        assert_eq!(params.v, Version::One);
        assert_eq!(params.output_substitution, OutputSubstitution::Disabled);
        assert_eq!(params.additional_fee_contribution, Some((Amount::from_sat(182), 0)));
        assert_eq!(
            params.min_fee_rate,
            FeeRate::from_sat_per_vb(2).expect("Could not calculate feerate")
        );
        #[cfg(feature = "_multiparty")]
        assert!(params.optimistic_merge)
    }

    #[test]
    fn from_query_pairs_unsupported_versions() {
        let invalid_pair: Vec<(&str, &str)> = vec![("v", "888")];
        let supported_versions = &[Version::One, Version::Two];
        let params = Params::from_query_pairs(invalid_pair.into_iter(), supported_versions);
        assert!(params.is_err());
        assert_eq!(params.err().unwrap(), Error::UnknownVersion { supported_versions });
    }
}
