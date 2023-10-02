use crate::{transaction::PartiallySignedTransaction, uri::Url};
use payjoin::send::ValidationError;
pub use payjoin::send::{Configuration as PdkConfiguration, Context as PdkContext};
use std::sync::{Arc, Mutex, MutexGuard};

///Builder for sender-side payjoin parameters
///
///These parameters define how client wants to handle Payjoin.

pub struct Configuration {
	pub internal: Mutex<Option<PdkConfiguration>>,
}

impl Configuration {
	pub(crate) fn get_configuration_mutex(&self) -> MutexGuard<Option<PdkConfiguration>> {
		self.internal.lock().expect("PdkConfiguration")
	}
	///Offer the receiver contribution to pay for his input.
	///
	///These parameters will allow the receiver to take max_fee_contribution from given change output to pay for additional inputs. The recommended fee is size_of_one_input * fee_rate.
	///
	///change_index specifies which output can be used to pay fee. If None is provided, then the output is auto-detected unless the supplied transaction has more than two outputs.
	pub fn with_fee_contribution(max_fee_contribution: u64, change_index: Option<usize>) -> Self {
		let configuration = PdkConfiguration::with_fee_contribution(
			payjoin::bitcoin::Amount::from_sat(max_fee_contribution),
			change_index,
		);
		Self { internal: Mutex::new(Some(configuration)) }
	}
	///Perform Payjoin without incentivizing the payee to cooperate.
	///
	///While it’s generally better to offer some contribution some users may wish not to. This function disables contribution.
	pub fn non_incentivizing() -> Self {
		Self { internal: Mutex::new(Some(PdkConfiguration::non_incentivizing())) }
	}
	///Disable output substitution even if the receiver didn’t.
	///
	///This forbids receiver switching output or decreasing amount. It is generally not recommended to set this as it may prevent the receiver from doing advanced operations such as opening LN channels and it also guarantees the receiver will not reward the sender with a discount.
	pub fn always_disable_output_substitution(self, disable: bool) -> Self {
		{
			let mut data_guard = self.get_configuration_mutex();
			let _config = std::mem::replace(&mut *data_guard, None);
			*data_guard = Some(_config.unwrap().always_disable_output_substitution(disable));
		}
		self
	}
	///Decrease fee contribution instead of erroring.
	///
	///If this option is set and a transaction with change amount lower than fee contribution is provided then instead of returning error the fee contribution will be just lowered to match the change amount.
	pub fn clamp_fee_contribution(self, clamp: bool) -> Self {
		{
			let mut data_guard = self.get_configuration_mutex();
			let _config = std::mem::replace(&mut *data_guard, None);
			*data_guard = Some(_config.unwrap().clamp_fee_contribution(clamp));
		}
		self
	}
	///Sets minimum fee rate required by the sender.
	pub fn min_fee_rate_sat_per_vb(self, fee_rate: u64) -> Self {
		{
			let mut data_guard = self.get_configuration_mutex();
			let _config = std::mem::replace(&mut *data_guard, None);
			*data_guard = Some(_config.unwrap().min_fee_rate_sat_per_vb(fee_rate));
		}
		self
	}
}

///Data required for validation of response.

///This type is used to process the response. It is returned from PjUriExt::create_pj_request() method and you only need to call .process_response() on it to continue BIP78 flow.
pub struct Context {
	pub internal: PdkContext,
}

impl Context {
	///Decodes and validates the response.

	///Call this method with response from receiver to continue BIP78 flow. If the response is valid you will get appropriate PSBT that you should sign and broadcast.
	pub fn process_response(
		self, response: &mut impl std::io::Read,
	) -> Result<PartiallySignedTransaction, ValidationError> {
		match self.internal.process_response(response) {
			Ok(e) => Ok(PartiallySignedTransaction { internal: Arc::new(e.to_owned()) }),
			Err(e) => Err(e),
		}
	}
}

///Represents data that needs to be transmitted to the receiver.

///You need to send this request over HTTP(S) to the receiver.
pub struct Request {
	///URL to send the request to.
	///
	///This is full URL with scheme etc - you can pass it right to reqwest or a similar library.
	pub url: Url,
	///Bytes to be sent to the receiver.
	///
	///This is properly encoded PSBT, already in base64. You only need to make sure Content-Type is text/plain and Content-Length is body.len() (most libraries do the latter automatically).
	pub body: Vec<u8>,
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use bitcoincore_rpc::bitcoin::psbt::PartiallySignedTransaction;

	#[test]
	fn official_vectors() {
		let original_psbt =
            "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

		let proposal =
            "cHNidP8BAJwCAAAAAo8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////jye60aAl3JgZdaIERvjkeh72VYZuTGH/ps2I4l0IO4MBAAAAAP7///8CJpW4BQAAAAAXqRQd6EnwadJ0FQ46/q6NcutaawlEMIcACT0AAAAAABepFHdAltvPSGdDwi9DR+m0af6+i2d6h9MAAAAAAQEgqBvXBQAAAAAXqRTeTh6QYcpZE1sDWtXm1HmQRUNU0IcBBBYAFMeKRXJTVYKNVlgHTdUmDV/LaYUwIgYDFZrAGqDVh1TEtNi300ntHt/PCzYrT2tVEGcjooWPhRYYSFzWUDEAAIABAACAAAAAgAEAAAAAAAAAAAEBIICEHgAAAAAAF6kUyPLL+cphRyyI5GTUazV0hF2R2NWHAQcXFgAUX4BmVeWSTJIEwtUb5TlPS/ntohABCGsCRzBEAiBnu3tA3yWlT0WBClsXXS9j69Bt+waCs9JcjWtNjtv7VgIge2VYAaBeLPDB6HGFlpqOENXMldsJezF9Gs5amvDQRDQBIQJl1jz1tBt8hNx2owTm+4Du4isx0pmdKNMNIjjaMHFfrQABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUIgICygvBWB5prpfx61y1HDAwo37kYP3YRJBvAjtunBAur3wYSFzWUDEAAIABAACAAAAAgAEAAAABAAAAAAA=";

		let original_psbt = PartiallySignedTransaction::from_str(original_psbt).unwrap();
		eprintln!("original: {:#?}", original_psbt);
		let mut proposal = PartiallySignedTransaction::from_str(proposal).unwrap();
		eprintln!("proposal: {:#?}", proposal);
		for mut output in proposal.clone().outputs {
			output.bip32_derivation.clear();
		}
		for mut input in proposal.clone().inputs {
			input.bip32_derivation.clear();
		}
		proposal.inputs[0].witness_utxo = None;
	}
}
