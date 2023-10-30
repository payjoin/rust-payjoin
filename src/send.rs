use std::sync::{Arc, Mutex, MutexGuard};

use crate::error::PayjoinError;
use crate::transaction::PartiallySignedTransaction;
use crate::uri::Url;
use crate::{FeeRate, ScriptBuf};
pub use payjoin::send::Configuration as PdkConfiguration;

///Builder for sender-side payjoin parameters
///
///These parameters define how client wants to handle Payjoin.
pub struct Configuration {
	internal: Mutex<Option<PdkConfiguration>>,
}

impl From<PdkConfiguration> for Configuration {
	fn from(value: PdkConfiguration) -> Self {
		Self { internal: Mutex::new(Some(value)) }
	}
}

impl Configuration {
	pub fn get_configuration(
		&self,
	) -> (Option<PdkConfiguration>, MutexGuard<Option<PdkConfiguration>>) {
		let mut data_guard = self.internal.lock().unwrap();
		(Option::take(&mut *data_guard), data_guard)
	}
	///Offer the receiver contribution to pay for his input.
	///
	///These parameters will allow the receiver to take max_fee_contribution from given change output to pay for additional inputs. The recommended fee is size_of_one_input * fee_rate.
	///
	///change_index specifies which output can be used to pay fee. If None is provided, then the output is auto-detected unless the supplied transaction has more than two outputs.
	pub fn with_fee_contribution(max_fee_contribution: u64, change_index: Option<u64>) -> Self {
		let configuration = PdkConfiguration::with_fee_contribution(
			payjoin::bitcoin::Amount::from_sat(max_fee_contribution),
			change_index.map(|x| x as usize),
		);
		configuration.into()
	}

	//TODO;  doesn't satisfy `payjoin::send::error::ConfigurationError: ToString`
	pub fn recommended(
		psbt: Arc<PartiallySignedTransaction>, payout_scripts: Vec<Arc<ScriptBuf>>,
		min_fee_rate: Arc<FeeRate>,
	) -> Result<Self, PayjoinError> {
		let script_buf_iter = payout_scripts.iter().map(|x| (*(x.to_owned())).clone().into());

		match PdkConfiguration::recommended(
			&((*psbt).clone().into()),
			script_buf_iter,
			(*min_fee_rate).into(),
		) {
			Ok(e) => Ok(e.into()),
			Err(_) => Err(PayjoinError::UnexpectedError {
				message: "Invalid configuration found".to_string(),
			}),
		}
	}

	///Perform Payjoin without incentivizing the payee to cooperate.
	///
	///While it’s generally better to offer some contribution some users may wish not to. This function disables contribution.
	pub fn non_incentivizing() -> Self {
		PdkConfiguration::non_incentivizing().into()
	}
	///Disable output substitution even if the receiver didn’t.
	///
	///This forbids receiver switching output or decreasing amount. It is generally not recommended to set this as it may prevent the receiver from doing advanced operations such as opening LN channels and it also guarantees the receiver will not reward the sender with a discount.
	pub fn always_disable_output_substitution(&self, disable: bool) {
		let (config, mut guard) = Self::get_configuration(self);
		*guard = Some(config.unwrap().always_disable_output_substitution(disable));
	}

	///Decrease fee contribution instead of erroring.
	///
	///If this option is set and a transaction with change amount lower than fee contribution is provided then instead of returning error the fee contribution will be just lowered to match the change amount.
	pub fn clamp_fee_contribution(&self, clamp: bool) {
		let (config, mut guard) = Self::get_configuration(self);
		*guard = Some(config.unwrap().clamp_fee_contribution(clamp));
	}
	///Sets minimum fee rate required by the sender.
	pub fn min_fee_rate(&self, fee_rate: Arc<FeeRate>) {
		let (config, mut guard) = Self::get_configuration(self);
		*guard = Some(config.unwrap().min_fee_rate((*fee_rate.clone()).into()));
	}
}

///Data required for validation of response.

///This type is used to process the response. It is returned from PjUriExt::create_pj_request() method and you only need to call .process_response() on it to continue BIP78 flow.

pub struct Context {
	internal: Mutex<Option<payjoin::send::Context>>,
}

impl Context {
	fn get_context(&self) -> Option<payjoin::send::Context> {
		let mut data_guard = self.internal.lock().unwrap();
		Option::take(&mut *data_guard)
	}
	///Decodes and validates the response.

	///Call this method with response from receiver to continue BIP78 flow. If the response is valid you will get appropriate PSBT that you should sign and broadcast.

	pub fn process_response(
		&self, response: String,
	) -> Result<Arc<PartiallySignedTransaction>, PayjoinError> {
		match self.get_context().unwrap().process_response(&mut response.as_bytes()) {
			Ok(e) => Ok(Arc::new(PartiallySignedTransaction::from(e))),
			Err(e) => Err(PayjoinError::ContextValidationError { message: e.to_string() }),
		}
	}
}

impl From<payjoin::send::Context> for Context {
	fn from(value: payjoin::send::Context) -> Self {
		Self { internal: Mutex::new(Some(value)) }
	}
}

///Represents data that needs to be transmitted to the receiver.

///You need to send this request over HTTP(S) to the receiver.
pub struct Request {
	///URL to send the request to.
	///
	///This is full URL with scheme etc - you can pass it right to reqwest or a similar library.
	pub url: Arc<Url>,
	///Bytes to be sent to the receiver.
	///
	///This is properly encoded PSBT, already in base64. You only need to make sure Content-Type is text/plain and Content-Length is body.len() (most libraries do the latter automatically).
	pub body: Vec<u8>,
}

#[cfg(test)]
mod tests {
	use crate::PartiallySignedTransaction;

	#[test]
	fn official_vectors() {
		let original = "cHNidP8BAHECAAAAAVuDh6O7xLpvJm70AWI6N25VtXzMiknZxAwcPtGoB/VHAAAAAAD+////AuYPECQBAAAAFgAUHAMjFjcTerY7Cmi4se8VqWIW5HgA4fUFAAAAABYAFL6Az084ngrVLQfpl3hccYjeF+EQAAAAAAABAIQCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wNSAQH/////AgDyBSoBAAAAFgAUQ0p5pXSyKswNZuFoJjltIQhFnpkAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QAAAAABAR8A8gUqAQAAABYAFENKeaV0sirMDWbhaCY5bSEIRZ6ZAQhrAkcwRAIgFe1S3DHoDIPHogsTU/9UD7IqPbNXDYfyU2JZT9HKD7oCIAxU7sZzUcoGsmM3lDetos/3N5fM5oynmzuvsrFiILN5ASECfoMstJPrqnyhems+r158wTniKIBaPkkCinDC4VdvmsYAIgIDXVq5OYL7D4Ur28OTJ77j0lZrSPzO5XGmkL/KIF7wKmgQgTP32gAAAIABAACAAQAAgAAA";

		let original_psbt = PartiallySignedTransaction::from_string(original.to_string()).unwrap();
		eprintln!("original: {:#?}", original_psbt);

		let pj_uri_string = "BITCOIN:BCRT1Q7WXQ0R2JHJKX8HQS3SHLKFAEAEF38C38SYKGZY?amount=1&pj=https://example.comOriginal".to_string();
		let _uri = crate::Uri::new(pj_uri_string).unwrap();
		eprintln!("address: {:#?}", _uri.address().as_string());

		let pj_uri = _uri.check_pj_supported().expect("Bad Uri");

		let pj_params = crate::Configuration::with_fee_contribution(10000, None);
		pj_params.always_disable_output_substitution(true);
		pj_params.clamp_fee_contribution(true);
		assert_eq!(pj_uri.amount().unwrap().to_btc(), 1.0)
	}
}
