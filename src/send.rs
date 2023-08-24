use std::{string::ParseError, sync::RwLock};

pub use payjoin::send::{Configuration as PdkConfiguration, Context as PdkContext};

///Builder for sender-side payjoin parameters
///These parameters define how client wants to handle Payjoin.

pub(crate) struct Configuration {
	pub(crate) internal: RwLock<Option<PdkConfiguration>>,
}

impl Configuration {
	///Offer the receiver contribution to pay for his input.
	///These parameters will allow the receiver to take max_fee_contribution from given change output to pay for additional inputs. The recommended fee is size_of_one_input * fee_rate.
	///change_index specifies which output can be used to pay fee. If None is provided, then the output is auto-detected unless the supplied transaction has more than two outputs.
	pub fn with_fee_contribution(max_fee_contribution: u64, change_index: Option<usize>) -> Self {
		let configuration = PdkConfiguration::with_fee_contribution(
			bitcoin::Amount::from_sat(max_fee_contribution),
			change_index,
		);
		Self { internal: RwLock::new(Some(configuration)) }
	}
	///Perform Payjoin without incentivizing the payee to cooperate.
	///While it’s generally better to offer some contribution some users may wish not to. This function disables contribution.
	pub fn non_incentivizing() -> Self {
		Self { internal: RwLock::new(Some(PdkConfiguration::non_incentivizing())) }
	}
	///Disable output substitution even if the receiver didn’t.
	///This forbids receiver switching output or decreasing amount. It is generally not recommended to set this as it may prevent the receiver from doing advanced operations such as opening LN channels and it also guarantees the receiver will not reward the sender with a discount.
	pub fn always_disable_output_substitution(self, disable: bool) -> Self {
		{
			let mut data_guard = self.internal.write().unwrap();
			// Temporarily take out the Configuration and replace with a dummy value
			let _config = std::mem::replace(&mut *data_guard, None);
			*data_guard = Some(_config.unwrap().always_disable_output_substitution(disable));
		}
		self
	}
	///Decrease fee contribution instead of erroring.
	///If this option is set and a transaction with change amount lower than fee contribution is provided then instead of returning error the fee contribution will be just lowered to match the change amount.
	pub fn clamp_fee_contribution(self, clamp: bool) -> Self {
		{
			let mut data_guard = self.internal.write().unwrap();
			// Temporarily take out the Configuration and replace with a dummy value
			let _config = std::mem::replace(&mut *data_guard, None);
			*data_guard = Some(_config.unwrap().clamp_fee_contribution(clamp));
		}
		self
	}
	///Sets minimum fee rate required by the sender.
	pub fn min_fee_rate_sat_per_vb(self, fee_rate: u64) -> Self {
		{
			let mut data_guard = self.internal.write().unwrap();
			// Temporarily take out the Configuration and replace with a dummy value
			let _config = std::mem::replace(&mut *data_guard, None);
			*data_guard = Some(_config.unwrap().min_fee_rate_sat_per_vb(fee_rate));
		}
		self
	}
}
pub struct Context {
	pub internal: PdkContext,
}

///Represents data that needs to be transmitted to the receiver.

///You need to send this request over HTTP(S) to the receiver.
pub struct Request {
	///URL to send the request to.

	///This is full URL with scheme etc - you can pass it right to reqwest or a similar library.
	pub url: Url,
	///Bytes to be sent to the receiver.

	///This is properly encoded PSBT, already in base64. You only need to make sure Content-Type is text/plain and Content-Length is body.len() (most libraries do the latter automatically).
	pub body: Vec<u8>,
}
pub struct Url {
	pub internal: String,
}
impl Url {
	pub fn parse(input: String) -> Result<Url, ParseError> {
		Ok(Self { internal: input })
	}
}
