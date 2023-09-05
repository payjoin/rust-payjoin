use crate::{
	send::{Configuration, Context, Request},
	transaction::PartiallySignedTransaction,
	Address, Network,
};
use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use payjoin::{bitcoin, PjUriExt, UriExt};
use std::str::FromStr;

#[derive(Clone)]
pub struct Uri<T>
where
	T: bitcoin::address::NetworkValidation,
{
	pub internal: payjoin::Uri<'static, T>,
}

impl Uri<NetworkUnchecked> {
	pub fn from_str(uri: String) -> Result<Self, anyhow::Error> {
		match payjoin::Uri::from_str(uri.as_str()) {
			Ok(e) => Ok(Uri { internal: e }),
			Err(e) => anyhow::bail!(e),
		}
	}
	pub fn assume_checked(self) -> Uri<NetworkChecked> {
		Uri { internal: self.internal.assume_checked() }
	}
	pub fn require_network(self, network: Network) -> Result<Uri<NetworkChecked>, anyhow::Error> {
		Ok(Uri {
			internal: self.internal.require_network(network.into()).expect("Invalid Network"),
		})
	}
}
impl Uri<NetworkChecked> {
	pub fn address(&self) -> Address<NetworkChecked> {
		Address { internal: self.internal.address.to_owned() }
	}
	pub fn amount(&self) -> u64 {
		self.internal.amount.unwrap().to_sat()
	}
	pub fn check_pj_supported(self) -> Result<PrjUri, anyhow::Error> {
		match self.internal.check_pj_supported() {
			Ok(e) => Ok(PrjUri { internal: e }),
			Err(e) => anyhow::bail!(e),
		}
	}
}

#[derive(Debug, Clone)]
pub struct PrjUri {
	pub internal: payjoin::PjUri<'static>,
}
impl PrjUri {
	pub fn create_pj_request(
		self, psbt: PartiallySignedTransaction, params: Configuration,
	) -> Result<(Request, Context), anyhow::Error> {
		let config = std::mem::replace(&mut *params.internal.lock().unwrap(), None);
		match self.internal.create_pj_request(psbt.internal.as_ref().to_owned(), config.unwrap()) {
			Ok(e) => Ok((
				Request { url: Url { internal: e.0.url }, body: e.0.body },
				Context { internal: e.1 },
			)),
			Err(e) => anyhow::bail!(e),
		}
	}

	pub fn address(self) -> Address<NetworkChecked> {
		Address { internal: self.internal.address }
	}
	pub fn amount(self) -> Option<payjoin::bitcoin::Amount> {
		self.internal.amount
	}
}

pub struct Url {
	pub internal: url::Url,
}
impl Url {
	pub fn parse(input: String) -> Result<Url, anyhow::Error> {
		match url::Url::from_str(input.as_str()) {
			Ok(e) => Ok(Self { internal: e }),
			Err(e) => anyhow::bail!(e),
		}
	}
}
#[cfg(test)]
mod tests {
	use payjoin::Uri;
	use std::convert::TryFrom;

	#[test]
	fn test_short() {
		assert!(Uri::try_from("").is_err());
		assert!(Uri::try_from("bitcoin").is_err());
		assert!(Uri::try_from("bitcoin:").is_err());
	}

	#[ignore]
	#[test]
	fn test_todo_url_encoded() {
		let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
		assert!(Uri::try_from(uri).is_err(), "pj url should be url encoded");
	}

	#[test]
	fn test_valid_url() {
		let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=this_is_NOT_a_validURL";
		assert!(Uri::try_from(uri).is_err(), "pj is not a valid url");
	}

	#[test]
	fn test_missing_amount() {
		let uri =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj";
		assert!(Uri::try_from(uri).is_ok(), "missing amount should be ok");
	}

	#[test]
	fn test_unencrypted() {
		let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=http://example.com";
		assert!(Uri::try_from(uri).is_err(), "unencrypted connection");

		let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=ftp://foo.onion";
		assert!(Uri::try_from(uri).is_err(), "unencrypted connection");
	}

	#[test]
	fn test_valid_uris() {
		let https = "https://example.com";
		let onion = "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion";

		let base58 = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
		let bech32_upper = "BITCOIN:TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4";
		let bech32_lower = "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";

		for address in [base58, bech32_upper, bech32_lower].iter() {
			for pj in [https, onion].iter() {
				// TODO add with and without amount
				// TODO shuffle params
				let uri = format!("{}?amount=1&pj={}", address, pj);
				assert!(Uri::try_from(&*uri).is_ok());
			}
		}
	}

	#[test]
	fn test_unsupported() {
		assert!(!Uri::try_from("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX")
			.unwrap()
			.extras
			.pj_is_supported());
	}
}
