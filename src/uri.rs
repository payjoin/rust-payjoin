use crate::{
	send::{Configuration, Context, Request},
	transaction::PartiallySignedTransaction,
	Address, Network,
};
use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use payjoin::{bitcoin, PjUriExt, UriExt};
use std::str::FromStr;

#[derive(Clone)]
pub enum PayjoinUri {
	Unchecked(payjoin::Uri<'static, NetworkUnchecked>),
	Checked(payjoin::Uri<'static, NetworkChecked>),
}
#[derive(Clone)]
pub struct Uri {
	internal: PayjoinUri,
}

impl Uri {
	pub fn from_str(uri: String) -> Result<Self, anyhow::Error> {
		match payjoin::Uri::from_str(uri.as_str()) {
			Ok(e) => Ok(Uri { internal: PayjoinUri::Unchecked(e) }),
			Err(e) => anyhow::bail!(e),
		}
	}
	pub fn assume_checked(self) -> Self {
		match self.internal {
			PayjoinUri::Unchecked(e) => Self { internal: PayjoinUri::Checked(e.assume_checked()) },
			PayjoinUri::Checked(e) => Self { internal: PayjoinUri::Checked(e) },
		}
	}
	pub fn check_pj_supported(self) -> Result<PrjUri, anyhow::Error> {
		match self.internal {
			PayjoinUri::Unchecked(_) => anyhow::bail!("Network Unchecked"),
			PayjoinUri::Checked(e) => match e.check_pj_supported() {
				Ok(e) => Ok(PrjUri { internal: e }),
				Err(e) => anyhow::bail!(e),
			},
		}
	}
	pub fn address(self) -> Address {
		match self.internal {
			PayjoinUri::Unchecked(e) => {
				Address { internal: crate::BitcoinAddress::Unchecked(e.address) }
			}
			PayjoinUri::Checked(e) => {
				Address { internal: crate::BitcoinAddress::Checked(e.address) }
			}
		}
	}
	pub fn amount(self) -> Option<u64> {
		match self.internal {
			PayjoinUri::Unchecked(e) => match e.amount {
				Some(a) => Some(a.to_sat()),
				None => None,
			},
			PayjoinUri::Checked(e) => match e.amount {
				Some(a) => Some(a.to_sat()),
				None => None,
			},
		}
	}
	pub fn require_network(self, network: Network) -> Result<Self, anyhow::Error> {
		match self.internal {
			PayjoinUri::Unchecked(e) => Ok(Uri {
				internal: PayjoinUri::Checked(
					e.require_network(network.into()).expect("Invalid Network"),
				),
			}),
			PayjoinUri::Checked(_) => anyhow::bail!("Network already checked"),
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

	pub fn address(self) -> String {
		// Address { internal: crate::BitcoinAddress::Checked() }
		self.internal.address.to_string()
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
