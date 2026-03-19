use bitcoin::Amount;
use corepc_node::AddressType;
use tracing::Level;

use crate::BoxError;

pub fn init_bitcoind() -> Result<corepc_node::Node, BoxError> {
    let bitcoind_exe = corepc_node::exe_path()?;
    let mut conf = corepc_node::Conf::default();
    conf.view_stdout = tracing::enabled!(target: "corepc", Level::TRACE);
    // conf.args.push("-txindex");
    let bitcoind = corepc_node::Node::with_conf(bitcoind_exe, &conf)?;
    Ok(bitcoind)
}

pub fn init_bitcoind_sender_receiver(
    sender_address_type: Option<AddressType>,
    receiver_address_type: Option<AddressType>,
) -> Result<(corepc_node::Node, corepc_node::Client, corepc_node::Client), BoxError> {
    let bitcoind = init_bitcoind()?;
    let mut wallets = create_and_fund_wallets(
        &bitcoind,
        vec![("receiver", receiver_address_type), ("sender", sender_address_type)],
    )?;
    let receiver = wallets.pop().expect("receiver to exist");
    let sender = wallets.pop().expect("sender to exist");

    Ok((bitcoind, receiver, sender))
}

fn create_and_fund_wallets<W: AsRef<str>>(
    bitcoind: &corepc_node::Node,
    wallets: Vec<(W, Option<AddressType>)>,
) -> Result<Vec<corepc_node::Client>, BoxError> {
    let mut funded_wallets = vec![];
    let funding_wallet = bitcoind.create_wallet("funding_wallet")?;
    let funding_address = funding_wallet.new_address()?;
    // 100 blocks would work here, we add a extra block to cover fees between transfers
    bitcoind.client.generate_to_address(101 + wallets.len(), &funding_address)?;
    for (wallet_name, address_type) in wallets {
        let wallet = bitcoind.create_wallet(wallet_name)?;
        let address = wallet.get_new_address(None, address_type)?.into_model()?.0.assume_checked();
        funding_wallet.send_to_address(&address, Amount::from_btc(50.0)?)?;
        funded_wallets.push(wallet);
    }
    // Mine the block which funds the different wallets
    bitcoind.client.generate_to_address(1, &funding_address)?;

    for wallet in funded_wallets.iter() {
        let balances = wallet.get_balances()?.into_model()?;
        assert_eq!(
            balances.mine.trusted,
            Amount::from_btc(50.0)?,
            "wallet doesn't have expected amount of bitcoin"
        );
    }

    Ok(funded_wallets)
}

pub fn init_bitcoind_multi_sender_single_reciever(
    number_of_senders: usize,
) -> Result<(corepc_node::Node, Vec<corepc_node::Client>, corepc_node::Client), BoxError> {
    let bitcoind = init_bitcoind()?;
    let wallets_to_create =
        (0..number_of_senders + 1).map(|i| (format!("sender_{i}"), None)).collect::<Vec<_>>();
    let mut wallets = create_and_fund_wallets(&bitcoind, wallets_to_create)?;
    let receiver = wallets.pop().expect("receiver to exist");
    let senders = wallets;

    Ok((bitcoind, senders, receiver))
}
