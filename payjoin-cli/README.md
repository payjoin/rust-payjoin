# **payjoin-cli README**

 ## A command-line payjoin client for bitcoind in rust

### **Install payjoin-cli**
 \
 Get a list of commands and options:\
 ```console
 RUST_LOG=debug cargo run \-- \--help\
 ```
 Manually create a config.toml file within the payjoin-cli directory
 and configurate it as follows:
```toml
 \# config.toml\
 bitcoind_cookie = "\[bitcoind cookie file location\]" \# mine was:
 \"/tmp/regtest1/bitcoind/regtest/.cookie\" \
 bitcoind_rpchost = "\[rpcport/wallet/wallet name\]" \# mine was:
 \"http://localhost:18443/wallet/boom"
 ```

### **Receive Payjoin**
 Set up 2 local regtest wallets and fund them. In my case, I funded a
 regtest wallet "boom" with 158 coins and another wallet "ocean" with
 .8 coins.

 Determine the RPC port specified in your bitcoind's "bitcoin.conf"
 file. Mine was 18443. Look for:\
 ```toml
 rpcport=\[rpcport\]\
 ```
 Run the following command from the payjoin-cli directory, where "boom"
 is the receiving wallet, 18443 is the rpc port, and you wish to
 request 10,000 sats:\
 ```console
 RUST_LOG=debug cargo run \-- -r "http://localhost:18443/wallet/boom"
 receive 10000\
 ```
 This will generate a pay join-capable bip21 URI with which to accept
 payjoin as follows:\
 ```console
 BITCOIN:BCRT1QCJ4X75DUNY4X5NAWLM3CR8MALM9YAUYWWEWKWL?amount=0.00010&pj=http
 s://localhost:3010
 ```

 Default configuration listens for payjoin requests at
 http://localhost:3000 and lists server as https://localhost:3010.

 Download and install local-ssl-proxy:\
 https://github.com/cameronhunter/local-ssl-proxy \
 The default configuration listens for payjoin requests at http://localhost:3000 and lists the server as 
 https://localhost:3010. Only https and .onion payjoin endpoints are valid. Therefore, in order to receive
  payjoin, one must also host an https reverse proxy to marshall https requests from localhost:3010 to
   localhost:3000.To do this, run:
```console
local-ssl-proxy \--source 3010 \--target 3000
```
###  **Send Payjoin**

 **cd** into the "sender" directory within payjoin-cli. Create another
 config.toml file in this directory and configure it as you did
 previously, except replace the receiver wallet name with the sender
 wallet name ("ocean" for me).

 If you are testing locally, add the following line to the
 configuration file:

 danger_accept_invalid_certs = true

 Using the previously generated bip21 URI, run the following command
 from the sender directory:

 RUST_LOG=debug cargo run \-- send "\[BIP21 URI\]"

 You should see the payjoin transaction occur and be able to verify the
 Partially Signed Bitcoin Transaction (PSBT), inputs, and Unspent
 Transaction Outputs (UTXOs).
