/*
NKpsk0:
  <- s
  ...
  -> psk, e, es
  <- e, ee
  ->
  <-
*/

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

#[macro_use]
pub(crate) mod macros;

pub(crate) mod prims;
pub(crate) mod state;
pub(crate) mod utils;

pub mod consts;
pub mod error;
pub mod noisesession;
pub mod types;


#[cfg(test)]
mod test {
    use crate::consts::{MAC_LENGTH, DHLEN};
    use crate::noisesession::NoiseSession;
    use crate::types::{Keypair, Psk, PublicKey};

  #[test]
  fn e2e_from_pj_sender() {
    println!("test");

    // <- s
    let receiver_static = Keypair::default(); // s from responder aka payjoin receiver
    let rs = receiver_static.get_public_key(); // rs from responder

    // ...
    let original_psbt = b"Original PSBT";
    println!("original_psbt: {:?}", String::from_utf8(original_psbt.to_vec()));
    println!("original_psbt bytes: {:?}", original_psbt);
    // ...

    // Ready Message A -> psk, e, es

    //  from the sender
    let sender_static = Keypair::new_empty(); // the N in NK, should be nothing at all.
    let psk = Psk::default(); // pre-shared (from WHO?) symmetric key. // TODO get from randomness, not default() emptyness
    let mut sender = NoiseSession::init_session(true, b"prologue", sender_static, Some(rs), psk.clone());
    sender.set_ephemeral_keypair(Keypair::default()); // sender's e

    let mut in_out: Vec<u8> = Vec::new();
    in_out.extend(original_psbt);
    let message_a_size = original_psbt.len() + DHLEN + MAC_LENGTH;
    in_out.resize(message_a_size, 0);
    sender.send_message(&mut in_out).unwrap(); // psk, e, es
    let mut message_a = in_out;
    
    //  from the receiver
    let mut receiver = NoiseSession::init_session(false, b"prologue", receiver_static, None, psk);
    receiver.set_ephemeral_keypair(Keypair::default()); // receiver's e
    //let mut message_a_received: Vec<u8> = Vec::with_capacity(message_a_size); // you would have to make a sized buffer in implementation
    receiver.recv_message(&mut message_a).unwrap(); // es derived internally
    println!("message_a bytes:{:?}", message_a);
    let orig = &message_a[..original_psbt.len()];
    println!("message_a decrypted:{:?}", String::from_utf8(orig.to_vec()));

    // Ready Message B <- e, ee
  }
}