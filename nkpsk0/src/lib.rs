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
    // <- s
    let receiver_static = Keypair::default(); // s from responder aka payjoin receiver
    let rs = receiver_static.get_public_key(); // rs from responder

    // ...
    let original_psbt = b"Original PSBT";
    println!("original_psbt: {:?}", String::from_utf8(original_psbt.to_vec()));
    // ...

    // Ready Message A -> psk, e, es

    //  from the initiator (payjoin sender)
    let sender_static = Keypair::new_empty(); // the N in NK, should be nothing at all.
    let psk = Psk::default(); // pre-shared (from WHO?) symmetric key. // TODO get from randomness, not default() emptyness
    let mut initiator = NoiseSession::init_session(true, b"", sender_static, Some(rs), psk.clone());

    let mut in_out: Vec<u8> = vec![0; DHLEN];
    in_out.append(&mut original_psbt.to_vec());
    let message_a_size = DHLEN + original_psbt.len() + MAC_LENGTH;
    in_out.resize(message_a_size, 0);
    initiator.send_message(&mut in_out).unwrap(); // psk, e, es
    let mut message_a = in_out;
    
    //  from the responder (payjoin receiver)
    let mut responder = NoiseSession::init_session(false, b"", receiver_static, None, psk);
    //let mut message_a_received: Vec<u8> = Vec::with_capacity(message_a_size); // you would have to make a sized buffer in implementation
    responder.recv_message(&mut message_a).unwrap(); // es derived internally
    println!("message_a bytes:{:?}", message_a);
    let (_initiator_e, payload) = message_a.split_at_mut(DHLEN);
    let (payload, _mac) = payload.split_at_mut(payload.len() - MAC_LENGTH);
    println!("message_a decrypted:{:?}", String::from_utf8(payload.to_vec()));

    // Ready Message B <- e, ee
    //  from the responder (payjoin receiver)
    let payjoin_psbt = process_original_psbt(payload);
    let mut in_out: Vec<u8> = vec![0; DHLEN];
    in_out.append(&mut payjoin_psbt.to_vec());
    let message_b_size = DHLEN + payjoin_psbt.len() + MAC_LENGTH;
    in_out.resize(message_b_size, 0);
    responder.send_message(&mut in_out).unwrap(); // e, ee

    //  from the initiator (payjoin sender)
    let mut message_b = in_out;
    println!("message_b bytes:{:?}", message_b);
    initiator.recv_message(&mut message_b).unwrap(); // ee derived internally
    let (_responder_e, payload) = message_b.split_at_mut(DHLEN);
    let (payload, _mac) = payload.split_at_mut(payload.len() - MAC_LENGTH);
    println!("message_b decrypted:{:?}", String::from_utf8(payload.to_vec()));
  }

  fn process_original_psbt(_original_psbt: &[u8]) -> &[u8] {
    b"Payjoin PSBT"
  }
}