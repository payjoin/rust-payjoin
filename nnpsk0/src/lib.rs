/*
NNpsk0:
  -> psk, e
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
    use crate::types::{Keypair, Psk};

  #[test]
  fn e2e_noise_from_pj_sender() {    
    let receiver_static = Keypair::new_empty(); // security does not depend on long-term static keys in NNpsk0. The interface still requires a Keypair, but it is not used.
    // let receiver_static = Keypair::default(); // s from responder aka payjoin receiver
    // ...
    let psk = Psk::from_bytes(new_256bit_key()); // pre-shared from responder symmetric key. // todo can use 128 bit?
    // ...
    
    // Ready Message A -> psk, e
    
    //  from the initiator (payjoin sender)
    let original_psbt = b"Original PSBT";
    let sender_static = Keypair::new_empty(); // security does not depend on long-term static keys in NNpsk0. The interface still requires a Keypair, but it is not used.
    let mut initiator = NoiseSession::init_session(true, b"", sender_static, psk.clone());

    let mut in_out: Vec<u8> = vec![0; DHLEN];
    in_out.append(&mut original_psbt.to_vec());
    let message_a_size = DHLEN + original_psbt.len() + MAC_LENGTH;
    in_out.resize(message_a_size, 0);
    initiator.send_message(&mut in_out).unwrap(); // psk, e
    let mut message_a = in_out;
    
    //  from the responder (payjoin receiver)

    let mut responder = NoiseSession::init_session(false, b"", receiver_static, psk);
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

  fn new_256bit_key() -> [u8; 32] {
    use rand::RngCore;
    use rand::thread_rng;

    let mut rng = thread_rng();
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    key
  }
}