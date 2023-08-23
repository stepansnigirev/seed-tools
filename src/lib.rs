use wasm_bindgen::prelude::*;
use bip39::Mnemonic;
use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;
use bitcoin::base58;
use serde::{Serialize, Deserialize};

// double mnemonic generation

fn split_mnemonic(full: &str) -> (String, String) {
  let words: Vec<&str> = full.split_whitespace().collect();
  let first = words[..12].join(" ");
  let second = words[12..].join(" ");
  (first.into(), second.into())
}

#[wasm_bindgen]
pub fn double_mnemonic_from_entropy(entropystr: &str) -> Result<String, JsError> {
  let mut entropy = sha256::Hash::hash(entropystr.as_bytes()).to_byte_array();
  // bruteforce until we get two valid mnemonics
  let mut success = false;
  while !success {
    entropy = sha256::Hash::hash(&entropy).to_byte_array();
    let mnemonic = Mnemonic::from_entropy(&entropy)?;
    let full: String = format!("{}", mnemonic).into();
    let (mn1, mn2) = split_mnemonic(&full);
    success = match Mnemonic::parse(mn1) {
      Ok(_) => {
        match Mnemonic::parse(mn2) {
          Ok(_) => true,
          Err(_) => false,
        }
      },
      Err(_) => false,
    };
  }
  let mnemonic = Mnemonic::from_entropy(&entropy)?;
  Ok(format!("{}", mnemonic).into())
}

// slip132 converter

#[derive(Serialize, Deserialize)]
pub struct XYZKey{
  pub x: String, // canonical
  pub y: String, // nested segwit single key
  pub z: String, // native segwit single key
  pub Y: String, // nested segwit multisig
  pub Z: String, // native segwit multisig
}

fn replace_encode(payload: &[u8], version: &[u8]) -> Result<String, JsError> {
  if payload.len() != 78 {
    return Err(JsError::new("Invalid payload length!"));
  }
  let mut result: Vec<u8> = Vec::new();
  result.extend_from_slice(&version);
  result.extend_from_slice(&payload[4..]);
  Ok(base58::encode_check(&result))
}

#[wasm_bindgen]
pub fn slip132_convert(input: &str) -> Result<JsValue, JsError> {
  let payload = base58::decode_check(input)?;
  let res = if &input[1..4] == "pub" {
    XYZKey {
      x: replace_encode(&payload, &vec![0x04, 0x88, 0xb2, 0x1e])?,
      y: replace_encode(&payload, &vec![0x04, 0x9d, 0x7c, 0xb2])?,
      z: replace_encode(&payload, &vec![0x04, 0xb2, 0x47, 0x46])?,
      Y: replace_encode(&payload, &vec![0x02, 0x95, 0xb4, 0x3f])?,
      Z: replace_encode(&payload, &vec![0x02, 0xaa, 0x7e, 0xd3])?,
    }
  } else if &input[1..4] == "prv" {
    XYZKey {
      x: replace_encode(&payload, &vec![0x04, 0x88, 0xad, 0xe4])?,
      y: replace_encode(&payload, &vec![0x04, 0x9d, 0x78, 0x78])?,
      z: replace_encode(&payload, &vec![0x04, 0xb2, 0x43, 0x0c])?,
      Y: replace_encode(&payload, &vec![0x02, 0x95, 0xb0, 0x05])?,
      Z: replace_encode(&payload, &vec![0x02, 0xaa, 0x7a, 0x99])?,
    }
  } else {
    return Err(JsError::new("Should be ?pub or ?prv"));
  };
  Ok(serde_wasm_bindgen::to_value(&res)?)
}
