use wasm_bindgen::prelude::*;
use bip39::Mnemonic;
use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;

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
