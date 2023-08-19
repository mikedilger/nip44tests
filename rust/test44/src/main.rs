use secp256k1::{PublicKey, SECP256K1, SecretKey, XOnlyPublicKey, Parity};
use secp256k1::ecdh::SharedSecret;
use std::error::Error;

fn hex_to_private(hex_private: &str) -> Result<SecretKey, Box<dyn Error>> {
    let vec: Vec<u8> = hex::decode(hex_private)?;
    Ok(SecretKey::from_slice(&vec)?)
}

fn hex_to_public(hex_public: &str) -> Result<XOnlyPublicKey, Box<dyn Error>> {
    let vec: Vec<u8> = hex::decode(hex_public)?;
    Ok(XOnlyPublicKey::from_slice(&vec)?)
}

fn shared_secret_nip44(hex_private: &str, hex_public: &str) -> Result<[u8; 32], Box<dyn Error>> {

    let privkey = hex_to_private(hex_private)?;
    let xonly_pubkey = hex_to_public(hex_public)?;
    let pubkey = PublicKey::from_x_only_public_key(xonly_pubkey, Parity::Even);

    let mut shared_secret = SharedSecret::new(&pubkey, &privkey);
    let bytes = shared_secret.secret_bytes();
    shared_secret.non_secure_erase();
    Ok(bytes)
}

fn main() -> Result<(), Box<dyn Error>> {
    let sec1_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let sec2_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    let sec2 = hex_to_private(sec2_hex)?;
    let (pub2, _parity) = sec2.x_only_public_key(&SECP256K1);
    let pub2_hex = hex::encode(pub2.serialize());

    let shared_secret = shared_secret_nip44(sec1_hex, &pub2_hex)?;
    println!("{}", hex::encode(shared_secret));
    Ok(())
}
