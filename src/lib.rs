use data_encoding::HEXLOWER;
use ring::{
    aead::{self},
    rand::{SecureRandom, SystemRandom},
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let plain_text = "This is Remon Ahammad";
        let ecnrypted = enc(plain_text.to_string()).unwrap();
        println!("Encrypted: {}", ecnrypted);
        let decrypted = dec(ecnrypted).unwrap();
        assert_eq!(decrypted, plain_text);
    }
}

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const AADSTR: &[u8; 5] = b"Remon";

pub fn enc(data: String) -> Result<String, Box<dyn std::error::Error>> {
    let key_bytes = key_bytes();

    let rng = SystemRandom::new();
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
        .map_err(|_| "Failed to create key")?;
    let sealing_key = aead::LessSafeKey::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    if let Err(_) = rng.fill(&mut nonce_bytes) {
        return Err("Failed to generate random nonce".into());
    }
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    let aad = aead::Aad::from(AADSTR);
    let mut in_out = data.as_bytes().to_vec();
    in_out.resize(in_out.len() + aead::AES_256_GCM.tag_len(), 0);
    sealing_key
        .seal_in_place_append_tag(nonce, aad, &mut in_out)
        .map_err(|_| "Encryption failed")?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&in_out);

    let hex = HEXLOWER.encode(&result);

    // println!("Encrypted (hex): {}", hex);

    Ok(hex)
}

pub fn dec(data: String) -> Result<String, Box<dyn std::error::Error>> {
    let key_bytes = key_bytes();
    let aad = aead::Aad::from(AADSTR);

    let opening_key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
            .map_err(|_| "Failed to create key")?,
    );

    let data_bytes = HEXLOWER.decode(data.as_bytes())?;
    let (nonce_bytes, in_out) = data_bytes.split_at(NONCE_LEN);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());

    let mut in_out = in_out.to_vec();
    let decrypted_data = opening_key
        .open_in_place(nonce, aad, &mut in_out)
        .map_err(|_| "Decryption failed")?;

    let r = std::str::from_utf8(decrypted_data)?
        .trim_end_matches('\0')
        .to_string();
    println!("Decrypted message: {}", r);

    Ok(r)
}

fn key_bytes() -> [u8; 32] {
    let name = b"Remon";
    let mut key_bytes = [0u8; KEY_LEN];
    for (i, &byte) in name.iter().enumerate() {
        if i < KEY_LEN {
            key_bytes[i] = byte;
        }
    }
    key_bytes
}
