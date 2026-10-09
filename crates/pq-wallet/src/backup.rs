use crate::{manifest::MAX_PLAINTEXT, Error};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

pub(crate) const HEADER_LEN: usize = 56;
pub(crate) const MAX_FILE: usize = HEADER_LEN + MAX_PLAINTEXT + 16;
const PREFIX: &[u8; 24] =
    b"TPQBACK\0\x01\x01\x01\x13\x00\x00\x01\x00\x03\x00\x00\x00\x04\x00\x00\x00";

fn password_check(password: &[u8]) -> Result<(), Error> {
    if !(1..=1024).contains(&password.len()) || std::str::from_utf8(password).is_err() {
        return Err(Error::Password);
    }
    Ok(())
}

pub(crate) fn key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    password_check(password)?;
    let parameters = Params::new(65_536, 3, 4, Some(32)).map_err(|_| Error::UnsupportedFormat)?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
    // Clear our Argon2 block allocation and output key on drop. This does not
    // cover the caller's password, backend/hash state or temporary copies.
    let mut memory = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(65_536)
        .map_err(|_| Error::Limits)?;
    memory.resize(65_536, Block::default());
    let mut key = Zeroizing::new([0; 32]);
    kdf.hash_password_into_with_memory(password, salt, key.as_mut(), memory.as_mut_slice())
        .map_err(|_| Error::Authentication)?;
    Ok(key)
}

pub(crate) fn encrypt(
    mut plaintext: Zeroizing<Vec<u8>>,
    password: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>, Error> {
    password_check(password)?;
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(Error::Limits);
    }
    let mut header = [0; HEADER_LEN];
    header[..24].copy_from_slice(PREFIX);
    rng.try_fill_bytes(&mut header[24..40])
        .map_err(|_| Error::Entropy)?;
    rng.try_fill_bytes(&mut header[40..52])
        .map_err(|_| Error::Entropy)?;
    let length = u32::try_from(plaintext.len() + 16).map_err(|_| Error::Limits)?;
    header[52..].copy_from_slice(&length.to_le_bytes());
    let key = key(password, &header[24..40])?;
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&header[40..52]), &header, &mut plaintext)
        .map_err(|_| Error::Authentication)?;
    let mut result = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
    result.extend(header);
    result.extend_from_slice(&plaintext);
    result.extend_from_slice(&tag);
    Ok(result)
}

pub(crate) fn decrypt(blob: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    decrypt_with(blob, password, key)
}

pub(crate) fn decrypt_with(
    blob: &[u8],
    password: &[u8],
    kdf: impl FnOnce(&[u8], &[u8]) -> Result<Zeroizing<[u8; 32]>, Error>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    // All attacker-controlled parameters and lengths are checked before the KDF.
    if blob.len() < HEADER_LEN {
        return Err(Error::Encoding);
    }
    if &blob[..24] != PREFIX {
        return Err(Error::UnsupportedFormat);
    }
    let length = u32::from_le_bytes(blob[52..56].try_into().map_err(|_| Error::Encoding)?) as usize;
    if !(16..=MAX_PLAINTEXT + 16).contains(&length) || blob.len() != HEADER_LEN + length {
        return Err(Error::Limits);
    }
    password_check(password)?;
    let key = kdf(password, &blob[24..40])?;
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let tag_start = blob.len() - 16;
    let mut plaintext = Zeroizing::new(blob[HEADER_LEN..tag_start].to_vec());
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&blob[40..52]),
            &blob[..HEADER_LEN],
            &mut plaintext,
            Tag::from_slice(&blob[tag_start..]),
        )
        .map_err(|_| Error::Authentication)?;
    Ok(plaintext)
}
