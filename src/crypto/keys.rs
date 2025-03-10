use crate::error::ProviderError;
use log::{debug, info};
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::box_::{self, PublicKey};

// Initialize sodium at program start
pub fn init_sodium() -> Result<(), ProviderError> {
    sodiumoxide::init().map_err(|_| ProviderError::CryptoError("Failed to initialize sodium".into()))
}

pub fn derive_key(sealing_key: &[u8], measurements: &[u8]) -> Vec<u8> {
    info!("Deriving key from measurements");
    debug!("Sealing key length: {} bytes", sealing_key.len());
    debug!("Measurements length: {} bytes", measurements.len());

    let mut hasher = Sha256::new();
    hasher.update(sealing_key);
    hasher.update(measurements);
    let derived = hasher.finalize().to_vec();

    debug!("Derived key length: {} bytes", derived.len());
    derived
}

pub fn extract_public_key(report_data: &[u8]) -> Result<PublicKey, ProviderError> {
    debug!("Extracting public key from report data");
    
    if report_data.len() < box_::PUBLICKEYBYTES {
        return Err(ProviderError::PublicKeyError(format!(
            "Report data too short. Expected {} bytes", box_::PUBLICKEYBYTES
        )));
    }

    PublicKey::from_slice(&report_data[..box_::PUBLICKEYBYTES])
        .ok_or_else(|| ProviderError::PublicKeyError("Invalid public key format".into()))
}

pub fn encrypt_key(derived_key: &[u8], public_key: &PublicKey) -> Result<Vec<u8>, ProviderError> {
    info!("Encrypting derived key using sealed box");
    debug!("Input key length: {} bytes", derived_key.len());
    
    let encrypted = sealedbox::seal(derived_key, public_key);

    debug!("Encrypted data length: {} bytes", encrypted.len());
    debug!("Encrypted data (hex): {}", hex::encode(&encrypted));
    
    Ok(encrypted)
}
