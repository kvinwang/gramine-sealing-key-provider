use crate::error::ProviderError;
use log::{debug, info};
use p256::PublicKey;
use sha2::{Digest, Sha256};

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
    // This code is checking for SEC1 formatted compressed public keys
    // SEC1 format for compressed public keys:
    // - First byte (0x02 or 0x03) indicates the sign of the y-coordinate
    // - Followed by the x-coordinate (32 bytes for P-256)
    // Total length: 33 bytes

    // Check minimum length requirement
    if report_data.len() < 33 {
        return Err(ProviderError::PublicKeyError(
            "Report data too short".into(),
        ));
    }

    // Check if it's a valid compressed public key format
    // 0x02: positive y-coordinate
    // 0x03: negative y-coordinate
    if report_data[0] != 0x02 && report_data[0] != 0x03 {
        return Err(ProviderError::PublicKeyError(
            "Invalid public key format".into(),
        ));
    }
    
    // Parse the first 33 bytes as a SEC1-encoded public key
    PublicKey::from_sec1_bytes(&report_data[..33])
        .map_err(|e| ProviderError::PublicKeyError(e.to_string()))
}

pub fn encrypt_key(derived_key: &[u8], public_key: &PublicKey) -> Result<Vec<u8>, ProviderError> {
    info!("Encrypting derived key using provided public key");
    debug!("Input key length: {} bytes", derived_key.len());
    debug!("Input key (hex): {}", hex::encode(derived_key));
    debug!("Public key: {:?}", public_key);

    // TODO: Implement actual public key encryption
    let encrypted = derived_key.to_vec();

    debug!("Encrypted data length: {} bytes", encrypted.len());
    Ok(encrypted)
}
