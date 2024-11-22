use crate::error::ProviderError;
use log::{debug, error};
use std::fs;

pub fn get_sealing_key() -> Result<Vec<u8>, ProviderError> {
    debug!("Reading sealing key from Gramine");
    fs::read("/dev/attestation/keys/_sgx_mrenclave").map_err(|e| {
        error!("Failed to read sealing key: {}", e);
        ProviderError::IOError(e)
    })
}

pub fn set_user_report_data(data: &[u8]) -> Result<(), ProviderError> {
    debug!("Setting user report data: {} bytes", data.len());
    if data.len() > 64 {
        return Err(ProviderError::CryptoError(
            "User report data must not exceed 64 bytes".into(),
        ));
    }

    // Pad data to 64 bytes if necessary
    let mut padded_data = vec![0u8; 64];
    padded_data[..data.len()].copy_from_slice(data);

    fs::write("/dev/attestation/user_report_data", &padded_data).map_err(|e| {
        error!("Failed to write user report data: {}", e);
        ProviderError::IOError(e)
    })
}

pub fn get_quote_with_data(user_data: &[u8]) -> Result<Vec<u8>, ProviderError> {
    debug!("Setting user report data and getting quote");
    
    // First set the user report data
    set_user_report_data(user_data)?;
    
    // Then get the quote
    fs::read("/dev/attestation/quote").map_err(|e| {
        error!("Failed to read quote: {}", e);
        ProviderError::IOError(e)
    })
}
