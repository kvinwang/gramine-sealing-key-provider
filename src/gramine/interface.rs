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

pub fn get_local_quote() -> Result<Vec<u8>, ProviderError> {
    debug!("Reading local quote from Gramine");
    fs::read("/dev/attestation/quote").map_err(|e| {
        error!("Failed to read local quote: {}", e);
        ProviderError::IOError(e)
    })
}
