use dcap_qvl::quote::{Quote, Report};
use sha2::{Sha256, Digest};
use std::fs;
use std::env;
use thiserror::Error;
use log::{debug, info, error, warn};

#[derive(Error, Debug)]
enum ProviderError {
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Quote parsing error: {0}")]
    QuoteParseError(String),
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("PPID mismatch")]
    PPIDMismatch,
    #[error("Usage error: {0}")]
    UsageError(String),
}

// Get sealing key from Gramine
fn get_sealing_key() -> Result<Vec<u8>, ProviderError> {
    debug!("Attempting to read sealing key from /dev/attestation/keys/_sgx_mrenclave");
    let key = fs::read("/dev/attestation/keys/_sgx_mrenclave")
        .map_err(|e| {
            error!("Failed to read sealing key: {}", e);
            ProviderError::IOError(e)
        })?;
    debug!("Successfully read sealing key, length: {} bytes", key.len());
    Ok(key)
}

// Get local quote from Gramine
fn get_local_quote() -> Result<Vec<u8>, ProviderError> {
    debug!("Attempting to read local quote from /dev/attestation/quote");
    let quote = fs::read("/dev/attestation/quote")
        .map_err(|e| {
            error!("Failed to read local quote: {}", e);
            ProviderError::IOError(e)
        })?;
    debug!("Successfully read local quote, length: {} bytes", quote.len());
    Ok(quote)
}

// Extract measurements from TDX quote
fn extract_measurements(quote: &Quote) -> Vec<u8> {
    debug!("Extracting measurements from TDX quote");
    let mut measurements = Vec::new();
    
    match &quote.report {
        Report::TD10(report) => {
            debug!("Found TD10 report format");
            // Add MRTD
            measurements.extend_from_slice(&report.mr_td);
            debug!("Added MRTD measurement: {}", hex::encode(&report.mr_td));
            
            // Add RTMRs 0-3
            debug!("Adding RTMR measurements");
            measurements.extend_from_slice(&report.rt_mr0);
            measurements.extend_from_slice(&report.rt_mr1);
            measurements.extend_from_slice(&report.rt_mr2);
            measurements.extend_from_slice(&report.rt_mr3);
            debug!("RTMR0: {}", hex::encode(&report.rt_mr0));
            debug!("RTMR1: {}", hex::encode(&report.rt_mr1));
            debug!("RTMR2: {}", hex::encode(&report.rt_mr2));
            debug!("RTMR3: {}", hex::encode(&report.rt_mr3));
        },
        Report::TD15(report) => {
            debug!("Found TD15 report format");
            measurements.extend_from_slice(&report.base.mr_td);
            measurements.extend_from_slice(&report.base.rt_mr0);
            measurements.extend_from_slice(&report.base.rt_mr1);
            measurements.extend_from_slice(&report.base.rt_mr2);
            measurements.extend_from_slice(&report.base.rt_mr3);
        },
        _ => {
            warn!("Unexpected report type, not a TDX quote");
            return measurements;
        }
    }
    
    debug!("Total measurements length: {} bytes", measurements.len());
    measurements
}

// Derive key using sealing key and measurements
fn derive_key(sealing_key: &[u8], measurements: &[u8]) -> Vec<u8> {
    debug!("Deriving key using sealing key and measurements");
    debug!("Sealing key length: {} bytes", sealing_key.len());
    debug!("Measurements length: {} bytes", measurements.len());
    
    let mut hasher = Sha256::new();
    hasher.update(sealing_key);
    hasher.update(measurements);
    let derived = hasher.finalize().to_vec();
    
    debug!("Derived key length: {} bytes", derived.len());
    derived
}

fn process_quotes(tdx_quote_path: &str) -> Result<Vec<u8>, ProviderError> {
    info!("Starting quote processing");
    debug!("Reading quote from path: {}", tdx_quote_path);
    
    // 1. Get local quote and sealing key
    let sgx_quote_data = get_local_quote()?;
    info!("Successfully read local SGX quote");
    
    let sealing_key = get_sealing_key()?;
    info!("Successfully read sealing key");
    
    // 2. Read TDX quote from file
    let tdx_quote_data = fs::read(tdx_quote_path)
        .map_err(|e| {
            error!("Failed to read TDX quote from {}: {}", tdx_quote_path, e);
            ProviderError::IOError(e)
        })?;
    info!("Successfully read TDX quote from file");
    
    // 3. Parse quotes using dcap-qvl
    debug!("Parsing SGX quote");
    let sgx_quote = Quote::parse(&sgx_quote_data)
        .map_err(|e| {
            error!("Failed to parse SGX quote: {}", e);
            ProviderError::QuoteParseError(e.to_string())
        })?;
    
    debug!("Parsing TDX quote");
    let tdx_quote = Quote::parse(&tdx_quote_data)
        .map_err(|e| {
            error!("Failed to parse TDX quote: {}", e);
            ProviderError::QuoteParseError(e.to_string())
        })?;
    
    // 4. Extract and compare PPIDs from user_data (first 16 bytes)
    let sgx_ppid = &sgx_quote.header.user_data[..16];
    let tdx_ppid = &tdx_quote.header.user_data[..16];
    
    debug!("SGX PPID: {}", hex::encode(sgx_ppid));
    debug!("TDX PPID: {}", hex::encode(tdx_ppid));
    
    if sgx_ppid != tdx_ppid {
        error!("PPID mismatch between SGX and TDX quotes");
        return Err(ProviderError::PPIDMismatch);
    }
    info!("PPID match confirmed");
    
    // 5. Extract measurements and derive key
    let measurements = extract_measurements(&tdx_quote);
    info!("Successfully extracted measurements");
    
    let derived_key = derive_key(&sealing_key, &measurements);
    info!("Successfully derived key");
    
    Ok(derived_key)
}

fn main() -> Result<(), ProviderError> {
    // Initialize logger
    env_logger::init();
    info!("Starting Gramine Sealing Key Provider");
    
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        error!("Incorrect number of arguments");
        return Err(ProviderError::UsageError(
            "Usage: gramine-sealing-key-provider <tdx-quote-path>".to_string()
        ));
    }
    
    let tdx_quote_path = &args[1];
    debug!("Processing quote from path: {}", tdx_quote_path);
    
    match process_quotes(tdx_quote_path) {
        Ok(derived_key) => {
            let key_hex = hex::encode(&derived_key);
            info!("Successfully derived key");
            debug!("Derived key: {}", key_hex);
            println!("{}", key_hex);
            Ok(())
        }
        Err(e) => {
            error!("Failed to process quotes: {}", e);
            Err(e)
        }
    }
}
