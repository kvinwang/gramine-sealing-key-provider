use dcap_qvl::{
    collateral::get_collateral_from_pcs,
    quote::{Quote, Report},
    verify::verify,
};
use log::{debug, error, info, warn};
use p256::{ecdh::EphemeralSecret, PublicKey};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

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
    #[error("Public key error: {0}")]
    PublicKeyError(String),
    // Add #[allow(dead_code)] for variants we want to keep for future use
    #[allow(dead_code)]
    #[error("Quote verification failed")]
    QuoteVerificationError,
    #[error("DCAP error")]
    DcapError,
}

// Convert dcap_qvl::Error to ProviderError
impl From<dcap_qvl::Error> for ProviderError {
    fn from(_: dcap_qvl::Error) -> Self {
        ProviderError::DcapError
    }
}

#[derive(Debug)]
struct QuoteData {
    quote: Quote,
}

// Gramine interface functions
mod gramine {
    use super::*;

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
}

// Quote handling functions
mod quote_handler {
    use super::*;

    #[cfg(not(feature = "dev-mode"))]
    pub async fn verify_quote(quote_data: &[u8]) -> Result<(), ProviderError> {
        debug!("Verifying quote with DCAP");

        let collateral = get_collateral_from_pcs(quote_data, std::time::Duration::from_secs(10))
            .await
            .map_err(|_| ProviderError::QuoteVerificationError)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        verify(quote_data, &collateral, now).map_err(|_| ProviderError::QuoteVerificationError)?;

        info!("Quote verified successfully");
        Ok(())
    }

    pub fn parse_quote(data: Vec<u8>) -> Result<QuoteData, ProviderError> {
        let quote = Quote::parse(&data)
            .map_err(|_| ProviderError::QuoteParseError("Failed to parse quote".into()))?;

        Ok(QuoteData { quote })
    }

    pub fn verify_ppid_match(sgx_quote: &Quote, tdx_quote: &Quote) -> Result<(), ProviderError> {
        let sgx_ppid = &sgx_quote.header.user_data[..16];
        let tdx_ppid = &tdx_quote.header.user_data[..16];

        info!("Performing PPID verification");
        debug!("SGX Quote Header: {:?}", sgx_quote.header);
        debug!("TDX Quote Header: {:?}", tdx_quote.header);
        debug!("SGX PPID (hex): {}", hex::encode(sgx_ppid));
        debug!("TDX PPID (hex): {}", hex::encode(tdx_ppid));

        if sgx_ppid != tdx_ppid {
            error!("PPID mismatch between SGX and TDX quotes");
            error!("SGX PPID: {}", hex::encode(sgx_ppid));
            error!("TDX PPID: {}", hex::encode(tdx_ppid));
            return Err(ProviderError::PPIDMismatch);
        }

        info!("PPID match confirmed");
        Ok(())
    }

    pub fn extract_measurements(quote: &Quote) -> Result<Vec<u8>, ProviderError> {
        info!("Extracting measurements from quote");
        let mut measurements = Vec::new();

        match &quote.report {
            Report::TD10(report) => {
                debug!("Processing TD10 measurements");
                debug!("MRTD: {}", hex::encode(&report.mr_td));
                measurements.extend_from_slice(&report.mr_td);

                debug!("RTMR0: {}", hex::encode(&report.rt_mr0));
                debug!("RTMR1: {}", hex::encode(&report.rt_mr1));
                debug!("RTMR2: {}", hex::encode(&report.rt_mr2));
                debug!("RTMR3: {}", hex::encode(&report.rt_mr3));

                measurements.extend_from_slice(&report.rt_mr0);
                measurements.extend_from_slice(&report.rt_mr1);
                measurements.extend_from_slice(&report.rt_mr2);
                measurements.extend_from_slice(&report.rt_mr3);
            }
            Report::TD15(report) => {
                debug!("Processing TD15 measurements");
                debug!("MRTD: {}", hex::encode(&report.base.mr_td));
                measurements.extend_from_slice(&report.base.mr_td);

                debug!("RTMR0: {}", hex::encode(&report.base.rt_mr0));
                debug!("RTMR1: {}", hex::encode(&report.base.rt_mr1));
                debug!("RTMR2: {}", hex::encode(&report.base.rt_mr2));
                debug!("RTMR3: {}", hex::encode(&report.base.rt_mr3));

                measurements.extend_from_slice(&report.base.rt_mr0);
                measurements.extend_from_slice(&report.base.rt_mr1);
                measurements.extend_from_slice(&report.base.rt_mr2);
                measurements.extend_from_slice(&report.base.rt_mr3);
            }
            _ => {
                error!("Invalid report type for measurements");
                return Err(ProviderError::QuoteParseError("Not a TDX quote".into()));
            }
        }

        debug!("Total measurements length: {} bytes", measurements.len());
        debug!("Full measurements (hex): {}", hex::encode(&measurements));
        Ok(measurements)
    }

    pub fn get_report_data(quote: &Quote) -> Result<&[u8], ProviderError> {
        match &quote.report {
            Report::TD10(report) => Ok(&report.report_data),
            Report::TD15(report) => Ok(&report.base.report_data),
            _ => Err(ProviderError::QuoteParseError("Not a TDX quote".into())),
        }
    }
}

// Cryptographic operations
mod crypto {
    use super::*;

    pub fn derive_key(sealing_key: &[u8], measurements: &[u8]) -> Vec<u8> {
        info!("Deriving key from measurements");
        debug!("Sealing key length: {} bytes", sealing_key.len());
        debug!("Measurements length: {} bytes", measurements.len());
        debug!("Sealing key (hex): {}", hex::encode(sealing_key));
        debug!("Measurements (hex): {}", hex::encode(measurements));

        let mut hasher = Sha256::new();
        hasher.update(sealing_key);
        hasher.update(measurements);
        let derived = hasher.finalize().to_vec();

        debug!("Derived key length: {} bytes", derived.len());
        debug!("Derived key (hex): {}", hex::encode(&derived));
        derived
    }

    pub fn extract_public_key(report_data: &[u8]) -> Result<PublicKey, ProviderError> {
        debug!("Extracting public key from report data");
        if report_data.len() < 33 {
            return Err(ProviderError::PublicKeyError(
                "Report data too short".into(),
            ));
        }

        if report_data[0] != 0x02 && report_data[0] != 0x03 {
            return Err(ProviderError::PublicKeyError(
                "Invalid public key format".into(),
            ));
        }

        PublicKey::from_sec1_bytes(&report_data[..33])
            .map_err(|e| ProviderError::PublicKeyError(e.to_string()))
    }

    pub fn encrypt_key(
        derived_key: &[u8],
        public_key: &PublicKey,
    ) -> Result<Vec<u8>, ProviderError> {
        info!("Encrypting derived key using provided public key");
        debug!("Input key length: {} bytes", derived_key.len());
        debug!("Input key (hex): {}", hex::encode(derived_key));
        debug!("Public key: {:?}", public_key);

        // TODO: Implement actual public key encryption
        // For example, using RSA-OAEP or ECIES
        // For now, this is just a placeholder
        let encrypted = derived_key.to_vec(); // Replace with actual encryption

        debug!("Encrypted data length: {} bytes", encrypted.len());
        debug!("Encrypted data (hex): {}", hex::encode(&encrypted));
        Ok(encrypted)
    }
}

async fn process_quotes(tdx_quote_data: &[u8]) -> Result<Vec<u8>, ProviderError> {
    info!("Starting quote processing");
    debug!("Input quote length: {} bytes", tdx_quote_data.len());
    debug!("Input quote (hex): {}", hex::encode(tdx_quote_data));

    // 1. Verify TDX quote
    #[cfg(feature = "dev-mode")]
    {
        warn!("Development mode enabled");
        warn!("Skipping quote verification in dev mode");
    }

    #[cfg(not(feature = "dev-mode"))]
    {
        info!("Production mode - performing full quote verification");
        quote_handler::verify_quote(tdx_quote_data).await?;
    }

    // 2. Parse quotes
    let tdx_quote = quote_handler::parse_quote(tdx_quote_data.to_vec())?;
    let sgx_quote_data = gramine::get_local_quote()?;
    let sgx_quote = quote_handler::parse_quote(sgx_quote_data)?;

    // 3. Verify PPID match
    quote_handler::verify_ppid_match(&sgx_quote.quote, &tdx_quote.quote)?;

    // 4. Get measurements and derive key
    let sealing_key = gramine::get_sealing_key()?;
    let measurements = quote_handler::extract_measurements(&tdx_quote.quote)?;
    let derived_key = crypto::derive_key(&sealing_key, &measurements);

    // 5. Extract public key and encrypt response
    let report_data = quote_handler::get_report_data(&tdx_quote.quote)?;
    let public_key = crypto::extract_public_key(report_data)?;
    let encrypted_key = crypto::encrypt_key(&derived_key, &public_key)?;

    info!("Successfully processed quote and encrypted response");
    Ok(encrypted_key)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), ProviderError> {
    env_logger::init();
    info!("Starting Gramine Sealing Key Provider");

    #[cfg(feature = "dev-mode")]
    warn!("Running in DEVELOPMENT mode - security features are reduced");

    #[cfg(not(feature = "dev-mode"))]
    info!("Running in PRODUCTION mode - full security enabled");

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        error!("Incorrect number of arguments");
        return Err(ProviderError::UsageError(
            "Usage: gramine-sealing-key-provider <tdx-quote-path>".to_string(),
        ));
    }

    let tdx_quote_path = &args[1];
    debug!("Reading quote from: {}", tdx_quote_path);

    let tdx_quote_data = fs::read(tdx_quote_path).map_err(|e| {
        error!("Failed to read TDX quote file: {}", e);
        ProviderError::IOError(e)
    })?;

    match process_quotes(&tdx_quote_data).await {
        Ok(encrypted_key) => {
            println!("{}", hex::encode(&encrypted_key));
            Ok(())
        }
        Err(e) => {
            error!("Failed to process quotes: {}", e);
            Err(e)
        }
    }
}
