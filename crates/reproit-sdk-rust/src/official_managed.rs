use std::sync::Arc;

use reproit_core::{Error, ErrorCode, crypto::decode_base64url};

use crate::ManagedTlsClient;

const FIXTURE_CAPTURE_SIGNER_PUBLIC_KEYS: [&str; 5] = [
    "1238bj1eePRsVOlCHJedzcDZ0DmBthqGWrICsYCNzpA",
    "Pm6nrLpZVoxfNqy0GBb7FqsrJ6sTq9OLCSTKJpGtZZk",
    "IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI",
    "Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY",
    "p_bfr484uJuozmSbWU-R5NAf3Ff5yUk99DteUKmYc2c",
];

const OFFICIAL_MANAGED_HTTPS_ORIGIN: &str = "__REPROIT_OFFICIAL_MANAGED_HTTPS_ORIGIN_SENTINEL__";
const OFFICIAL_CAPTURE_GRANT_SIGNER_ID: &str =
    "__REPROIT_OFFICIAL_CAPTURE_GRANT_SIGNER_ID_SENTINEL__";
const OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY: &str =
    "__REPROIT_OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY_SENTINEL__";

pub(crate) struct OfficialManagedConfiguration {
    pub capture_signer_id: &'static str,
    pub capture_signer_public_key: [u8; 32],
    pub client: Arc<ManagedTlsClient>,
    pub managed_origin: &'static str,
}

pub(crate) fn official_managed_configuration() -> Result<OfficialManagedConfiguration, Error> {
    reject_unbound_release()?;
    validate_signer_id(OFFICIAL_CAPTURE_GRANT_SIGNER_ID)?;
    let capture_signer_public_key =
        decode_base64url::<32>(OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY)
            .map_err(|_| release_binding_invalid())?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&capture_signer_public_key)
        .map_err(|_| release_binding_invalid())?;
    if capture_signer_public_key.iter().all(|byte| *byte == 0)
        || FIXTURE_CAPTURE_SIGNER_PUBLIC_KEYS.contains(&OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY)
        || verifying_key.is_weak()
    {
        return Err(release_binding_invalid());
    }
    let client = Arc::new(ManagedTlsClient::official(OFFICIAL_MANAGED_HTTPS_ORIGIN)?);
    Ok(OfficialManagedConfiguration {
        capture_signer_id: OFFICIAL_CAPTURE_GRANT_SIGNER_ID,
        capture_signer_public_key,
        client,
        managed_origin: OFFICIAL_MANAGED_HTTPS_ORIGIN,
    })
}

fn reject_unbound_release() -> Result<(), Error> {
    if is_release_sentinel(OFFICIAL_MANAGED_HTTPS_ORIGIN)
        || is_release_sentinel(OFFICIAL_CAPTURE_GRANT_SIGNER_ID)
        || is_release_sentinel(OFFICIAL_CAPTURE_GRANT_SIGNER_PUBLIC_KEY)
    {
        return Err(Error::new(
            ErrorCode::ConfigConflict,
            "This Repro It SDK has no official managed release binding.",
        ));
    }
    Ok(())
}

fn is_release_sentinel(value: &str) -> bool {
    value.starts_with("__REPROIT_OFFICIAL_") && value.ends_with("_SENTINEL__")
}

fn validate_signer_id(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(release_binding_invalid());
    }
    Ok(())
}

fn release_binding_invalid() -> Error {
    Error::new(
        ErrorCode::ConfigConflict,
        "The official managed release binding is invalid.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_configuration_is_bound_or_fails_closed() {
        let result = official_managed_configuration();
        if is_release_sentinel(OFFICIAL_MANAGED_HTTPS_ORIGIN) {
            assert!(matches!(
                result,
                Err(error) if error.code == ErrorCode::ConfigConflict
            ));
        } else {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn signer_id_rejects_invalid_values() {
        for value in ["", "contains space", "contains/slash", &"a".repeat(257)] {
            assert!(validate_signer_id(value).is_err());
        }
    }
}
