//! Key Derivation Module
//!
//! Implements password-based key derivation using Argon2id and domain-separated
//! key expansion using HKDF-SHA256. This ensures that a single user password
//! produces three independent cryptographic keys:
//!
//! - Data Encryption Key (DEK): Used for encrypting file data
//! - Metadata Key: Used for encrypting locker metadata
//! - Authentication Key: Used for HMAC integrity verification
//!
//! Security properties:
//! - Argon2id provides resistance against both side-channel and GPU brute-force attacks
//! - HKDF domain separation ensures compromise of one key doesn't reveal others
//! - All keys are 256-bit (32 bytes)
//! - Salts are 32 bytes, cryptographically random, unique per locker

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::error::LockerError;

/// Default Argon2id parameters
/// These are tuned for ~1-2 second derivation on modern hardware
pub const DEFAULT_MEMORY_COST_KIB: u32 = 256 * 1024; // 256 MiB
pub const DEFAULT_TIME_COST: u32 = 4;
pub const DEFAULT_PARALLELISM: u32 = 2;
pub const SALT_LENGTH: usize = 32;
pub const KEY_LENGTH: usize = 32;

/// Argon2 parameters stored in the locker header
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost_kib: DEFAULT_MEMORY_COST_KIB,
            time_cost: DEFAULT_TIME_COST,
            parallelism: DEFAULT_PARALLELISM,
        }
    }
}

/// The set of derived keys from a single master key.
/// All keys are zeroized on drop for security.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeys {
    /// Key for encrypting/decrypting file data (AES-256-GCM STREAM)
    pub data_encryption_key: [u8; KEY_LENGTH],
    /// Key for encrypting/decrypting locker metadata
    pub metadata_key: [u8; KEY_LENGTH],
    /// Key for HMAC-SHA256 integrity verification
    pub authentication_key: [u8; KEY_LENGTH],
}

/// Generate a cryptographically secure random salt.
pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a cryptographically secure random nonce (12 bytes for AES-GCM).
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Derive a master key from a password and salt using Argon2id.
///
/// # Arguments
/// * `password` - The user's password as bytes
/// * `salt` - A 32-byte random salt (unique per locker)
/// * `params` - Argon2id cost parameters
///
/// # Returns
/// A 32-byte master key. This key should NOT be used directly for encryption;
/// use `expand_keys` to derive domain-separated subkeys.
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8; SALT_LENGTH],
    params: &Argon2Params,
) -> Result<[u8; KEY_LENGTH], LockerError> {
    let argon2_params = Params::new(
        params.memory_cost_kib,
        params.time_cost,
        params.parallelism,
        Some(KEY_LENGTH),
    )
    .map_err(|e| LockerError::KeyDerivation(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut master_key = [0u8; KEY_LENGTH];
    argon2
        .hash_password_into(password, salt, &mut master_key)
        .map_err(|e| LockerError::KeyDerivation(format!("Argon2id derivation failed: {}", e)))?;

    Ok(master_key)
}

/// Expand a master key into domain-separated subkeys using HKDF-SHA256.
///
/// This produces three independent keys from the master key:
/// - Data Encryption Key (info: "datalocker-dek-v1")
/// - Metadata Key (info: "datalocker-mdk-v1")
/// - Authentication Key (info: "datalocker-auk-v1")
///
/// # Security
/// Each key is derived with a unique info string, ensuring that knowing one
/// derived key reveals nothing about the others (assuming HKDF security).
pub fn expand_keys(master_key: &[u8; KEY_LENGTH]) -> Result<DerivedKeys, LockerError> {
    let hk = Hkdf::<Sha256>::new(None, master_key);

    let mut data_encryption_key = [0u8; KEY_LENGTH];
    let mut metadata_key = [0u8; KEY_LENGTH];
    let mut authentication_key = [0u8; KEY_LENGTH];

    hk.expand(b"datalocker-dek-v1", &mut data_encryption_key)
        .map_err(|_| LockerError::KeyDerivation("HKDF expansion failed for DEK".into()))?;

    hk.expand(b"datalocker-mdk-v1", &mut metadata_key)
        .map_err(|_| {
            LockerError::KeyDerivation("HKDF expansion failed for metadata key".into())
        })?;

    hk.expand(b"datalocker-auk-v1", &mut authentication_key)
        .map_err(|_| LockerError::KeyDerivation("HKDF expansion failed for auth key".into()))?;

    Ok(DerivedKeys {
        data_encryption_key,
        metadata_key,
        authentication_key,
    })
}

/// Derive all keys from password + salt in one call.
/// Convenience function combining `derive_master_key` and `expand_keys`.
pub fn derive_keys(
    password: &[u8],
    salt: &[u8; SALT_LENGTH],
    params: &Argon2Params,
) -> Result<DerivedKeys, LockerError> {
    let mut master_key = derive_master_key(password, salt, params)?;
    let keys = expand_keys(&master_key)?;
    master_key.zeroize(); // Clear master key from memory
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_generation_uniqueness() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_ne!(salt1, salt2, "Two salts should never be identical");
    }

    #[test]
    fn test_nonce_generation_uniqueness() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let password = b"test-password-123!";
        let salt = [42u8; SALT_LENGTH];
        // Use reduced params for fast testing
        let params = Argon2Params {
            memory_cost_kib: 1024, // 1 MiB for tests
            time_cost: 1,
            parallelism: 1,
        };

        let key1 = derive_master_key(password, &salt, &params).unwrap();
        let key2 = derive_master_key(password, &salt, &params).unwrap();
        assert_eq!(key1, key2, "Same password + salt must produce same key");
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = [42u8; SALT_LENGTH];
        let params = Argon2Params {
            memory_cost_kib: 1024,
            time_cost: 1,
            parallelism: 1,
        };

        let key1 = derive_master_key(b"password1", &salt, &params).unwrap();
        let key2 = derive_master_key(b"password2", &salt, &params).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_salts_different_keys() {
        let params = Argon2Params {
            memory_cost_kib: 1024,
            time_cost: 1,
            parallelism: 1,
        };

        let key1 = derive_master_key(b"password", &[1u8; SALT_LENGTH], &params).unwrap();
        let key2 = derive_master_key(b"password", &[2u8; SALT_LENGTH], &params).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_key_expansion_produces_unique_keys() {
        let master_key = [99u8; KEY_LENGTH];
        let keys = expand_keys(&master_key).unwrap();

        assert_ne!(keys.data_encryption_key, keys.metadata_key);
        assert_ne!(keys.data_encryption_key, keys.authentication_key);
        assert_ne!(keys.metadata_key, keys.authentication_key);
    }

    #[test]
    fn test_key_expansion_deterministic() {
        let master_key = [99u8; KEY_LENGTH];
        let keys1 = expand_keys(&master_key).unwrap();
        let keys2 = expand_keys(&master_key).unwrap();

        assert_eq!(keys1.data_encryption_key, keys2.data_encryption_key);
        assert_eq!(keys1.metadata_key, keys2.metadata_key);
        assert_eq!(keys1.authentication_key, keys2.authentication_key);
    }

    #[test]
    fn test_full_derive_keys_pipeline() {
        let password = b"my-secure-password";
        let salt = generate_salt();
        let params = Argon2Params {
            memory_cost_kib: 1024,
            time_cost: 1,
            parallelism: 1,
        };

        let keys = derive_keys(password, &salt, &params).unwrap();
        assert_ne!(keys.data_encryption_key, [0u8; KEY_LENGTH]);
        assert_ne!(keys.metadata_key, [0u8; KEY_LENGTH]);
        assert_ne!(keys.authentication_key, [0u8; KEY_LENGTH]);
    }
}
