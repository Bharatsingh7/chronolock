//! Locker Binary Format
//!
//! Implements reading and writing of the `.locker` file header.
//!
//! # Binary Layout (128 bytes fixed header)
//! ```text
//! Offset  Size   Field
//! 0       8      Magic bytes: "TLOCKER\0"
//! 8       2      Format version (u16 LE)
//! 10      2      Flags (u16 LE)
//! 12      4      Argon2 memory cost KiB (u32 LE)
//! 16      4      Argon2 time cost (u32 LE)
//! 20      4      Argon2 parallelism (u32 LE)
//! 24      4      Chunk size bytes (u32 LE)
//! 28      32     Salt
//! 60      12     Metadata nonce
//! 72      8      Metadata block length (u64 LE)
//! 80      8      Data section length (u64 LE)
//! 88      8      Total original size (u64 LE)
//! 96      4      File count (u32 LE)
//! 100     4      Directory count (u32 LE)
//! 104     12     Data nonce (12 bytes for streaming encryption)
//! 116     12     Reserved (zero-filled)
//! 128     ---    [Encrypted Metadata Block]
//! 128+M   ---    [Encrypted Data Chunks]
//! EOF-32  32     HMAC-SHA256 footer
//! ```

use std::io::{Read, Write};

use crate::core::crypto::kdf::Argon2Params;
use crate::core::error::LockerError;

pub const MAGIC_BYTES: &[u8; 8] = b"TLOCKER\0";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 128;
pub const HMAC_SIZE: usize = 32;

/// Flags
pub const FLAG_COMPRESSED: u16 = 0x0001;

/// The fixed-size locker file header.
#[derive(Debug, Clone)]
pub struct LockerHeader {
    pub version: u16,
    pub flags: u16,
    pub argon2_params: Argon2Params,
    pub chunk_size: u32,
    pub salt: [u8; 32],
    pub metadata_nonce: [u8; 12],
    pub metadata_length: u64,
    pub data_length: u64,
    pub total_original_size: u64,
    pub file_count: u32,
    pub dir_count: u32,
    pub data_nonce: [u8; 12],
}

impl LockerHeader {
    /// Write the header to a writer.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), LockerError> {
        let mut buf = [0u8; HEADER_SIZE];

        // Magic bytes
        buf[0..8].copy_from_slice(MAGIC_BYTES);
        // Version
        buf[8..10].copy_from_slice(&self.version.to_le_bytes());
        // Flags
        buf[10..12].copy_from_slice(&self.flags.to_le_bytes());
        // Argon2 params
        buf[12..16].copy_from_slice(&self.argon2_params.memory_cost_kib.to_le_bytes());
        buf[16..20].copy_from_slice(&self.argon2_params.time_cost.to_le_bytes());
        buf[20..24].copy_from_slice(&self.argon2_params.parallelism.to_le_bytes());
        // Chunk size
        buf[24..28].copy_from_slice(&self.chunk_size.to_le_bytes());
        // Salt
        buf[28..60].copy_from_slice(&self.salt);
        // Metadata nonce
        buf[60..72].copy_from_slice(&self.metadata_nonce);
        // Metadata length
        buf[72..80].copy_from_slice(&self.metadata_length.to_le_bytes());
        // Data length
        buf[80..88].copy_from_slice(&self.data_length.to_le_bytes());
        // Total original size
        buf[88..96].copy_from_slice(&self.total_original_size.to_le_bytes());
        // File count
        buf[96..100].copy_from_slice(&self.file_count.to_le_bytes());
        // Dir count
        buf[100..104].copy_from_slice(&self.dir_count.to_le_bytes());
        // Data nonce
        buf[104..116].copy_from_slice(&self.data_nonce);
        // Reserved (already zero)

        writer
            .write_all(&buf)
            .map_err(|e| LockerError::Io(format!("Write header: {}", e)))?;

        Ok(())
    }

    /// Read a header from a reader.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, LockerError> {
        let mut buf = [0u8; HEADER_SIZE];
        reader
            .read_exact(&mut buf)
            .map_err(|e| LockerError::Io(format!("Read header: {}", e)))?;

        // Validate magic bytes
        if &buf[0..8] != MAGIC_BYTES {
            return Err(LockerError::InvalidFormat(
                "Not a valid ChronoLock file (wrong magic bytes)".into(),
            ));
        }

        let version = u16::from_le_bytes([buf[8], buf[9]]);
        if version != FORMAT_VERSION {
            return Err(LockerError::InvalidFormat(format!(
                "Unsupported format version: {} (expected {})",
                version, FORMAT_VERSION
            )));
        }

        let flags = u16::from_le_bytes([buf[10], buf[11]]);

        let argon2_params = Argon2Params {
            memory_cost_kib: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            time_cost: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            parallelism: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
        };

        let chunk_size = u32::from_le_bytes(buf[24..28].try_into().unwrap());

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&buf[28..60]);

        let mut metadata_nonce = [0u8; 12];
        metadata_nonce.copy_from_slice(&buf[60..72]);

        let metadata_length = u64::from_le_bytes(buf[72..80].try_into().unwrap());
        let data_length = u64::from_le_bytes(buf[80..88].try_into().unwrap());
        let total_original_size = u64::from_le_bytes(buf[88..96].try_into().unwrap());
        let file_count = u32::from_le_bytes(buf[96..100].try_into().unwrap());
        let dir_count = u32::from_le_bytes(buf[100..104].try_into().unwrap());

        let mut data_nonce = [0u8; 12];
        data_nonce.copy_from_slice(&buf[104..116]);

        Ok(LockerHeader {
            version,
            flags,
            argon2_params,
            chunk_size,
            salt,
            metadata_nonce,
            metadata_length,
            data_length,
            total_original_size,
            file_count,
            dir_count,
            data_nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::kdf::{generate_nonce, generate_salt};
    use std::io::Cursor;

    fn sample_header() -> LockerHeader {
        LockerHeader {
            version: FORMAT_VERSION,
            flags: FLAG_COMPRESSED,
            argon2_params: Argon2Params::default(),
            chunk_size: 1024 * 1024,
            salt: generate_salt(),
            metadata_nonce: generate_nonce(),
            metadata_length: 1234,
            data_length: 567890,
            total_original_size: 500000,
            file_count: 42,
            dir_count: 5,
            data_nonce: generate_nonce(),
        }
    }

    #[test]
    fn test_header_round_trip() {
        let header = sample_header();
        let mut buf = Vec::new();
        header.write_to(&mut buf).unwrap();

        assert_eq!(buf.len(), HEADER_SIZE);

        let read_back = LockerHeader::read_from(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(read_back.version, header.version);
        assert_eq!(read_back.flags, header.flags);
        assert_eq!(read_back.chunk_size, header.chunk_size);
        assert_eq!(read_back.salt, header.salt);
        assert_eq!(read_back.metadata_nonce, header.metadata_nonce);
        assert_eq!(read_back.metadata_length, header.metadata_length);
        assert_eq!(read_back.data_length, header.data_length);
        assert_eq!(read_back.total_original_size, header.total_original_size);
        assert_eq!(read_back.file_count, header.file_count);
        assert_eq!(read_back.dir_count, header.dir_count);
        assert_eq!(read_back.data_nonce, header.data_nonce);
    }

    #[test]
    fn test_reject_wrong_magic() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(b"INVALID\0");
        let result = LockerHeader::read_from(&mut Cursor::new(&buf));
        assert!(matches!(result, Err(LockerError::InvalidFormat(_))));
    }

    #[test]
    fn test_reject_wrong_version() {
        let header = sample_header();
        let mut buf = Vec::new();
        header.write_to(&mut buf).unwrap();
        // Change version to 99
        buf[8] = 99;
        buf[9] = 0;
        let result = LockerHeader::read_from(&mut Cursor::new(&buf));
        assert!(matches!(result, Err(LockerError::InvalidFormat(_))));
    }

    #[test]
    fn test_reject_truncated_header() {
        let buf = vec![0u8; 64]; // Too short
        let result = LockerHeader::read_from(&mut Cursor::new(&buf));
        assert!(result.is_err());
    }
}
