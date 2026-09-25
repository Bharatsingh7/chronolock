use chrono::{Duration, Utc};
use chronolock_lib::core::error::LockerError;
use chronolock_lib::core::locker::builder::build_locker;
use chronolock_lib::core::locker::extractor::{extract_locker, verify_and_read_metadata};
use std::fs::{self, File};
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_end_to_end_locker_creation_and_extraction() {
    let temp = TempDir::new().unwrap();
    let source_dir = temp.path().join("source");
    fs::create_dir_all(&source_dir).unwrap();

    // Create test files
    let file1_path = source_dir.join("hello.txt");
    fs::write(&file1_path, b"Hello, encrypted world!").unwrap();

    let sub_dir = source_dir.join("nested");
    fs::create_dir_all(&sub_dir).unwrap();
    let file2_path = sub_dir.join("data.bin");
    let test_data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
    fs::write(&file2_path, &test_data).unwrap();

    let locker_path = temp.path().join("test.locker");
    let password = b"SuperSecretPassword123!";
    let unlock_at = Utc::now() - Duration::seconds(10); // already unlockable

    // Build locker
    let build_res = build_locker(
        "Integration Test Locker",
        &[source_dir.clone()],
        &locker_path,
        password,
        unlock_at,
        None,
    )
    .expect("Failed to build locker");

    assert_eq!(build_res.file_count, 2);
    assert_eq!(build_res.dir_count, 2);
    assert!(locker_path.exists());

    // Verify metadata reading
    let (header, meta) = verify_and_read_metadata(&locker_path, password)
        .expect("Failed to read metadata with valid password");
    assert_eq!(meta.locker_name, "Integration Test Locker");
    assert_eq!(header.file_count, 2);

    // Extract locker
    let extract_dir = temp.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let now = Utc::now();
    extract_locker(&locker_path, &extract_dir, password, &now, None)
        .expect("Extraction failed");

    // Check extracted files
    let extracted_file1 = extract_dir.join("source").join("hello.txt");
    let extracted_file2 = extract_dir.join("source").join("nested").join("data.bin");

    assert_eq!(fs::read(&extracted_file1).unwrap(), b"Hello, encrypted world!");
    assert_eq!(fs::read(&extracted_file2).unwrap(), test_data);
}

#[test]
fn test_timer_enforcement_blocks_early_unlock() {
    let temp = TempDir::new().unwrap();
    let source_dir = temp.path().join("source");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("secret.txt"), b"Top Secret Information").unwrap();

    let locker_path = temp.path().join("timelocked.locker");
    let password = b"LockedPassword456!";
    // Locked for 1 hour in future
    let unlock_at = Utc::now() + Duration::hours(1);

    build_locker(
        "Time-locked Vault",
        &[source_dir],
        &locker_path,
        password,
        unlock_at,
        None,
    )
    .unwrap();

    let extract_dir = temp.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    // Attempting extraction now should fail with TimerNotExpired
    let current_time = Utc::now();
    let result = extract_locker(&locker_path, &extract_dir, password, &current_time, None);

    match result {
        Err(LockerError::TimerNotExpired(msg)) => {
            assert!(msg.contains("still locked"));
        }
        other => panic!("Expected TimerNotExpired, got: {:?}", other),
    }

    // Now simulate time passing beyond unlock_at
    let future_time = unlock_at + Duration::seconds(5);
    let success_result = extract_locker(&locker_path, &extract_dir, password, &future_time, None);
    assert!(success_result.is_ok(), "Extraction should succeed once timer expires");

    let extracted_content = fs::read(extract_dir.join("source").join("secret.txt")).unwrap();
    assert_eq!(extracted_content, b"Top Secret Information");
}

#[test]
fn test_wrong_password_fails() {
    let temp = TempDir::new().unwrap();
    let source_dir = temp.path().join("source");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("document.pdf"), b"%PDF-1.4 dummy content").unwrap();

    let locker_path = temp.path().join("auth_test.locker");
    let password = b"CorrectPassword789!";
    let unlock_at = Utc::now() - Duration::minutes(1);

    build_locker(
        "Auth Test",
        &[source_dir],
        &locker_path,
        password,
        unlock_at,
        None,
    )
    .unwrap();

    let extract_dir = temp.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let wrong_pw = b"WrongPassword000!";
    let result = extract_locker(&locker_path, &extract_dir, wrong_pw, &Utc::now(), None);

    match result {
        Err(LockerError::WrongPassword(_)) => {
            // Success: detected wrong password
        }
        other => panic!("Expected WrongPassword, got: {:?}", other),
    }
}

#[test]
fn test_tampered_locker_fails_integrity() {
    let temp = TempDir::new().unwrap();
    let source_dir = temp.path().join("source");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("safe.txt"), b"Integrity check content").unwrap();

    let locker_path = temp.path().join("tamper_test.locker");
    let password = b"IntegrityPassword!";
    let unlock_at = Utc::now() - Duration::minutes(1);

    build_locker(
        "Tamper Test",
        &[source_dir],
        &locker_path,
        password,
        unlock_at,
        None,
    )
    .unwrap();

    // Read bytes, modify a byte in the middle of data section, write back
    let mut bytes = fs::read(&locker_path).unwrap();
    let len = bytes.len();
    assert!(len > 200);
    // Flip bit in the payload
    bytes[len / 2] ^= 0x55;
    let mut perms = fs::metadata(&locker_path).unwrap().permissions();
    perms.set_readonly(false);
    let _ = fs::set_permissions(&locker_path, perms);
    fs::write(&locker_path, &bytes).unwrap();

    let extract_dir = temp.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    let result = extract_locker(&locker_path, &extract_dir, password, &Utc::now(), None);
    assert!(
        result.is_err(),
        "Extraction of tampered locker must fail integrity check"
    );
}

#[test]
fn test_streaming_multi_megabyte_file() {
    let temp = TempDir::new().unwrap();
    let source_dir = temp.path().join("source");
    fs::create_dir_all(&source_dir).unwrap();

    // Create a 2.5MB file (chunk size is 1MB, so this tests multi-chunk streaming)
    let file_path = source_dir.join("large.bin");
    let mut file = File::create(&file_path).unwrap();
    let chunk = vec![0xABu8; 1024 * 1024]; // 1MB chunk
    file.write_all(&chunk).unwrap();
    file.write_all(&chunk).unwrap();
    file.write_all(&chunk[0..512 * 1024]).unwrap(); // + 512KB
    drop(file);

    let locker_path = temp.path().join("large.locker");
    let password = b"StreamingChunkPass!";
    let unlock_at = Utc::now() - Duration::minutes(1);

    build_locker(
        "Streaming Test",
        &[source_dir],
        &locker_path,
        password,
        unlock_at,
        None,
    )
    .unwrap();

    let extract_dir = temp.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    extract_locker(&locker_path, &extract_dir, password, &Utc::now(), None)
        .expect("Failed to extract multi-chunk streaming locker");

    let extracted_size = fs::metadata(extract_dir.join("source").join("large.bin")).unwrap().len();
    assert_eq!(extracted_size, (2 * 1024 * 1024) + (512 * 1024));
}
