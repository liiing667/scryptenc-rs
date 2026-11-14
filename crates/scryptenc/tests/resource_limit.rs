// SPDX-FileCopyrightText: 2026 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(feature = "alloc")]
use scryptenc::decrypt_with_limit;
use scryptenc::{
    Decryptor, Encryptor, Error, HEADER_SIZE, Params, ResourceLimit, TAG_SIZE,
    scrypt::Params as ScryptParams,
};

const PASSPHRASE: &str = "passphrase";
const TEST_DATA_ENC: &[u8] = include_bytes!("data/data.txt.scrypt");

// The fixture uses N = 1024, r = 8 and p = 1.
const MEMORY_USAGE: u128 = 128 * 1024 * 8;
const OPERATION_COUNT: u128 = 4 * 1024 * 8;

#[test]
fn unlimited_limit_accepts_the_fixture() {
    let limit = ResourceLimit::new();
    assert!(Params::with_limit(TEST_DATA_ENC, limit).is_ok());
    assert!(Decryptor::with_limit(&TEST_DATA_ENC, PASSPHRASE, limit).is_ok());
}

#[test]
fn params_accepts_data_within_the_limits() {
    let limit = ResourceLimit::new()
        .with_max_memory(MEMORY_USAGE)
        .with_max_ops(OPERATION_COUNT)
        .with_max_ciphertext_size(TEST_DATA_ENC.len() as u128);
    assert!(Params::with_limit(TEST_DATA_ENC, limit).is_ok());
}

#[test]
fn params_rejects_data_exceeding_the_memory_limit() {
    let limit = ResourceLimit::new().with_max_memory(MEMORY_USAGE - 1);
    let err = Params::with_limit(TEST_DATA_ENC, limit).unwrap_err();
    assert_eq!(err, Error::MemoryLimitExceeded);
}

#[test]
fn params_rejects_data_exceeding_the_operation_limit() {
    let limit = ResourceLimit::new().with_max_ops(OPERATION_COUNT - 1);
    let err = Params::with_limit(TEST_DATA_ENC, limit).unwrap_err();
    assert_eq!(err, Error::OperationLimitExceeded);
}

#[test]
fn params_rejects_data_exceeding_the_ciphertext_size_limit() {
    let limit = ResourceLimit::new().with_max_ciphertext_size(TEST_DATA_ENC.len() as u128 - 1);
    let err = Params::with_limit(TEST_DATA_ENC, limit).unwrap_err();
    assert_eq!(err, Error::CiphertextTooLarge);
}

#[test]
fn decryptor_accepts_data_within_the_limits() {
    let limit = ResourceLimit::new()
        .with_max_memory(MEMORY_USAGE)
        .with_max_ops(OPERATION_COUNT)
        .with_max_ciphertext_size(TEST_DATA_ENC.len() as u128);
    assert!(Decryptor::with_limit(&TEST_DATA_ENC, PASSPHRASE, limit).is_ok());
}

#[test]
fn decryptor_rejects_data_exceeding_the_memory_limit() {
    let limit = ResourceLimit::new().with_max_memory(MEMORY_USAGE - 1);
    let err = Decryptor::with_limit(&TEST_DATA_ENC, PASSPHRASE, limit).unwrap_err();
    assert_eq!(err, Error::MemoryLimitExceeded);
}

#[test]
fn decryptor_rejects_data_exceeding_the_operation_limit() {
    let limit = ResourceLimit::new().with_max_ops(OPERATION_COUNT - 1);
    let err = Decryptor::with_limit(&TEST_DATA_ENC, PASSPHRASE, limit).unwrap_err();
    assert_eq!(err, Error::OperationLimitExceeded);
}

#[test]
fn decryptor_rejects_data_exceeding_the_ciphertext_size_limit() {
    let limit = ResourceLimit::new().with_max_ciphertext_size(TEST_DATA_ENC.len() as u128 - 1);
    let err = Decryptor::with_limit(&TEST_DATA_ENC, PASSPHRASE, limit).unwrap_err();
    assert_eq!(err, Error::CiphertextTooLarge);
}

#[test]
fn limits_are_enforced_before_the_header_checksum() {
    let mut data = TEST_DATA_ENC.to_vec();
    let checksum: &mut [u8] = &mut data[48..64];
    checksum.reverse();

    let limit = ResourceLimit::new().with_max_memory(MEMORY_USAGE - 1);
    let err = Decryptor::with_limit(&data, PASSPHRASE, limit).unwrap_err();
    assert_eq!(err, Error::MemoryLimitExceeded);
}

#[test]
fn invalid_header_is_still_rejected_with_a_limit() {
    let data = [u8::default(); HEADER_SIZE + TAG_SIZE];
    let limit = ResourceLimit::new().with_max_ciphertext_size(u128::MAX);
    let err = Decryptor::with_limit(&data, PASSPHRASE, limit).unwrap_err();
    assert_eq!(err, Error::InvalidMagicNumber);
}

#[cfg(feature = "alloc")]
#[test]
fn convenience_function_uses_the_limit() {
    let limit = ResourceLimit::new().with_max_ciphertext_size(TEST_DATA_ENC.len() as u128 - 1);
    let err = decrypt_with_limit(TEST_DATA_ENC, PASSPHRASE, limit).unwrap_err();
    assert_eq!(err, Error::CiphertextTooLarge);
}

#[cfg(feature = "alloc")]
#[test]
fn large_legal_blob_succeeds_with_a_generous_limit() {
    let plaintext = vec![u8::default(); 1024 * 1024];
    let params = ScryptParams::new(10, 8, 1, ScryptParams::RECOMMENDED_LEN).unwrap();
    let ciphertext = Encryptor::with_params(&plaintext, PASSPHRASE, params).encrypt_to_vec();
    assert_eq!(ciphertext.len(), plaintext.len() + HEADER_SIZE + TAG_SIZE);

    let limit = ResourceLimit::new()
        .with_max_memory(MEMORY_USAGE)
        .with_max_ops(OPERATION_COUNT)
        .with_max_ciphertext_size(ciphertext.len() as u128);
    let decrypted = decrypt_with_limit(&ciphertext, PASSPHRASE, limit).unwrap();
    assert_eq!(decrypted, plaintext);
}
