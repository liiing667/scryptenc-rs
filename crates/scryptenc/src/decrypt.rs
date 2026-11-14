// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decrypts from the scrypt encrypted data format.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use aes::cipher::{KeyIvInit, StreamCipher, array::Array};
use hmac::{KeyInit, Mac};

use crate::{
    Aes256Ctr128BE, Error, HEADER_SIZE, HmacSha256, HmacSha256Key, HmacSha256Output, ResourceLimit,
    Result, TAG_SIZE,
    format::{DerivedKey, Header},
};

/// Decryptor for the scrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Decryptor<'c> {
    header: Header,
    dk: DerivedKey,
    ciphertext: &'c [u8],
    mac: HmacSha256Output,
}

impl<'c> Decryptor<'c> {
    #[expect(clippy::missing_panics_doc)]
    /// Creates a new `Decryptor`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following are true:
    ///
    /// - `ciphertext` is shorter than 128 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unrecognized scrypt version number.
    /// - The scrypt parameters are invalid.
    /// - The checksum of the header mismatch.
    /// - The MAC (authentication tag) of the header is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use scryptenc::Decryptor;
    ///
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// ```
    pub fn new(ciphertext: &'c impl AsRef<[u8]>, passphrase: impl AsRef<[u8]>) -> Result<Self> {
        let inner = |ciphertext: &'c [u8], passphrase: &[u8]| -> Result<Self> {
            let mut header = Header::parse(ciphertext)?;
            header.verify_checksum(&ciphertext[48..64])?;

            // The derived key size is 64 bytes. The first 256 bits are for
            // AES-256-CTR key, and the last 256 bits are for
            // HMAC-SHA-256 key.
            let mut dk = [u8::default(); DerivedKey::SIZE];
            scrypt::scrypt(passphrase, &header.salt(), &header.params().into(), &mut dk).unwrap();
            let dk = DerivedKey::new(dk);

            header.verify_mac(&dk.mac(), ciphertext[64..HEADER_SIZE].try_into().unwrap())?;
            let (ciphertext, mac) =
                ciphertext[HEADER_SIZE..].split_at(ciphertext.len() - HEADER_SIZE - TAG_SIZE);
            let mac = HmacSha256Output::try_from(mac).unwrap();
            Ok(Self {
                header,
                dk,
                ciphertext,
                mac,
            })
        };
        inner(ciphertext.as_ref(), passphrase.as_ref())
    }

    /// Creates a new `Decryptor`, rejecting `ciphertext` if it does not comply
    /// with the resource `limit`.
    ///
    /// The length of `ciphertext` and the `N`/`r`/`p` parameters stored in its
    /// header are checked against `limit` before the scrypt KDF is invoked, so
    /// an excessive amount of memory or CPU time is never spent on
    /// unauthenticated data.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following are true:
    ///
    /// - `ciphertext` is shorter than 128 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unrecognized scrypt version number.
    /// - The scrypt parameters are invalid.
    /// - The length of `ciphertext` exceeds the limit.
    /// - The memory required by the scrypt parameters exceeds the limit.
    /// - The CPU time required by the scrypt parameters exceeds the limit.
    /// - The checksum of the header mismatch.
    /// - The MAC (authentication tag) of the header is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use scryptenc::{Decryptor, ResourceLimit};
    ///
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    /// let passphrase = "passphrase";
    ///
    /// let limit = ResourceLimit::new().with_max_memory(64 * 1024 * 1024);
    /// let cipher = Decryptor::with_limit(&ciphertext, passphrase, limit).unwrap();
    /// ```
    #[expect(clippy::missing_panics_doc)]
    pub fn with_limit(
        ciphertext: &'c impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        limit: ResourceLimit,
    ) -> Result<Self> {
        let inner =
            |ciphertext: &'c [u8], passphrase: &[u8], limit: ResourceLimit| -> Result<Self> {
                limit.check_ciphertext_size(ciphertext.len())?;

                let mut header = Header::parse(ciphertext)?;
                limit.check_params(header.params())?;
                header.verify_checksum(&ciphertext[48..64])?;

                // The derived key size is 64 bytes. The first 256 bits are for
                // AES-256-CTR key, and the last 256 bits are for
                // HMAC-SHA-256 key.
                let mut dk = [u8::default(); DerivedKey::SIZE];
                scrypt::scrypt(passphrase, &header.salt(), &header.params().into(), &mut dk)
                    .unwrap();
                let dk = DerivedKey::new(dk);

                header.verify_mac(&dk.mac(), ciphertext[64..HEADER_SIZE].try_into().unwrap())?;
                let (ciphertext, mac) =
                    ciphertext[HEADER_SIZE..].split_at(ciphertext.len() - HEADER_SIZE - TAG_SIZE);
                let mac = HmacSha256Output::try_from(mac).unwrap();
                Ok(Self {
                    header,
                    dk,
                    ciphertext,
                    mac,
                })
            };
        inner(ciphertext.as_ref(), passphrase.as_ref(), limit)
    }

    /// Decrypts the ciphertext into `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if the MAC (authentication tag) of the scrypt encrypted
    /// data format is invalid.
    ///
    /// # Panics
    ///
    /// Panics if any of the following are true:
    ///
    /// - `buf` and the decrypted data have different lengths.
    /// - The end of the keystream will be reached with the given data length.
    ///
    /// # Examples
    ///
    /// ```
    /// use scryptenc::Decryptor;
    ///
    /// let data = b"Hello, world!\n";
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// let mut buf = [u8::default(); 14];
    /// cipher.decrypt(&mut buf).unwrap();
    /// assert_eq!(buf, *data);
    /// ```
    pub fn decrypt<B: AsMut<[u8]> + ?Sized>(self, buf: &mut B) -> Result<()> {
        let inner = |decryptor: Self, buf: &mut [u8]| -> Result<()> {
            fn verify_mac(data: &[u8], key: &HmacSha256Key, tag: &HmacSha256Output) -> Result<()> {
                let mut mac = HmacSha256::new_from_slice(key).unwrap();
                mac.update(data);
                mac.verify(tag).map_err(Error::InvalidMac)
            }

            buf.copy_from_slice(decryptor.ciphertext);

            let mut cipher = Aes256Ctr128BE::new(&decryptor.dk.encrypt(), &Array::default());
            cipher.apply_keystream(buf);
            let data = [&decryptor.header.as_bytes(), decryptor.ciphertext].concat();
            verify_mac(&data, &decryptor.dk.mac(), &decryptor.mac)
        };
        inner(self, buf.as_mut())
    }

    /// Decrypts the ciphertext and into a newly allocated [`Vec`].
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if the MAC (authentication tag) of the scrypt encrypted
    /// data format is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use scryptenc::Decryptor;
    ///
    /// let data = b"Hello, world!\n";
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// let plaintext = cipher.decrypt_to_vec().unwrap();
    /// assert_eq!(plaintext, data);
    /// ```
    #[cfg(feature = "alloc")]
    pub fn decrypt_to_vec(self) -> Result<Vec<u8>> {
        let mut buf = vec![u8::default(); self.out_len()];
        self.decrypt(&mut buf)?;
        Ok(buf)
    }

    /// Returns the number of output bytes of the decrypted data.
    ///
    /// # Examples
    ///
    /// ```
    /// use scryptenc::Decryptor;
    ///
    /// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// assert_eq!(cipher.out_len(), 14);
    /// ```
    #[must_use]
    pub const fn out_len(&self) -> usize {
        self.ciphertext.len()
    }
}

/// Decrypts `ciphertext` and into a newly allocated [`Vec`].
///
/// This is a convenience function for using [`Decryptor::new`] and
/// [`Decryptor::decrypt_to_vec`].
///
/// # Errors
///
/// Returns [`Err`] if any of the following are true:
///
/// - `ciphertext` is shorter than 128 bytes.
/// - The magic number is invalid.
/// - The version number is the unrecognized scrypt version number.
/// - The scrypt parameters are invalid.
/// - The checksum of the header mismatch.
/// - The MAC (authentication tag) of the header is invalid.
/// - The MAC (authentication tag) of the scrypt encrypted data format is
///   invalid.
///
/// # Examples
///
/// ```
/// let data = b"Hello, world!\n";
/// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
/// let passphrase = "passphrase";
///
/// let plaintext = scryptenc::decrypt(ciphertext, passphrase).unwrap();
/// assert_eq!(plaintext, data);
/// ```
#[cfg(feature = "alloc")]
pub fn decrypt(ciphertext: impl AsRef<[u8]>, passphrase: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    Decryptor::new(&ciphertext, passphrase).and_then(Decryptor::decrypt_to_vec)
}

/// Decrypts `ciphertext` and into a newly allocated [`Vec`], rejecting it if it
/// does not comply with the resource `limit`.
///
/// This is a convenience function for using [`Decryptor::with_limit`] and
/// [`Decryptor::decrypt_to_vec`].
///
/// # Errors
///
/// Returns [`Err`] if any of the following are true:
///
/// - `ciphertext` is shorter than 128 bytes.
/// - The magic number is invalid.
/// - The version number is the unrecognized scrypt version number.
/// - The scrypt parameters are invalid.
/// - The length of `ciphertext` exceeds the limit.
/// - The memory required by the scrypt parameters exceeds the limit.
/// - The CPU time required by the scrypt parameters exceeds the limit.
/// - The checksum of the header mismatch.
/// - The MAC (authentication tag) of the header is invalid.
/// - The MAC (authentication tag) of the scrypt encrypted data format is
///   invalid.
///
/// # Examples
///
/// ```
/// use scryptenc::ResourceLimit;
///
/// let data = b"Hello, world!\n";
/// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
/// let passphrase = "passphrase";
///
/// let limit = ResourceLimit::new().with_max_ciphertext_size(1024);
/// let plaintext =
///     scryptenc::decrypt_with_limit(ciphertext, passphrase, limit).unwrap();
/// assert_eq!(plaintext, data);
/// ```
#[cfg(feature = "alloc")]
pub fn decrypt_with_limit(
    ciphertext: impl AsRef<[u8]>,
    passphrase: impl AsRef<[u8]>,
    limit: ResourceLimit,
) -> Result<Vec<u8>> {
    Decryptor::with_limit(&ciphertext, passphrase, limit).and_then(Decryptor::decrypt_to_vec)
}
