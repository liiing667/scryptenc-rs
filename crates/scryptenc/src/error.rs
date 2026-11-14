// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Error types for this crate.

use core::{fmt, result};
#[cfg(feature = "std")]
use std::error;

use hmac::digest::MacError;
use scrypt::errors::InvalidParams;

/// The error type for the scrypt encrypted data format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The encrypted data was shorter than 128 bytes.
    InvalidLength,

    /// The magic number (file signature) was invalid.
    InvalidMagicNumber,

    /// The version was the unrecognized scrypt version number.
    UnknownVersion(u8),

    /// The scrypt parameters were invalid.
    InvalidParams(InvalidParams),

    /// The checksum of the header mismatched.
    InvalidChecksum,

    /// The MAC (authentication tag) of the header was invalid.
    InvalidHeaderMac(MacError),

    /// The MAC (authentication tag) of the scrypt encrypted data format was
    /// invalid.
    InvalidMac(MacError),

    /// The scrypt KDF required more memory than allowed by the configured
    /// resource limit.
    MemoryLimitExceeded,

    /// The scrypt KDF required more CPU time (Salsa20/8 operations) than
    /// allowed by the configured resource limit.
    OperationLimitExceeded,

    /// The encrypted blob was larger than the configured resource limit.
    CiphertextTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "encrypted data is shorter than 128 bytes"),
            Self::InvalidMagicNumber => write!(f, "invalid magic number"),
            Self::UnknownVersion(version) => write!(f, "unknown version number `{version}`"),
            Self::InvalidParams(err) => err.fmt(f),
            Self::InvalidChecksum => write!(f, "checksum mismatch"),
            Self::InvalidHeaderMac(_) => write!(f, "invalid header MAC"),
            Self::InvalidMac(_) => write!(f, "invalid MAC"),
            Self::MemoryLimitExceeded => {
                write!(f, "decrypting the data takes too much memory")
            }
            Self::OperationLimitExceeded => {
                write!(f, "decrypting the data takes too much CPU time")
            }
            Self::CiphertextTooLarge => {
                write!(f, "the encrypted data is larger than the limit")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::InvalidParams(err) => Some(err),
            Self::InvalidHeaderMac(err) | Self::InvalidMac(err) => Some(err),
            _ => None,
        }
    }
}

impl From<InvalidParams> for Error {
    fn from(err: InvalidParams) -> Self {
        Self::InvalidParams(err)
    }
}

/// A specialized [`Result`](result::Result) type for read and write operations
/// for the scrypt encrypted data format.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "alloc")]
/// # {
/// use scryptenc::{Decryptor, Encryptor};
///
/// fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> Vec<u8> {
///     Encryptor::new(&plaintext, passphrase).encrypt_to_vec()
/// }
///
/// fn decrypt(ciphertext: &[u8], passphrase: &[u8]) -> scryptenc::Result<Vec<u8>> {
///     Decryptor::new(&ciphertext, passphrase).and_then(|c| c.decrypt_to_vec())
/// }
///
/// let data = b"Hello, world!\n";
/// let passphrase = b"passphrase";
///
/// let ciphertext = encrypt(data, passphrase);
/// assert_ne!(ciphertext, data);
///
/// let plaintext = decrypt(&ciphertext, passphrase).unwrap();
/// assert_eq!(plaintext, data);
/// # }
/// ```
pub type Result<T> = result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use core::any;
    #[cfg(feature = "std")]
    use std::error::Error as _;

    use super::*;

    #[test]
    fn clone() {
        assert_eq!(Error::InvalidLength.clone(), Error::InvalidLength);
        assert_eq!(Error::InvalidMagicNumber.clone(), Error::InvalidMagicNumber);
        assert_eq!(
            Error::UnknownVersion(u8::MAX).clone(),
            Error::UnknownVersion(u8::MAX)
        );
        assert_eq!(
            Error::InvalidParams(InvalidParams).clone(),
            Error::InvalidParams(InvalidParams)
        );
        assert_eq!(Error::InvalidChecksum.clone(), Error::InvalidChecksum);
        assert_eq!(
            Error::InvalidHeaderMac(MacError).clone(),
            Error::InvalidHeaderMac(MacError)
        );
        assert_eq!(
            Error::InvalidMac(MacError).clone(),
            Error::InvalidMac(MacError)
        );
        assert_eq!(
            Error::MemoryLimitExceeded.clone(),
            Error::MemoryLimitExceeded
        );
        assert_eq!(
            Error::OperationLimitExceeded.clone(),
            Error::OperationLimitExceeded
        );
        assert_eq!(Error::CiphertextTooLarge.clone(), Error::CiphertextTooLarge);
    }

    #[test]
    fn copy() {
        {
            let a = Error::InvalidLength;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidMagicNumber;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::UnknownVersion(u8::MAX);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidParams(InvalidParams);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidChecksum;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidHeaderMac(MacError);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidMac(MacError);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::MemoryLimitExceeded;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::OperationLimitExceeded;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::CiphertextTooLarge;
            let b = a;
            assert_eq!(a, b);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn debug() {
        assert_eq!(format!("{:?}", Error::InvalidLength), "InvalidLength");
        assert_eq!(
            format!("{:?}", Error::InvalidMagicNumber),
            "InvalidMagicNumber"
        );
        assert_eq!(
            format!("{:?}", Error::UnknownVersion(u8::MAX)),
            "UnknownVersion(255)"
        );
        assert_eq!(
            format!("{:?}", Error::InvalidParams(InvalidParams)),
            "InvalidParams(InvalidParams)"
        );
        assert_eq!(format!("{:?}", Error::InvalidChecksum), "InvalidChecksum");
        assert_eq!(
            format!("{:?}", Error::InvalidHeaderMac(MacError)),
            "InvalidHeaderMac(MacError)"
        );
        assert_eq!(
            format!("{:?}", Error::InvalidMac(MacError)),
            "InvalidMac(MacError)"
        );
        assert_eq!(
            format!("{:?}", Error::MemoryLimitExceeded),
            "MemoryLimitExceeded"
        );
        assert_eq!(
            format!("{:?}", Error::OperationLimitExceeded),
            "OperationLimitExceeded"
        );
        assert_eq!(
            format!("{:?}", Error::CiphertextTooLarge),
            "CiphertextTooLarge"
        );
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn equality() {
        assert_eq!(Error::InvalidLength, Error::InvalidLength);
        assert_ne!(Error::InvalidLength, Error::InvalidMagicNumber);
        assert_ne!(Error::InvalidLength, Error::UnknownVersion(u8::MAX));
        assert_ne!(Error::InvalidLength, Error::InvalidParams(InvalidParams));
        assert_ne!(Error::InvalidLength, Error::InvalidChecksum);
        assert_ne!(Error::InvalidLength, Error::InvalidHeaderMac(MacError));
        assert_ne!(Error::InvalidLength, Error::InvalidMac(MacError));
        assert_ne!(Error::InvalidMagicNumber, Error::InvalidLength);
        assert_eq!(Error::InvalidMagicNumber, Error::InvalidMagicNumber);
        assert_ne!(Error::InvalidMagicNumber, Error::UnknownVersion(u8::MAX));
        assert_ne!(
            Error::InvalidMagicNumber,
            Error::InvalidParams(InvalidParams)
        );
        assert_ne!(Error::InvalidMagicNumber, Error::InvalidChecksum);
        assert_ne!(Error::InvalidMagicNumber, Error::InvalidHeaderMac(MacError));
        assert_ne!(Error::InvalidMagicNumber, Error::InvalidMac(MacError));
        assert_ne!(Error::UnknownVersion(u8::MAX), Error::InvalidLength);
        assert_ne!(Error::UnknownVersion(u8::MAX), Error::InvalidMagicNumber);
        assert_eq!(
            Error::UnknownVersion(u8::MAX),
            Error::UnknownVersion(u8::MAX)
        );
        assert_ne!(
            Error::UnknownVersion(u8::MAX),
            Error::InvalidParams(InvalidParams)
        );
        assert_ne!(Error::UnknownVersion(u8::MAX), Error::InvalidChecksum);
        assert_ne!(
            Error::UnknownVersion(u8::MAX),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(Error::UnknownVersion(u8::MAX), Error::InvalidMac(MacError));
        assert_ne!(Error::InvalidParams(InvalidParams), Error::InvalidLength);
        assert_ne!(
            Error::InvalidParams(InvalidParams),
            Error::InvalidMagicNumber
        );
        assert_ne!(
            Error::InvalidParams(InvalidParams),
            Error::UnknownVersion(u8::MAX)
        );
        assert_eq!(
            Error::InvalidParams(InvalidParams),
            Error::InvalidParams(InvalidParams)
        );
        assert_ne!(Error::InvalidParams(InvalidParams), Error::InvalidChecksum);
        assert_ne!(
            Error::InvalidParams(InvalidParams),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(
            Error::InvalidParams(InvalidParams),
            Error::InvalidMac(MacError)
        );
        assert_ne!(Error::InvalidChecksum, Error::InvalidLength);
        assert_ne!(Error::InvalidChecksum, Error::InvalidMagicNumber);
        assert_ne!(Error::InvalidChecksum, Error::UnknownVersion(u8::MAX));
        assert_ne!(Error::InvalidChecksum, Error::InvalidParams(InvalidParams));
        assert_eq!(Error::InvalidChecksum, Error::InvalidChecksum);
        assert_ne!(Error::InvalidChecksum, Error::InvalidHeaderMac(MacError));
        assert_ne!(Error::InvalidChecksum, Error::InvalidMac(MacError));
        assert_ne!(Error::InvalidHeaderMac(MacError), Error::InvalidLength);
        assert_ne!(Error::InvalidHeaderMac(MacError), Error::InvalidMagicNumber);
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::UnknownVersion(u8::MAX)
        );
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::InvalidParams(InvalidParams)
        );
        assert_ne!(Error::InvalidHeaderMac(MacError), Error::InvalidChecksum);
        assert_eq!(
            Error::InvalidHeaderMac(MacError),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::InvalidMac(MacError)
        );
        assert_ne!(Error::InvalidMac(MacError), Error::InvalidLength);
        assert_ne!(Error::InvalidMac(MacError), Error::InvalidMagicNumber);
        assert_ne!(Error::InvalidMac(MacError), Error::UnknownVersion(u8::MAX));
        assert_ne!(
            Error::InvalidMac(MacError),
            Error::InvalidParams(InvalidParams)
        );
        assert_ne!(Error::InvalidMac(MacError), Error::InvalidChecksum);
        assert_ne!(
            Error::InvalidMac(MacError),
            Error::InvalidHeaderMac(MacError)
        );
        assert_eq!(Error::InvalidMac(MacError), Error::InvalidMac(MacError));
        assert_ne!(Error::InvalidMac(MacError), Error::MemoryLimitExceeded);
        assert_ne!(Error::InvalidMac(MacError), Error::OperationLimitExceeded);
        assert_ne!(Error::InvalidMac(MacError), Error::CiphertextTooLarge);
        assert_eq!(Error::MemoryLimitExceeded, Error::MemoryLimitExceeded);
        assert_ne!(Error::MemoryLimitExceeded, Error::OperationLimitExceeded);
        assert_ne!(Error::MemoryLimitExceeded, Error::CiphertextTooLarge);
        assert_eq!(Error::OperationLimitExceeded, Error::OperationLimitExceeded);
        assert_ne!(Error::OperationLimitExceeded, Error::CiphertextTooLarge);
        assert_eq!(Error::CiphertextTooLarge, Error::CiphertextTooLarge);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn display() {
        assert_eq!(
            format!("{}", Error::InvalidLength),
            "encrypted data is shorter than 128 bytes"
        );
        assert_eq!(
            format!("{}", Error::InvalidMagicNumber),
            "invalid magic number"
        );
        assert_eq!(
            format!("{}", Error::UnknownVersion(u8::MAX)),
            "unknown version number `255`"
        );
        assert_eq!(
            format!("{}", Error::InvalidParams(InvalidParams)),
            "invalid scrypt parameters"
        );
        assert_eq!(format!("{}", Error::InvalidChecksum), "checksum mismatch");
        assert_eq!(
            format!("{}", Error::InvalidHeaderMac(MacError)),
            "invalid header MAC"
        );
        assert_eq!(format!("{}", Error::InvalidMac(MacError)), "invalid MAC");
        assert_eq!(
            format!("{}", Error::MemoryLimitExceeded),
            "decrypting the data takes too much memory"
        );
        assert_eq!(
            format!("{}", Error::OperationLimitExceeded),
            "decrypting the data takes too much CPU time"
        );
        assert_eq!(
            format!("{}", Error::CiphertextTooLarge),
            "the encrypted data is larger than the limit"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn source() {
        assert!(Error::InvalidLength.source().is_none());
        assert!(Error::InvalidMagicNumber.source().is_none());
        assert!(Error::UnknownVersion(u8::MAX).source().is_none());
        assert!(
            Error::InvalidParams(InvalidParams)
                .source()
                .unwrap()
                .is::<InvalidParams>()
        );
        assert!(Error::InvalidChecksum.source().is_none());
        assert!(
            Error::InvalidHeaderMac(MacError)
                .source()
                .unwrap()
                .is::<MacError>()
        );
        assert!(
            Error::InvalidMac(MacError)
                .source()
                .unwrap()
                .is::<MacError>()
        );
        assert!(Error::MemoryLimitExceeded.source().is_none());
        assert!(Error::OperationLimitExceeded.source().is_none());
        assert!(Error::CiphertextTooLarge.source().is_none());
    }

    #[test]
    fn from_invalid_params_to_error() {
        assert_eq!(
            Error::from(InvalidParams),
            Error::InvalidParams(InvalidParams)
        );
    }

    #[test]
    fn result_type() {
        assert_eq!(
            any::type_name::<Result<()>>(),
            any::type_name::<result::Result<(), Error>>()
        );
        assert_eq!(
            any::type_name::<Result<u8>>(),
            any::type_name::<result::Result<u8, Error>>()
        );
    }
}
