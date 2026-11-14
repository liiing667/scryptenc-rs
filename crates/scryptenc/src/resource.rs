// SPDX-FileCopyrightText: 2026 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Policies for limiting the resources used to decrypt untrusted data.

use crate::{Error, Params, Result};

/// A configurable policy that limits the resources which an untrusted
/// scrypt-encrypted blob is allowed to consume.
///
/// The limits encoded in this type are checked against the parameters stored
/// in the header and the length of the ciphertext before any memory is
/// allocated for the scrypt KDF and before the derived key is computed. This
/// makes it possible to reject malicious headers advertising excessive
/// `N`/`r`/`p` parameters or excessively large ciphertexts without spending
/// CPU time or memory on them.
///
/// Each limit is optional; [`None`] means that the corresponding resource is
/// not bounded. The default value therefore imposes no limits.
///
/// The same policy can be shared by [`crate::Params`],
/// [`crate::Decryptor`] and the callers of either type, such as the
/// `rscrypt` command-line tool.
///
/// # Examples
///
/// ```
/// use scryptenc::{Decryptor, ResourceLimit};
///
/// let ciphertext = include_bytes!("../tests/data/data.txt.scrypt");
/// let passphrase = "passphrase";
///
/// let limit = ResourceLimit::new()
///     .with_max_memory(64 * 1024 * 1024)
///     .with_max_ops(1_000_000_000)
///     .with_max_ciphertext_size(1024);
/// assert!(Decryptor::with_limit(&ciphertext, passphrase, limit).is_ok());
/// ```
#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceLimit {
    /// The maximum number of bytes of RAM which the scrypt KDF may use.
    max_memory: Option<u128>,

    /// The maximum number of Salsa20/8 operations which the scrypt KDF may
    /// perform.
    max_ops: Option<u128>,

    /// The maximum length in bytes of the entire encrypted blob.
    max_ciphertext_size: Option<u128>,
}

impl ResourceLimit {
    /// Creates a new `ResourceLimit` which imposes no limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_memory: None,
            max_ops: None,
            max_ciphertext_size: None,
        }
    }

    /// Limits the number of bytes of RAM which the scrypt KDF is allowed to
    /// use.
    ///
    /// The memory required by scrypt for parameters `N` and `r` is
    /// `128 * N * r` bytes.
    #[must_use]
    pub const fn with_max_memory(mut self, max_memory: u128) -> Self {
        self.max_memory = Some(max_memory);
        self
    }

    /// Limits the number of Salsa20/8 operations which the scrypt KDF is
    /// allowed to perform.
    ///
    /// The number of operations required by scrypt for parameters `N`, `r`
    /// and `p` is `4 * N * r * p`.
    #[must_use]
    pub const fn with_max_ops(mut self, max_ops: u128) -> Self {
        self.max_ops = Some(max_ops);
        self
    }

    /// Limits the length in bytes of the entire encrypted blob, including the
    /// 96-byte header and the 32-byte authentication tag.
    #[must_use]
    pub const fn with_max_ciphertext_size(mut self, max_ciphertext_size: u128) -> Self {
        self.max_ciphertext_size = Some(max_ciphertext_size);
        self
    }

    /// Returns the maximum number of bytes of RAM which the scrypt KDF may
    /// use, if configured.
    #[must_use]
    pub const fn max_memory(&self) -> Option<u128> {
        self.max_memory
    }

    /// Returns the maximum number of Salsa20/8 operations which the scrypt KDF
    /// may perform, if configured.
    #[must_use]
    pub const fn max_ops(&self) -> Option<u128> {
        self.max_ops
    }

    /// Returns the maximum length in bytes of the entire encrypted blob, if
    /// configured.
    #[must_use]
    pub const fn max_ciphertext_size(&self) -> Option<u128> {
        self.max_ciphertext_size
    }

    /// Checks the length of the encrypted blob against this policy.
    pub(crate) fn check_ciphertext_size(&self, ciphertext_len: usize) -> Result<()> {
        let ciphertext_len = u128::try_from(ciphertext_len).unwrap_or(u128::MAX);
        match self.max_ciphertext_size {
            Some(limit) if ciphertext_len > limit => Err(Error::CiphertextTooLarge),
            _ => Ok(()),
        }
    }

    /// Checks the resources required by `params` against this policy.
    ///
    /// This performs no I/O and no key derivation, so it is cheap to call
    /// before the scrypt KDF is invoked.
    pub(crate) fn check_params(&self, params: Params) -> Result<()> {
        let n = u128::from(params.n());
        let r = u128::from(params.r());
        let p = u128::from(params.p());

        if let Some(max_memory) = self.max_memory
            && n.saturating_mul(r).saturating_mul(128) > max_memory
        {
            return Err(Error::MemoryLimitExceeded);
        }

        if let Some(max_ops) = self.max_ops
            && n.saturating_mul(r).saturating_mul(p).saturating_mul(4) > max_ops
        {
            return Err(Error::OperationLimitExceeded);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(log_n: u8, r: u32, p: u32) -> Params {
        scrypt::Params::new(log_n, r, p, scrypt::Params::RECOMMENDED_LEN)
            .unwrap()
            .into()
    }

    #[test]
    fn no_limits_by_default() {
        let limit = ResourceLimit::new();
        assert_eq!(limit.max_memory(), None);
        assert_eq!(limit.max_ops(), None);
        assert_eq!(limit.max_ciphertext_size(), None);
    }

    #[test]
    fn builders() {
        let limit = ResourceLimit::new()
            .with_max_memory(1024)
            .with_max_ops(2048)
            .with_max_ciphertext_size(4096);
        assert_eq!(limit.max_memory(), Some(1024));
        assert_eq!(limit.max_ops(), Some(2048));
        assert_eq!(limit.max_ciphertext_size(), Some(4096));
    }

    #[test]
    fn check_ciphertext_size() {
        let limit = ResourceLimit::new().with_max_ciphertext_size(128);
        assert!(limit.check_ciphertext_size(127).is_ok());
        assert!(limit.check_ciphertext_size(128).is_ok());
        assert!(limit.check_ciphertext_size(129).is_err());

        assert!(
            ResourceLimit::new()
                .check_ciphertext_size(usize::MAX)
                .is_ok()
        );
    }

    #[test]
    fn check_params_within_limits() {
        let limit = ResourceLimit::new()
            .with_max_memory(128 * 1024 * 8)
            .with_max_ops(4 * 1024 * 8);
        assert!(limit.check_params(params(10, 8, 1)).is_ok());
    }

    #[test]
    fn check_params_memory_limit() {
        let limit = ResourceLimit::new().with_max_memory(128 * 1024 * 8 - 1);
        assert_eq!(
            limit.check_params(params(10, 8, 1)).unwrap_err(),
            Error::MemoryLimitExceeded
        );
    }

    #[test]
    fn check_params_operation_limit() {
        let limit = ResourceLimit::new().with_max_ops(4 * 1024 * 8 - 1);
        assert_eq!(
            limit.check_params(params(10, 8, 1)).unwrap_err(),
            Error::OperationLimitExceeded
        );
    }
}
