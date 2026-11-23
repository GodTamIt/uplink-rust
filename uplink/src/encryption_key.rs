//! Storj DCS Encryption key.

use crate::uplink_c::Ensurer;
use crate::{helpers, Error, Result};

use uplink_sys as ulksys;

/// Represents a key for encrypting and decrypting data.
#[derive(Debug)]
pub struct EncryptionKey {
    /// The encryption key type of the FFI that an instance of this struct represents and guards its
    /// lifetime until the instances drops.
    /// It's an encryption result because it's the one that holds the encryption
    /// key and allows to free its memory.
    inner: ulksys::UplinkEncryptionKeyResult,
}

impl EncryptionKey {
    /// Derives a salted encryption key for `passphrase` using the passed salt.
    ///
    /// It's mostly useful for implementing multitenancy in a single app bucket.
    /// See [Multitenancy in a Single Application Bucket](https://pkg.go.dev/storj.io/uplink#hdr-Multitenancy_in_a_Single_Application_Bucket)
    /// section in the original Uplink library.
    pub fn derive(passphrase: &str, salt: &[u8]) -> Result<Self> {
        use std::ffi::c_void;
        use std::os::raw::c_char;

        let passphrase = helpers::cstring_from_str_fn_arg("passphrase", passphrase)?;

        // SAFETY: we trust that the FFI is safe creating an instance of its own types.
        // Note that we get a non-mutable pointer to the `salt` argument but we apply a conversion
        // to to mutable rather than using the `as_mut_ptr` method because otherwise it will require
        // the `salt` parameter to be mutable but the FFI function doesn't mutate it despite that
        // the function parameters is specified as mutable.
        let uc_res = unsafe {
            ulksys::uplink_derive_encryption_key(
                passphrase.as_ptr() as *mut c_char,
                salt.as_ptr() as *mut c_void,
                salt.len(),
            )
        };

        uc_res.ensure();

        if let Some(err) = Error::new_uplink(uc_res.error) {
            // SAFETY: we trust the FFI is safe freeing the memory of a valid pointer.
            unsafe { ulksys::uplink_free_encryption_key_result(uc_res) };
            return Err(err);
        }

        Ok(Self { inner: uc_res })
    }

    /// Returns the FFI representation of this encryption key.
    pub(crate) fn as_ffi_encryption_key(&self) -> *mut ulksys::UplinkEncryptionKey {
        self.inner.encryption_key
    }
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        // SAFETY: this type implementation guarantees that the FFI value is valid since an instance
        // is created until it's dropped.
        unsafe { ulksys::uplink_free_encryption_key_result(self.inner) };
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error;
    use crate::Error;

    #[test]
    fn test_derive_invalid_argument() {
        if let Error::InvalidArguments(error::Args { names, msg }) =
            EncryptionKey::derive("pass\0phrase", &[0])
                .expect_err("when passing a passphrase with NULL bytes")
        {
            assert_eq!(names, "passphrase", "invalid error argument name");
            assert_eq!(
                msg, "cannot contains null bytes (0 byte). Null byte found at 4",
                "invalid error argument message"
            );
        } else {
            panic!("expected an invalid argument error");
        }
    }

    #[test]
    fn test_drop_frees_ffi_encryption_key() {
        use crate::access::Grant;

        // This access grant is invalidated so it isn't leaking any valid access grant.
        let grant = Grant::new("15kvZYL7aMhTXFU6vne8iedGfvvZdcbaDLAZ9SiN1yChpAYupdDw3SMfyHqA7pETdFjhe8SnjLox4tnq5hYbZWfCm443kv3fWV8ZWNkKwaq1mbrmyz3pPd1WSxiJn2g5tYKWoPpzvG1ygjDaB4yEq9zdpYSaH5DiVHrbaWmq6mCwRrnEF1ANdVcA2gXNbFpmSKp2i59fA14RRdZYVTrvY6rWKyG35p35eenp3ePyjwoXNSe9Cs8KvMRteVcozNiMwwuYCm4ExwP8os5Eqydqwjpx8ic8hnirkn7ThBbLLAtJBLtu").expect("valid serialized access grant");

        // Uses the encryption key through a copy of its handle, because the memory of the FFI value
        // cannot be accessed after dropping the key. The FFI never reuses handles.
        let use_handle = |mut handle: ulksys::UplinkEncryptionKey| {
            // SAFETY: all the pointers are valid during the call to the function.
            Error::from_ffi_error(unsafe {
                ulksys::uplink_access_override_encryption_key(
                    grant.as_ffi_access(),
                    c"a-bucket".as_ptr(),
                    c"prefix/".as_ptr(),
                    &mut handle,
                )
            })
        };

        let key = EncryptionKey::derive("Rust test", &[0]).expect("derive encryption key");
        // SAFETY: the pointer is valid until the key is dropped.
        let handle = unsafe { *key.as_ffi_encryption_key() };
        assert!(use_handle(handle).is_none(), "before dropping the key");

        drop(key);
        match use_handle(handle).expect("after dropping the key") {
            Error::Uplink(error::Uplink::InvalidHandle(_)) => {}
            err => panic!("expected an Uplink invalid handle error, got: {err:?}"),
        }
    }
}
