//! Record-layer AEAD for Snell encryption.
//!
//! Every relayed byte passes through here, using BoringSSL's AEAD context.
//! Nonce is 12 bytes and tag is 16 bytes.

use boring::aead::{AeadCtx, Algorithm};

/// Nonce length of every algorithm here.
pub(crate) const NONCE_LEN: usize = 12;
/// Tag length of every algorithm here.
pub(crate) const TAG_LEN: usize = 16;

/// AEAD failure: a tag that does not authenticate, or a sealed buffer too
/// short to hold one.
#[derive(Debug)]
pub(crate) struct AeadError;

/// One key's AEAD context. The key schedule lives behind BoringSSL's context
/// pointer, so this is pointer-sized.
pub(crate) struct Aead(AeadCtx);

impl Aead {
    /// AES-128-GCM; `key` must be 16 bytes.
    pub(crate) fn aes_128_gcm(key: &[u8]) -> Self {
        Self::new(&Algorithm::aes_128_gcm(), key)
    }

    /// Panics on a wrong-length key: every caller derives the key at a fixed
    /// length, so a mismatch is a bug, not input to handle.
    fn new(algorithm: &Algorithm, key: &[u8]) -> Self {
        Self(
            AeadCtx::new_default_tag(algorithm, key)
                .expect("AEAD key length matches the algorithm"),
        )
    }

    /// Encrypt `data` in place under `nonce` and `ad`, writing the tag to
    /// `tag` (which must be [`TAG_LEN`] bytes).
    pub(crate) fn seal_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), AeadError> {
        debug_assert_eq!(tag.len(), TAG_LEN);
        self.0
            .seal_in_place(nonce, data, tag, ad)
            .map(|_| ())
            .map_err(|_| AeadError)
    }

    /// Verify `tag` and decrypt `data` in place under `nonce` and `ad`.
    pub(crate) fn open_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        data: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AeadError> {
        self.0
            .open_in_place(nonce, data, tag, ad)
            .map_err(|_| AeadError)
    }

    /// Encrypt `buf` in place under `nonce` and `ad` and append the tag.
    pub(crate) fn seal_append(
        &self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        let len = buf.len();
        buf.resize(len + TAG_LEN, 0);
        let (data, tag) = buf.split_at_mut(len);
        self.seal_detached(nonce, ad, data, tag)
    }

    /// Verify and strip the trailing tag of `buf`, decrypting the rest in
    /// place under `nonce` and `ad`.
    pub(crate) fn open_trailing(
        &self,
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        let len = buf.len().checked_sub(TAG_LEN).ok_or(AeadError)?;
        let (data, tag) = buf.split_at_mut(len);
        self.open_detached(nonce, ad, data, tag)?;
        buf.truncate(len);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Plaintext and AAD of McGrew–Viega GCM spec test cases 4 and 16.
    const GCM_SPEC_IV: &str = "cafebabefacedbaddecaf888";
    const GCM_SPEC_AD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    const GCM_SPEC_PLAIN: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d\
                                  8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";

    /// Seal `plain` both ways — detached tag and appended tag — and check
    /// each against `sealed` (ciphertext || tag), then open both back.
    fn assert_vector(aead: &Aead, nonce: &str, ad: &str, plain: &str, sealed: &str) {
        let nonce: [u8; NONCE_LEN] = unhex(nonce).try_into().unwrap();
        let (ad, plain, sealed) = (unhex(ad), unhex(plain), unhex(sealed));
        let (want_ct, want_tag) = sealed.split_at(plain.len());

        let mut data = plain.clone();
        let mut tag = [0u8; TAG_LEN];
        aead.seal_detached(&nonce, &ad, &mut data, &mut tag)
            .unwrap();
        assert_eq!((data.as_slice(), tag.as_slice()), (want_ct, want_tag));
        aead.open_detached(&nonce, &ad, &mut data, &tag).unwrap();
        assert_eq!(data, plain);

        let mut buf = plain.clone();
        aead.seal_append(&nonce, &ad, &mut buf).unwrap();
        assert_eq!(buf, sealed);
        aead.open_trailing(&nonce, &ad, &mut buf).unwrap();
        assert_eq!(buf, plain);
    }

    #[test]
    fn aes_128_gcm_matches_gcm_spec() {
        // Test case 2: zero key and nonce, one zero block, no AAD.
        assert_vector(
            &Aead::aes_128_gcm(&[0; 16]),
            "000000000000000000000000",
            "",
            "00000000000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf",
        );
        // Test case 4: 60-byte plaintext with AAD.
        assert_vector(
            &Aead::aes_128_gcm(&unhex("feffe9928665731c6d6a8f9467308308")),
            GCM_SPEC_IV,
            GCM_SPEC_AD,
            GCM_SPEC_PLAIN,
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e23\
             29aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
             5bc94fbc3221a5db94fae95ae7121a47",
        );
    }

    #[test]
    fn open_rejects_tampering_and_short_input() {
        let aead = Aead::aes_128_gcm(&[7; 16]);
        let nonce = [1; NONCE_LEN];
        let mut buf = b"record".to_vec();
        aead.seal_append(&nonce, b"ad", &mut buf).unwrap();

        let mut flipped = buf.clone();
        flipped[0] ^= 1;
        assert!(aead.open_trailing(&nonce, b"ad", &mut flipped).is_err());
        assert!(
            aead.open_trailing(&[2; NONCE_LEN], b"ad", &mut buf.clone())
                .is_err()
        );
        assert!(
            aead.open_trailing(&nonce, b"other ad", &mut buf.clone())
                .is_err()
        );
        assert!(
            aead.open_trailing(&nonce, b"", &mut vec![0; TAG_LEN - 1])
                .is_err()
        );
        aead.open_trailing(&nonce, b"ad", &mut buf).unwrap();
        assert_eq!(buf, b"record");
    }
}
