use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

const IDENTITY_ADDRESS_VERSION: u8 = 102;
const IDENTITY_HASH_LENGTH: usize = 20;
const MAX_IDENTITY_NAME_BYTES: usize = 64;

// These are the characters removed by the daemon's display-filtered
// CleanName path. Requiring an unchanged leaf name lets the proxy derive the
// same ID without depending on the daemon's runtime chain name.
const INVALID_IDENTITY_NAME_CHARS: &[char] =
    &['\\', '/', ':', '*', '?', '"', '<', '>', '|', '.', '@'];
const IDENTITY_SPACE_CHARS: &[char] = &[
    '\u{0020}', '\u{00a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
    '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{200c}', '\u{200d}',
    '\u{202f}', '\u{205f}', '\u{3000}',
];

pub(crate) fn is_canonical_identity_leaf_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_IDENTITY_NAME_BYTES {
        return false;
    }

    let mut previous_was_space = false;
    for (index, character) in name.chars().enumerate() {
        if character.is_control() || INVALID_IDENTITY_NAME_CHARS.contains(&character) {
            return false;
        }

        let is_space = IDENTITY_SPACE_CHARS.contains(&character);
        if is_space && (index == 0 || previous_was_space) {
            return false;
        }
        previous_was_space = is_space;
    }

    !previous_was_space
}

pub(crate) fn derive_parented_identity_address(name: &str, parent_address: &str) -> Option<String> {
    if !is_canonical_identity_leaf_name(name) {
        return None;
    }

    let decoded_parent = bs58::decode(parent_address)
        .with_check(None)
        .into_vec()
        .ok()?;
    if decoded_parent.len() != IDENTITY_HASH_LENGTH + 1
        || decoded_parent[0] != IDENTITY_ADDRESS_VERSION
        || decoded_parent[1..].iter().all(|byte| *byte == 0)
    {
        return None;
    }

    // Verus lowercases only ASCII characters here. Non-ASCII UTF-8 bytes are
    // deliberately preserved, matching toLowerCaseCLocale in the TS client.
    let normalized_name = name.to_ascii_lowercase();
    let name_hash = sha256d(normalized_name.as_bytes());

    let mut bound_input = Vec::with_capacity(IDENTITY_HASH_LENGTH + name_hash.len());
    bound_input.extend_from_slice(&decoded_parent[1..]);
    bound_input.extend_from_slice(&name_hash);
    let bound_hash = sha256d(&bound_input);

    let sha_hash = Sha256::digest(bound_hash);
    let identity_hash = Ripemd160::digest(sha_hash);
    let mut payload = Vec::with_capacity(IDENTITY_HASH_LENGTH + 1);
    payload.push(IDENTITY_ADDRESS_VERSION);
    payload.extend_from_slice(&identity_hash);

    Some(bs58::encode(payload).with_check().into_string())
}

fn sha256d(input: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(input);
    Sha256::digest(first).into()
}

#[cfg(test)]
mod tests {
    use super::{derive_parented_identity_address, is_canonical_identity_leaf_name};

    const PARENT: &str = "iJhCezBExJHvtyH3fGhNnt2NhU4Ztkf2yq";

    #[test]
    fn derives_addresses_matching_verus_client_vectors() {
        for (name, expected) in [
            ("test", "i8jHXEEYEQ7KEoYe6eKXBib8cUBZ6vjWSd"),
            ("test2", "iQa13cLx5a4bB9nnd8EZPigrqLTsn75VrF"),
            ("Andromeda", "iNC9NG5Jqk2tqVtqfjfiSpaqxrXaFU6RDu"),
            ("Chris", "iPsFBfFoCcxtuZNzE8yxPQhXVn4dmytf8j"),
            ("chris", "iPsFBfFoCcxtuZNzE8yxPQhXVn4dmytf8j"),
            ("test name", "i8Wnt3KJNEN91fdXmwJNHGtD6PxMJPuE6p"),
        ] {
            assert_eq!(
                derive_parented_identity_address(name, PARENT).as_deref(),
                Some(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_parent_or_name_shapes_that_cannot_be_derived_unambiguously() {
        const NULL_I_ADDRESS: &str = "i3UXS5QPRQGNRDDqVnyWTnmFCTHDbzmsYk";

        assert!(derive_parented_identity_address("test", "not-an-address").is_none());
        assert!(derive_parented_identity_address("test", NULL_I_ADDRESS).is_none());
        assert!(derive_parented_identity_address("test.child", PARENT).is_none());
        assert!(derive_parented_identity_address("test@", PARENT).is_none());
        assert!(!is_canonical_identity_leaf_name(" test"));
        assert!(!is_canonical_identity_leaf_name("test "));
        assert!(!is_canonical_identity_leaf_name("test  name"));
        assert!(!is_canonical_identity_leaf_name("test.child"));
        assert!(!is_canonical_identity_leaf_name("test@other"));
        assert!(!is_canonical_identity_leaf_name("test\nname"));
        assert!(!is_canonical_identity_leaf_name("test\u{00a0}\u{00a0}name"));
        assert!(is_canonical_identity_leaf_name(&"é".repeat(32)));
        assert!(!is_canonical_identity_leaf_name(&"é".repeat(33)));
        assert!(!is_canonical_identity_leaf_name(&"x".repeat(65)));
    }
}
