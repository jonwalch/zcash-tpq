//! Fixed field sizes for the sole SLH-DSA-B-128s profile.

/// Two 16-byte public seed/root components.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Complete SLH-DSA-B-128s signature, without an external message wrapper.
pub const SIGNATURE_SIZE: usize = 7_856;
