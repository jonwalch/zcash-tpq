//! Recognize the standalone identity command without decoding unrelated OS arguments.

use std::ffi::{OsStr, OsString};

pub(crate) fn is_identity_command(arguments: impl Iterator<Item = OsString>) -> bool {
    arguments.eq([OsStr::new("--slh-dsa-b128s-verifier-identity")])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_requires_exactly_one_matching_argument() {
        assert!(is_identity_command(
            [OsString::from("--slh-dsa-b128s-verifier-identity")].into_iter()
        ));
        for arguments in [
            vec![],
            vec!["start"],
            vec!["--slh-dsa-b128s-verifier-identity", "start"],
            vec!["start", "--slh-dsa-b128s-verifier-identity"],
        ] {
            assert!(!is_identity_command(
                arguments.into_iter().map(OsString::from)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_arguments_do_not_panic_or_select_identity() {
        use std::os::unix::ffi::OsStringExt;

        let invalid = OsString::from_vec(vec![0xff]);
        assert!(!is_identity_command([invalid.clone()].into_iter()));
        assert!(!is_identity_command(
            [OsString::from("--slh-dsa-b128s-verifier-identity"), invalid,].into_iter()
        ));
    }
}
