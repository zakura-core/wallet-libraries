//! Small argument helpers shared only by the reference CLI and canary.
//!
//! This module is not part of the library's module graph.

use std::ffi::{OsStr, OsString};

/// Recognize the long help flag or a short-option cluster beginning with `h`.
pub(super) fn is_help(argument: &OsStr) -> bool {
    argument == "--help" || argument.as_encoded_bytes().starts_with(b"-h")
}

/// Consume one named option's value, retaining native path encodings.
pub(super) fn take_value(
    argument: &OsStr,
    name: &str,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Option<Result<OsString, String>> {
    if argument == name {
        return Some(
            arguments
                .next()
                .filter(|value| value == "-" || !value.as_encoded_bytes().starts_with(b"-"))
                .ok_or_else(|| format!("a value is required for {name}")),
        );
    }
    argument
        .as_encoded_bytes()
        .strip_prefix(name.as_bytes())?
        .strip_prefix(b"=")?;
    Some(equals_value(argument, name))
}

/// Parse an unsigned decimal option with the same range as its stored value.
pub(super) fn number(value: OsString, name: &str) -> Result<u64, String> {
    value
        .to_str()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| format!("{name} requires an unsigned 64-bit integer"))
}

/// Copy the suffix after an already-checked option name and equals sign.
fn equals_value(argument: &OsStr, name: &str) -> Result<OsString, String> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        Ok(OsString::from_vec(
            argument.as_bytes()[name.len() + 1..].to_vec(),
        ))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let units: Vec<_> = argument
            .encode_wide()
            .skip(name.encode_utf16().count() + 1)
            .collect();
        Ok(OsString::from_wide(&units))
    }
    #[cfg(not(any(unix, windows)))]
    {
        argument
            .to_str()
            .map(|text| OsString::from(&text[name.len() + 1..]))
            .ok_or_else(|| format!("invalid encoding for {name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_preserve_empty_equals_and_separate_values() {
        let mut values = [OsString::from("한글"), OsString::from("next")].into_iter();
        assert_eq!(
            take_value(OsStr::new("--file"), "--file", &mut values),
            Some(Ok(OsString::from("한글"))),
        );
        assert_eq!(values.next(), Some(OsString::from("next")));
        for (argument, expected) in [("--file=", ""), ("--file==x", "=x"), ("--file=-h", "-h")] {
            assert_eq!(
                take_value(OsStr::new(argument), "--file", &mut std::iter::empty()),
                Some(Ok(OsString::from(expected))),
            );
        }
        assert!(take_value(OsStr::new("--files=x"), "--file", &mut values).is_none());
        assert!(
            take_value(OsStr::new("--file"), "--file", &mut values)
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn options_do_not_take_a_flag_as_their_separate_value() {
        for value in ["-h", "--help", "--other", "-1", "--"] {
            assert!(
                take_value(
                    OsStr::new("--file"),
                    "--file",
                    &mut [OsString::from(value)].into_iter(),
                )
                .unwrap()
                .is_err()
            );
        }
        assert_eq!(
            take_value(
                OsStr::new("--file"),
                "--file",
                &mut [OsString::from("-")].into_iter()
            ),
            Some(Ok(OsString::from("-"))),
        );
    }

    #[test]
    fn number_limits_and_help_clusters() {
        assert_eq!(number("+1".into(), "--n"), Ok(1));
        assert_eq!(number(u64::MAX.to_string().into(), "--n"), Ok(u64::MAX));
        for invalid in ["", "-1", "18446744073709551616", "1.5"] {
            assert!(number(invalid.into(), "--n").is_err());
        }
        for flag in ["-h", "-hfoo", "-h=bad", "--help"] {
            assert!(is_help(OsStr::new(flag)));
        }
        assert!(!is_help(OsStr::new("--help=bad")));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_remain_lossless() {
        use std::os::unix::ffi::OsStringExt;
        let path = OsString::from_vec(b"file\xff".to_vec());
        let joined = OsString::from_vec(b"--file=file\xff".to_vec());
        assert_eq!(
            take_value(&joined, "--file", &mut std::iter::empty()),
            Some(Ok(path.clone())),
        );
        assert_eq!(
            take_value(
                OsStr::new("--file"),
                "--file",
                &mut [path.clone()].into_iter()
            ),
            Some(Ok(path)),
        );
    }

    #[cfg(windows)]
    #[test]
    fn unpaired_surrogate_paths_remain_lossless() {
        use std::os::windows::ffi::OsStringExt;
        let path = OsString::from_wide(&[u16::from(b'f'), 0xd800]);
        let mut joined = OsString::from("--file=");
        joined.push(&path);
        assert_eq!(
            take_value(&joined, "--file", &mut std::iter::empty()),
            Some(Ok(path.clone())),
        );
        assert_eq!(
            take_value(
                OsStr::new("--file"),
                "--file",
                &mut [path.clone()].into_iter()
            ),
            Some(Ok(path)),
        );
    }
}
