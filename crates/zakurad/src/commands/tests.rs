//! Tests for parsing zakurad commands

use clap::Parser;

use crate::commands::ZakuradCmd;

use super::EntryPoint;

#[test]
fn args_with_subcommand_pass_through() {
    let test_cases = [
        (false, true, false, vec!["zakurad"]),
        (false, true, true, vec!["zakurad", "-v"]),
        (false, true, true, vec!["zakurad", "--verbose"]),
        (true, false, false, vec!["zakurad", "-h"]),
        (true, false, false, vec!["zakurad", "--help"]),
        (false, true, false, vec!["zakurad", "start"]),
        (false, true, true, vec!["zakurad", "-v", "start"]),
        (false, true, false, vec!["zakurad", "--filters", "warn"]),
        (true, false, false, vec!["zakurad", "warn"]),
        (false, true, false, vec!["zakurad", "start", "warn"]),
        (true, false, false, vec!["zakurad", "help", "warn"]),
        (true, false, false, vec!["zakurad", "native-identity"]),
        (
            false,
            false,
            false,
            vec![
                "zakurad",
                "native-identity",
                "--identity-dir",
                "/private/native",
            ],
        ),
    ];

    for (should_exit, should_be_start, should_be_verbose, args) in test_cases {
        let args = EntryPoint::process_cli_args(args.iter().map(Into::into).collect());

        if should_exit {
            args.expect_err("parsing invalid args or 'help'/'--help' should return an error");
            continue;
        }

        let args: Vec<std::ffi::OsString> = args.expect("args should parse into EntryPoint");

        let args =
            EntryPoint::try_parse_from(args).expect("hardcoded args should parse successfully");

        assert!(args.config.is_none(), "args.config should be none");
        assert!(args.cmd.is_some(), "args.cmd should not be none");
        assert_eq!(
            args.verbose, should_be_verbose,
            "process_cli_args should preserve top-level args"
        );

        assert_eq!(matches!(args.cmd(), ZakuradCmd::Start(_)), should_be_start,);
        if matches!(args.cmd(), ZakuradCmd::NativeIdentity(_)) {
            assert!(!args.cmd().is_server());
            assert!(!args.cmd().uses_intro());
            assert!(!args.cmd().should_ignore_load_config_error());
            assert_eq!(args.cmd().default_tracing_filter(false), "warn");
        }
    }
}
