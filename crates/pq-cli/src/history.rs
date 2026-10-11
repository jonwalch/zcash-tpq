use crate::payments::id;
use std::{
    io::{self, Write},
    ops::RangeInclusive,
    path::Path,
};
use zakura_pq_wallet::{Profile, WatchStore};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const USAGE: &str = "Saved payment history (no backup password or node required):\n\
  pq-wallet payment-history <profile> <store> [limit=16] [cursor]\n\
  pq-wallet payment-history-export <profile> <store> <proposal-id> <new-directory>\n\
History returns dated archival events in pages of 1..16. Pass next_cursor with\n\
the same store to continue; restart from the first page if the journal changes.\n\
Archive observations may be reversed by reorgs; they do not release reservations.\n\
Exports include the exact proposal, saved local partials and saved signed bytes.\n\
An old ID exports its own saved version; current_proposal_id names the latest.\n\
Exports contain public authorization data, not backup keys or signing approval.\n\
A failed export may leave an incomplete directory; use a new path for retries.\n";

pub fn expected(command: &str) -> Option<RangeInclusive<usize>> {
    match command {
        "payment-history" => Some(3..=5),
        "payment-history-export" => Some(5..=5),
        _ => None,
    }
}
fn page_arguments(args: &[String]) -> Result<(usize, Option<&str>)> {
    let limit = args
        .get(3)
        .map(|s| s.parse::<usize>())
        .transpose()?
        .unwrap_or(16);
    if !(1..=16).contains(&limit) {
        return Err("history limit must be 1 through 16".into());
    }
    Ok((limit, args.get(4).map(String::as_str)))
}
pub fn run(args: &[String], profile: Profile) -> Result<()> {
    if args[0] == "payment-history" {
        let (limit, cursor) = page_arguments(args)?;
        let mut store = WatchStore::open(Path::new(&args[2]), &profile)?;
        let page = store.payment_history(limit, cursor)?;
        serde_json::to_writer(io::stdout(), &page)?;
        writeln!(io::stdout())?;
    } else {
        let proposal_id = id(&args[3])?;
        let mut store = WatchStore::open(Path::new(&args[2]), &profile)?;
        store.export_payment_history(proposal_id, Path::new(&args[4]))?;
        writeln!(io::stdout(), "Saved payment export.")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paging_and_mutating_commands_have_distinct_bounded_arguments() {
        let mut args = vec!["payment-history".into(), "profile".into(), "store".into()];
        assert_eq!(page_arguments(&args).unwrap(), (16, None));
        for value in ["0", "17", "-1", "18446744073709551616"] {
            args.push(value.into());
            assert!(page_arguments(&args).is_err());
            args.pop();
        }
        args.extend(["2".into(), "cursor".into()]);
        assert_eq!(page_arguments(&args).unwrap(), (2, Some("cursor")));
        for n in 0..8 {
            assert_eq!(
                expected("payment-history").unwrap().contains(&n),
                (3..=5).contains(&n)
            );
        }
        assert_eq!(expected("payment-history-export"), Some(5..=5));
        for command in ["payment-archive", "payment-resume"] {
            assert_eq!(crate::payments::expected(command), Some(6));
            assert_eq!(expected(command), None);
        }
    }
}
