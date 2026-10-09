use crate::password::password;
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Write},
    path::Path,
};
use zakura_pq_wallet::{
    payment::{Intent, Partial, Proposal, MAX_INPUTS, MAX_PARTIAL, MAX_PROPOSAL},
    read_transfer,
    rpc::LocalRpc,
    write_transfer, Hex, Profile, Wallet, WatchStore,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const USAGE: &str = "Payments (confirmed native PQ, NU7 Regtest):\n\
  pq-wallet propose <profile> <backup> <store> <rpc> <intent.json> <new-proposal>\n\
  pq-wallet propose-preview <profile> <backup> <store> <rpc> <intent.json> <new-proposal>\n\
  pq-wallet review <profile> <backup> <store> <rpc> <intent.json> <proposal>\n\
  pq-wallet change-approve <profile> <backup> <store> <rpc> <intent.json> <proposal> <approved-change-id>\n\
  pq-wallet sign <profile> <backup> <store> <rpc> <intent.json> <proposal> <approved-id> <new-partials-dir>\n\
  pq-wallet assemble <profile> <backup> <store> <rpc> <intent.json> <proposal> <collected-partials-dir>\n\
  pq-wallet submit <profile> <backup> <store> <rpc> <proposal-id>\n\
  pq-wallet payment-archive <profile> <backup> <store> <rpc> <proposal-id>\n\
  pq-wallet payment-resume <profile> <backup> <store> <rpc> <proposal-id>\n\
  pq-wallet refresh-propose <profile> <backup> <store> <rpc> <old-id> <new-proposal>\n\
  pq-wallet refresh-review <profile> <backup> <store> <rpc> <old-id> <new-proposal>\n\
  pq-wallet refresh-approve <profile> <backup> <store> <rpc> <old-id> <new-proposal> <approved-new-id>\n\
  pq-wallet payments <profile> <store> <rpc>\n\
  pq-wallet payment-export <profile> <store> <proposal-id> <new-proposal>\n\
payments lists active records only; payment-history lists dated archive events.\n\
Archive/resume reconcile the trusted node and preserve saved authorizations.\n\
Resuming does not sign or submit. payment-export accepts archived and old IDs.\n\
Intent is independently approved canonical JSON: amount (zatoshis), max_fee,\n\
receiver, remainder (reject|keep|fee), optional version (5|6; default 6).\n\
Only experimental SLH receivers are accepted. The profile/gate is independently\n\
approved; node metadata never enables a wallet gate.\n\
Review every recipient, fee, change and expiry before passing its ID to sign.\n\
Review local_change on each signer. If advancement is present, change-approve\n\
requires that signer's approval_id and durably retires the displayed skipped\n\
range. propose-preview exports without reservations when propose needs a jump.\n\
Each cosigner uses its own backup/store/node. Copy its public partial files into\n\
one collection directory. Submission sends only the durably saved signed bytes.\n\
Refresh changes only tip metadata after renewed local approval; it preserves\n\
effects, expiry, reservations and saved signature/transaction bytes.\n";

pub fn expected(command: &str) -> Option<usize> {
    match command {
        "propose" | "propose-preview" | "review" | "refresh-propose" | "refresh-review" => Some(7),
        "sign" => Some(9),
        "assemble" | "refresh-approve" | "change-approve" => Some(8),
        "submit" | "payment-archive" | "payment-resume" => Some(6),
        "payments" => Some(4),
        "payment-export" => Some(5),
        _ => None,
    }
}
pub(crate) fn id(text: &str) -> Result<Hex<32>> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected a lowercase 64-character approval or proposal ID".into());
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(text, &mut bytes)?;
    Ok(Hex(bytes))
}
pub fn run(args: &[String], profile: Profile) -> Result<()> {
    if matches!(args[0].as_str(), "payments" | "payment-export") {
        let mut store = WatchStore::open(Path::new(&args[2]), &profile)?;
        if args[0] == "payment-export" {
            let expected = id(&args[3])?;
            let record = store.payment_record(expected)?.ok_or("unknown proposal")?;
            write_transfer(Path::new(&args[4]), &record.proposal.to_json()?)?;
        } else {
            store.reconcile_payments(&mut LocalRpc::new(args[3].parse()?)?)?;
            let rows: Vec<_> = store
                .payments()?
                .iter()
                .map(|r| {
                    Ok(serde_json::json!({
                        "proposal_id": hex::encode(r.proposal.id()?.0), "state": r.state,
                        "amount": r.intent.amount, "receiver": r.intent.receiver,
                    }))
                })
                .collect::<std::result::Result<_, zakura_pq_wallet::Error>>()?;
            serde_json::to_writer(io::stdout(), &rows)?;
            writeln!(io::stdout())?;
        }
        return Ok(());
    }
    let password = password("Backup password: ")?;
    let wallet = Wallet::load_backup(Path::new(&args[2]), password.as_bytes(), &profile)?;
    let mut store = WatchStore::open(Path::new(&args[3]), &profile)?;
    let mut rpc = LocalRpc::new(args[4].parse()?)?;
    if matches!(args[0].as_str(), "payment-archive" | "payment-resume") {
        let expected = id(&args[5])?;
        if args[0] == "payment-archive" {
            store.archive_payment(&wallet, &mut rpc, expected)?;
        } else {
            store.resume_payment(&wallet, &mut rpc, expected)?;
        }
        let record = store.payment_record(expected)?.ok_or("unknown proposal")?;
        serde_json::to_writer(
            io::stdout(),
            &serde_json::json!({
                "current_proposal_id": record.current_proposal_id,
                "location": record.location,
                "observation": record.observation,
            }),
        )?;
        writeln!(io::stdout())?;
        return Ok(());
    }
    if args[0] == "submit" {
        let txid = store.submit_payment(&wallet, &mut rpc, id(&args[5])?)?;
        writeln!(io::stdout(), "{}", hex::encode(txid.0))?;
        return Ok(());
    }
    if args[0] == "refresh-propose" {
        let (proposal, review) = store.preview_payment_refresh(&wallet, &mut rpc, id(&args[5])?)?;
        write_transfer(Path::new(&args[6]), &proposal.to_json()?)?;
        serde_json::to_writer(io::stdout(), &review_display(&review, &proposal)?)?;
        writeln!(io::stdout())?;
        return Ok(());
    }
    if matches!(args[0].as_str(), "refresh-review" | "refresh-approve") {
        let proposal = Proposal::from_json(&read_transfer(Path::new(&args[6]), MAX_PROPOSAL)?)?;
        let review = if args[0] == "refresh-review" {
            store.review_payment_refresh(&wallet, &mut rpc, id(&args[5])?, &proposal)?
        } else {
            store.approve_payment_refresh(
                &wallet,
                &mut rpc,
                id(&args[5])?,
                &proposal,
                id(&args[7])?,
            )?
        };
        serde_json::to_writer(io::stdout(), &review_display(&review, &proposal)?)?;
        writeln!(io::stdout())?;
        return Ok(());
    }
    let intent = Intent::from_json(&read_transfer(Path::new(&args[5]), 4096)?)?;
    if matches!(args[0].as_str(), "propose" | "propose-preview") {
        let (proposal, review) = if args[0] == "propose" {
            store.prepare_payment(&wallet, &mut rpc, &intent)?
        } else {
            store.preview_payment(&wallet, &mut rpc, &intent)?
        };
        write_transfer(Path::new(&args[6]), &proposal.to_json()?)?;
        serde_json::to_writer(io::stdout(), &review_display(&review, &proposal)?)?;
        writeln!(io::stdout())?;
        return Ok(());
    }
    let proposal = Proposal::from_json(&read_transfer(Path::new(&args[6]), MAX_PROPOSAL)?)?;
    match args[0].as_str() {
        "change-approve" => {
            let review = store.approve_payment_change(
                &wallet,
                &mut rpc,
                &proposal,
                &intent,
                id(&args[7])?,
            )?;
            serde_json::to_writer(io::stdout(), &review_display(&review, &proposal)?)?;
            writeln!(io::stdout())?;
        }
        "review" => {
            let review = store.review_payment(&wallet, &mut rpc, &proposal, &intent)?;
            serde_json::to_writer(io::stdout(), &review_display(&review, &proposal)?)?;
            writeln!(io::stdout())?;
        }
        "sign" => {
            let partials =
                store.sign_payment(&wallet, &mut rpc, &proposal, &intent, id(&args[7])?)?;
            let directory = Path::new(&args[8]);
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(directory)?;
            for partial in &partials {
                let name = format!(
                    "input-{:04}-signer-{:02}.json",
                    partial.input_index, partial.signer_index
                );
                write_transfer(&directory.join(name), &partial.to_json()?)?;
            }
            fs::File::open(
                directory
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?
            .sync_all()?;
            writeln!(
                io::stdout(),
                "Saved {} partials for the approved proposal.",
                partials.len()
            )?;
        }
        "assemble" => {
            let partials = collect_partials(Path::new(&args[7]), &proposal)?;
            let bytes = store.assemble_payment(&wallet, &mut rpc, &proposal, &intent, &partials)?;
            writeln!(
                io::stdout(),
                "Saved verified transaction ({} bytes). Submit using proposal {}.",
                bytes.len(),
                hex::encode(proposal.id()?.0)
            )?;
        }
        _ => return Err("unknown payment command".into()),
    }
    Ok(())
}

// Add public policy context to the existing approval fields without changing IDs.
fn review_display(
    review: &impl serde::Serialize,
    proposal: &Proposal,
) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(review)?;
    let fields = value.as_object_mut().ok_or("invalid review object")?;
    fields.insert(
        "suite".into(),
        serde_json::json!({"byte":247,"contract":"slh-dsa-b-128s-exp-v1"}),
    );
    fields.insert("profile".into(), serde_json::to_value(&proposal.profile)?);
    let inputs = proposal.inputs.iter().map(|input| {
        Ok(serde_json::json!({"threshold":input.entry.policy()?.threshold(),"origins":input.entry.origins,"policy_hex":input.entry.policy_hex}))
    }).collect::<std::result::Result<Vec<_>, zakura_pq_wallet::Error>>()?;
    fields.insert("input_policies".into(), serde_json::to_value(inputs)?);
    fields.insert(
        "change_policy".into(),
        serde_json::to_value(
            proposal
                .outputs
                .iter()
                .find_map(|output| output.entry.as_ref()),
        )?,
    );
    Ok(value)
}

// Bound directory traversal, every file, and duplicate slots before primitive work.
fn collect_partials(directory: &Path, proposal: &Proposal) -> Result<Vec<Partial>> {
    let thresholds = proposal
        .inputs
        .iter()
        .map(|input| input.entry.policy().map(|p| usize::from(p.threshold())))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let limit = thresholds.iter().sum::<usize>();
    if limit == 0 || limit > MAX_INPUTS * 15 {
        return Err("invalid partial allowance".into());
    }
    let approved_id = proposal.id()?;
    let mut slots = BTreeSet::new();
    let mut counts = vec![0usize; thresholds.len()];
    let mut partials = Vec::new();
    for item in fs::read_dir(directory)? {
        if partials.len() == limit {
            return Err("too many partials for the approved thresholds".into());
        }
        let partial = Partial::from_json(&read_transfer(&item?.path(), MAX_PARTIAL)?)?;
        let input =
            usize::try_from(partial.input_index).map_err(|_| "partial input is out of range")?;
        let policy = proposal
            .inputs
            .get(input)
            .ok_or("partial input is out of range")?
            .entry
            .policy()?;
        if partial.proposal_id != approved_id
            || usize::from(partial.signer_index) >= policy.commitments().len()
            || !slots.insert((partial.input_index, partial.signer_index))
        {
            return Err("partial proposal, signer index or duplicate slot mismatch".into());
        }
        counts[input] += 1;
        if counts[input] > thresholds[input] {
            return Err("too many partials for one input".into());
        }
        partials.push(partial);
    }
    if counts != thresholds {
        return Err("not enough distinct partials for every input threshold".into());
    }
    Ok(partials)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_pq_wallet::Origin;
    #[test]
    fn collected_files_obey_fifteen_of_fifteen_quorum_and_duplicate_bounds() {
        let corpus: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../tests/slh-dsa-b128s/wallet/formats/vectors.json"
        ))
        .unwrap();
        let mut proposal = Proposal::from_json(
            corpus["proposals"][1]["proposal_json"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let policy =
            zakura_pq_slh_dsa_b_exp::Policy::new(15, (0..15).map(|i| [i; 32]).collect()).unwrap();
        proposal.inputs[0].entry.policy_hex = hex::encode(policy.encode());
        proposal.inputs[0].entry.origins = (0..15)
            .map(|i| Origin {
                account: 0,
                index: 0,
                wallet_id: Hex([i; 16]),
            })
            .collect();
        let mut output = 100_000u64.to_le_bytes().to_vec();
        output.push(35);
        output.extend_from_slice(policy.lock_script().as_raw_bytes());
        proposal.inputs[0].spent_output_hex = hex::encode(output);
        let mut partial =
            Partial::from_json(corpus["partial_json"].as_str().unwrap().as_bytes()).unwrap();
        partial.input_index = 0;
        partial.proposal_id = proposal.id().unwrap();
        let display = review_display(
            &serde_json::json!({"proposal_id":proposal.id().unwrap(),"fee":1234}),
            &proposal,
        )
        .unwrap();
        assert_eq!(
            display["proposal_id"],
            hex::encode(proposal.id().unwrap().0)
        );
        assert_eq!(display["fee"], 1234);
        assert_eq!(display["suite"]["byte"], 247);
        assert_eq!(display["input_policies"][0]["threshold"], 15);
        assert_eq!(
            display["input_policies"][0]["origins"]
                .as_array()
                .unwrap()
                .len(),
            15
        );
        assert_eq!(
            display["profile"],
            serde_json::to_value(&proposal.profile).unwrap()
        );
        let dir = tempfile::tempdir().unwrap();
        for i in 0..15 {
            partial.signer_index = i;
            write_transfer(
                &dir.path().join(format!("{i}.json")),
                &partial.to_json().unwrap(),
            )
            .unwrap();
            if i < 14 {
                assert!(collect_partials(dir.path(), &proposal).is_err());
            }
        }
        assert_eq!(collect_partials(dir.path(), &proposal).unwrap().len(), 15);
        fs::remove_file(dir.path().join("0.json")).unwrap();
        write_transfer(
            &dir.path().join("duplicate.json"),
            &partial.to_json().unwrap(),
        )
        .unwrap();
        assert!(collect_partials(dir.path(), &proposal)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
        fs::remove_file(dir.path().join("duplicate.json")).unwrap();
        write_transfer(
            &dir.path().join("oversized.json"),
            &vec![b' '; MAX_PARTIAL + 1],
        )
        .unwrap();
        assert!(collect_partials(dir.path(), &proposal).is_err());
    }
}
