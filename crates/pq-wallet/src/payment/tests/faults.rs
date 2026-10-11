//! Human-only process adapter over existing private durable checkpoints.
//! The ordinary test suite compiles this driver but never executes its signing,
//! backup, snapshot, injected-I/O or process-interruption matrix.
use super::*;
use crate::{journal, recovery, storage, watch::StateStage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{Duration, Instant},
};

const PASSWORD: &[u8] = b"disposable human fault fixture only";
const LIMIT: u64 = 2 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    directory: PathBuf,
    token: String,
    case: String,
    stage: String,
    mode: String,
    phase: String,
}
impl Request {
    fn validate(&self) {
        assert!(self.directory.is_absolute());
        assert_eq!(fs::canonicalize(&self.directory).unwrap(), self.directory);
        assert_eq!(
            fs::metadata(&self.directory).unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(self.token.len(), 32);
        assert!(self
            .token
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert!(matches!(self.mode.as_str(), "positive" | "io" | "kill"));
        assert!(matches!(self.phase.as_str(), "prepare" | "run" | "reopen"));
        let stages: &[&str] = match self.case.as_str() {
            "migration" => &[
                "CreateJournal",
                "CreateObjects",
                "ObjectsSync",
                "JournalSync",
                "WatchSync",
                "ObjectWrite",
                "ObjectVerify",
                "ObjectSync",
                "ObjectPublish",
                "ObjectsSyncAfterPublish",
                "RecoveryWrite",
                "RecoveryVerify",
                "RecoverySync",
                "RecoveryPublish",
                "RecoveryDirectorySync",
                "FileWrite",
                "FileSync",
                "Publish",
                "DirectorySync",
            ],
            "receive" => &["FileWrite", "FileSync", "Publish", "DirectorySync"],
            "backup" => &["Write", "FileSync", "Verify", "Publish", "DirectorySync"],
            "entropy" | "final-publication" => &["BeforeSign"],
            "quota" => &["QuotaPreflight"],
            _ => panic!("unknown fault case"),
        };
        assert!(stages.contains(&self.stage.as_str()));
        assert!(
            self.mode != "kill" || matches!(self.case.as_str(), "migration" | "receive" | "backup")
        );
    }
    fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }
    fn receipt(&self, event: &str, checks: &[&str]) {
        let state = self.path("watch/state.json");
        let state = if state.exists() {
            state
        } else {
            self.path("relocated/state.json")
        };
        let value = serde_json::json!({
            "schema_version": 1, "token": self.token, "case": self.case,
            "stage": self.stage, "mode": self.mode, "phase": self.phase,
            "pid": std::process::id(), "event": event,
            "state_sha256": hash(&read(&state)), "checks": checks,
        });
        let temporary = self.path(&format!(".{}-{event}.tmp", self.phase));
        write(&temporary, &serde_json::to_vec(&value).unwrap());
        fs::rename(
            temporary,
            self.path(&format!("{}-{event}.json", self.phase)),
        )
        .unwrap();
        fs::File::open(&self.directory).unwrap().sync_all().unwrap();
    }
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn read(path: &Path) -> Vec<u8> {
    let meta = fs::symlink_metadata(path).unwrap();
    assert!(meta.is_file() && meta.len() <= LIMIT);
    assert_eq!(meta.permissions().mode() & 0o077, 0);
    fs::read(path).unwrap()
}
fn write(path: &Path, bytes: &[u8]) {
    assert!(bytes.len() as u64 <= LIMIT);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}
fn saved<T: Serialize>(request: &Request, name: &str, value: &T) {
    write(&request.path(name), &serde_json::to_vec(value).unwrap());
}
fn records(store: &WatchStore) -> Vec<u8> {
    serde_json::to_vec(store.payments().unwrap()).unwrap()
}
fn prepare(request: &Request) {
    let owners = wallets(1, 3, 2);
    let wallet = &owners[0];
    let mut source = Source::funded(wallet, &[2_000_000]);
    let mut store = create(
        &request.path("watch"),
        wallet.manifest(),
        WatchMode::Allocator,
    );
    store.receive().unwrap();
    let approved = intent(6);
    let (proposal, _) = store
        .prepare_payment(wallet, &mut source, &approved)
        .unwrap();
    assert_eq!(store.receive_next(), 1);
    assert_eq!(store.state.payments.change_next, 1);
    if !matches!(request.case.as_str(), "entropy" | "final-publication") {
        let partials = store
            .sign_payment(
                wallet,
                &mut source,
                &proposal,
                &approved,
                proposal.id().unwrap(),
            )
            .unwrap();
        store
            .assemble_payment(wallet, &mut source, &proposal, &approved, &partials)
            .unwrap();
    }
    wallet
        .save_backup(&request.path("backup.tpq"), PASSWORD)
        .unwrap();
    write(&request.path("proposal.json"), &proposal.to_json().unwrap());
    write(&request.path("intent.json"), &approved.to_json().unwrap());
    write(&request.path("records.json"), &records(&store));
    write(
        &request.path("before.json"),
        &read(&request.path("watch/state.json")),
    );
    saved(
        request,
        "backup-hash.json",
        &hash(&read(&request.path("backup.tpq"))),
    );
    request.receipt(
        "complete",
        &[
            "eligible_prepared_payment",
            "reserved_input_and_change",
            "covering_backup",
        ],
    );
}

struct Hook<'a> {
    request: &'a Request,
    reached: bool,
    objects_sync: usize,
}
impl<'a> Hook<'a> {
    fn new(request: &'a Request) -> Self {
        Self {
            request,
            reached: false,
            objects_sync: 0,
        }
    }
    fn state(&mut self, stage: StateStage) -> Result<(), Error> {
        let mut name = match stage {
            StateStage::Journal(stage) => format!("{stage:?}"),
            _ => format!("{stage:?}"),
        };
        if name == "ObjectsSync" {
            self.objects_sync += 1;
            if self.objects_sync == 2 {
                name = "ObjectsSyncAfterPublish".into();
            }
        }
        self.at(&name)
    }
    fn at(&mut self, name: &str) -> Result<(), Error> {
        if self.reached || name != self.request.stage {
            return Ok(());
        }
        self.reached = true;
        self.request.receipt("reached", &["named_stage_reached"]);
        match self.request.mode.as_str() {
            "positive" => Ok(()),
            "io" => Err(Error::Storage(std::io::Error::other(
                "private human fault checkpoint",
            ))),
            "kill" => {
                let start = Instant::now();
                while start.elapsed() < Duration::from_secs(45) {
                    std::thread::sleep(Duration::from_millis(25));
                }
                panic!("controller did not interrupt reached process within deadline");
            }
            _ => unreachable!(),
        }
    }
}

struct BeforeSign<'a> {
    hook: Hook<'a>,
    calls: usize,
}
impl CryptoRng for BeforeSign<'_> {}
impl RngCore for BeforeSign<'_> {
    fn next_u32(&mut self) -> u32 {
        panic!("fallible byte request required")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("fallible byte request required")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("fallible byte request required")
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.calls += 1;
        assert_eq!(self.calls, 1);
        if self.hook.request.case == "final-publication" && self.hook.request.mode == "io" {
            // As in the pinned final-publication regression: scanning and reservation
            // are already durable; the final commit's original path is now absent.
            assert!(
                fs::rename(
                    self.hook.request.path("watch"),
                    self.hook.request.path("relocated"),
                )
                .is_ok(),
                "private prepared watcher must relocate successfully"
            );
            self.hook
                .request
                .receipt("reached", &["named_stage_reached"]);
            self.hook.reached = true;
        } else if self.hook.at("BeforeSign").is_err() {
            return Err(rand_core::Error::from(
                std::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            ));
        }
        rand_core::OsRng.try_fill_bytes(bytes)
    }
}
// Cache proof: a saved authorization must not request another pre-sign checkpoint.
struct RefuseEntropy(usize);
impl CryptoRng for RefuseEntropy {}
impl RngCore for RefuseEntropy {
    fn next_u32(&mut self) -> u32 {
        panic!("fallible byte request required")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("fallible byte request required")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("fallible byte request required")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0 += 1;
        Err(rand_core::Error::from(
            std::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
        ))
    }
}

fn quota(request: &Request, store: &mut WatchStore) {
    use journal::{Batch, Entry, Journal, Key, Kind, Limits, ReadBudget, Snapshot, Value};
    let id = Hex([7; 16]);
    let entry = Entry {
        key: Key::id(Hex([2; 32])),
        value: Value::Alias {
            capability: Hex([3; 32]),
            lineage_id: Hex([2; 32]),
            revision: 0,
        },
    };
    let limits = Limits {
        bytes: if request.mode == "io" {
            1
        } else {
            Limits::default().bytes
        },
        ..Limits::default()
    };
    let mut journal = Journal::create(store, id, limits, |_| Ok(())).unwrap();
    let mut batch = Batch::new(id);
    let snapshot = journal
        .insert(
            &mut batch,
            &Snapshot::empty(id, Kind::Aliases),
            entry.clone(),
            &mut ReadBudget::new(4096).unwrap(),
        )
        .unwrap();
    request.receipt("reached", &["named_stage_reached"]);
    let mut writes = 0;
    let result = journal.publish(&batch, |_| {
        writes += 1;
        Ok(())
    });
    if request.mode == "io" {
        assert!(matches!(result, Err(journal::Error::Quota)));
        assert_eq!(writes, 0);
    } else {
        result.unwrap();
        assert!(writes > 0);
    }
    // File-level evidence: the refused preflight leaves no object or temporary file.
    assert_eq!(
        fs::read_dir(request.path("watch/journal/objects"))
            .unwrap()
            .next()
            .is_none(),
        request.mode == "io"
    );
    drop(journal);
    // Sanity check only: journal publication never writes the wallet root in
    // either mode, so this comparison does not distinguish them.
    assert_eq!(
        read(&request.path("watch/state.json")),
        read(&request.path("before.json"))
    );
    // Reopening with the ordinary quota retries the exact staged object, with no
    // ad hoc edits to the authoritative wallet descriptor or production quotas.
    let mut journal = Journal::open(store, id, Limits::default()).unwrap();
    journal.publish(&batch, |_| Ok(())).unwrap();
    assert_eq!(
        journal
            .get(&snapshot, &entry.key, &mut ReadBudget::new(4096).unwrap())
            .unwrap(),
        Some(entry.value)
    );
}

fn run(request: &Request) {
    let wallet = Wallet::load_backup(&request.path("backup.tpq"), PASSWORD, &profile()).unwrap();
    let mut store = WatchStore::open(&request.path("watch"), &profile()).unwrap();
    assert_eq!(records(&store), read(&request.path("records.json")));
    let mut hook = Hook::new(request);
    match request.case.as_str() {
        "migration" | "receive" | "backup" => {
            let result = match request.case.as_str() {
                "migration" => store.migrate_journal_with_hook(|stage| hook.state(stage)),
                "receive" => store
                    .fault_receive_with_hook(|stage| hook.state(stage))
                    .map(|_| ()),
                "backup" => wallet.save_with_hook(
                    &request.path("backup-next.tpq"),
                    PASSWORD,
                    |stage: storage::Stage| hook.at(&format!("{stage:?}")),
                ),
                _ => unreachable!(),
            };
            assert!(hook.reached);
            if request.mode == "positive" {
                result.unwrap();
            } else {
                assert!(matches!(result, Err(Error::Storage(_))));
                if request.case != "backup" {
                    assert!(matches!(store.payments(), Err(Error::ReopenRequired)));
                }
            }
        }
        "entropy" | "final-publication" => {
            let mut source = Source::funded(&wallet, &[2_000_000]);
            let proposal = Proposal::from_json(&read(&request.path("proposal.json"))).unwrap();
            let approved = Intent::from_json(&read(&request.path("intent.json"))).unwrap();
            let mut rng = BeforeSign { hook, calls: 0 };
            let result = store.sign_payment_with_rng(
                &wallet,
                &mut source,
                &proposal,
                &approved,
                proposal.id().unwrap(),
                &mut rng,
            );
            assert!(rng.hook.reached);
            assert_eq!(rng.calls, 1);
            if request.mode == "positive" {
                assert_eq!(result.unwrap().len(), 1);
            } else if request.case == "entropy" {
                assert!(matches!(result, Err(Error::Entropy)));
            } else {
                assert!(matches!(result, Err(Error::Storage(_))));
                assert!(matches!(store.payments(), Err(Error::ReopenRequired)));
            }
            assert!(source.sent.is_empty());
        }
        "quota" => quota(request, &mut store),
        _ => unreachable!(),
    }
    request.receipt(
        "complete",
        &[if request.mode == "positive" {
            "operation_succeeded"
        } else {
            "exact_fault_error"
        }],
    );
}

fn reopen(request: &Request) {
    let wallet = Wallet::load_backup(&request.path("backup.tpq"), PASSWORD, &profile()).unwrap();
    let expected_backup: String =
        serde_json::from_slice(&read(&request.path("backup-hash.json"))).unwrap();
    assert_eq!(hash(&read(&request.path("backup.tpq"))), expected_backup);
    let path = if request.path("watch").exists() {
        request.path("watch")
    } else {
        request.path("relocated")
    };
    let mut store = WatchStore::open(&path, &profile()).unwrap();
    let published = request.mode == "positive" || request.stage == "DirectorySync";
    if request.case == "receive" {
        assert_eq!(store.receive_next(), if published { 2 } else { 1 });
    } else {
        assert_eq!(store.receive_next(), 1);
    }
    assert_eq!(store.state.payments.change_next, 1);
    let was_signed = !matches!(request.case.as_str(), "entropy" | "final-publication");
    if was_signed || request.mode != "positive" {
        assert_eq!(records(&store), read(&request.path("records.json")));
    }
    if request.case == "migration" {
        assert_eq!(store.state.journal.is_some(), published);
        if !published {
            assert_eq!(
                read(&path.join("state.json")),
                read(&request.path("before.json"))
            );
        }
        store.migrate_payment_journal().unwrap();
        assert!(fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("state-pre-v3-")
                && read(&entry.path()) == read(&request.path("before.json"))));
    }
    if request.case == "backup" {
        assert_eq!(request.path("backup-next.tpq").exists(), published);
        if published {
            let next = Wallet::load_backup(&request.path("backup-next.tpq"), PASSWORD, &profile())
                .unwrap();
            assert_eq!(next.manifest(), wallet.manifest());
        }
    }
    let proposal = Proposal::from_json(&read(&request.path("proposal.json"))).unwrap();
    let approved = Intent::from_json(&read(&request.path("intent.json"))).unwrap();
    let mut source = Source::funded(&wallet, &[2_000_000]);
    let before = store.payments().unwrap()[0].clone();
    let partials = store
        .sign_payment(
            &wallet,
            &mut source,
            &proposal,
            &approved,
            proposal.id().unwrap(),
        )
        .unwrap();
    if was_signed {
        assert_eq!(partials, before.partials);
    }
    let mut refuse = RefuseEntropy(0);
    assert_eq!(
        store
            .sign_payment_with_rng(
                &wallet,
                &mut source,
                &proposal,
                &approved,
                proposal.id().unwrap(),
                &mut refuse
            )
            .unwrap(),
        partials
    );
    assert_eq!(refuse.0, 0);
    let signed = store
        .assemble_payment(&wallet, &mut source, &proposal, &approved, &partials)
        .unwrap();
    if was_signed {
        assert_eq!(
            before.signed_transaction_hex.as_deref(),
            Some(hex::encode(&signed).as_str())
        );
    }
    assert_eq!(store.state.payments.change_next, 1);
    let mut conflicting = approved.clone();
    conflicting.amount += 1;
    assert!(matches!(
        store.prepare_payment(&wallet, &mut source, &conflicting),
        Err(Error::Funds)
    ));
    source.journal = Some(path.join("state.json"));
    source.fail_submit = true;
    // The public API records uncertainty before submission and wraps the
    // synthetic source's transport error, as in the retained retry tests.
    assert!(matches!(
        store.submit_payment(&wallet, &mut source, proposal.id().unwrap()),
        Err(Error::SubmissionUnknown)
    ));
    assert_eq!(
        store.payments().unwrap()[0].state,
        PaymentState::SubmissionUnknown
    );
    source.fail_submit = false;
    store
        .submit_payment(&wallet, &mut source, proposal.id().unwrap())
        .unwrap();
    assert_eq!(source.sent, [signed.clone(), signed]);
    let next_index = store.receive_next();
    let receiver = store.receive().unwrap();
    let expected = wallet
        .manifest()
        .entries
        .iter()
        .find(|entry| {
            entry.role == 0
                && entry.local(wallet.manifest().wallet_id).unwrap().1.index as u64 == next_index
        })
        .unwrap()
        .receiver()
        .unwrap();
    assert_eq!(receiver, expected);
    assert_eq!(store.receive_next(), next_index + 1);
    // Snapshot authority is explicitly unknown. Do not promote based on a
    // self-created receipt or keep two allocators available after recovery.
    let saved_records = records(&store);
    store
        .save_operational_snapshot(
            &request.path("backup.tpq"),
            PASSWORD,
            &request.path("snapshot"),
        )
        .unwrap();
    drop(store);
    fs::remove_dir_all(&path).unwrap();
    let restored = recovery::restore_operational_snapshot(
        &request.path("snapshot"),
        PASSWORD,
        &profile(),
        recovery::SnapshotTrust::Unknown,
        &request.path("restored"),
    )
    .unwrap();
    let mut restored = restored.watch;
    assert_eq!(records(&restored), saved_records);
    assert_eq!(restored.mode(), WatchMode::Monitor);
    assert!(matches!(restored.receive(), Err(Error::MonitorOnly)));
    assert!(!restored.status().unwrap().complete_at_checkpoint);
    drop(restored);
    // Receipt state is now the actual restored state, without retaining private
    // snapshots or executable output outside the controller's disposable tree.
    fs::rename(request.path("restored/watch"), request.path("watch")).unwrap();
    request.receipt(
        "complete",
        &[
            "old_or_complete_new",
            "cached_authorization_exact",
            "retry_exact",
            "reservation_retained",
            "no_cursor_reuse",
            "unknown_snapshot_monitor",
        ],
    );
}

#[test]
#[ignore = "human-only durable fault/signing/backup/snapshot process driver"]
fn human_fault_case() {
    let path = PathBuf::from(
        std::env::var_os("SLH_WALLET_FAULT_REQUEST").expect("human controller request required"),
    );
    let request: Request = serde_json::from_slice(&read(&path)).unwrap();
    request.validate();
    assert_eq!(path.parent().unwrap(), request.directory);
    match request.phase.as_str() {
        "prepare" => prepare(&request),
        "run" => run(&request),
        "reopen" => reopen(&request),
        _ => unreachable!(),
    }
}
