//! Opt-in observation of synchronous verification on the current worker thread,
//! for bounded tests. Callbacks observe real operations; they
//! cannot replace their results.

use std::{cell::RefCell, sync::Arc};

/// Events at successful reservation and actual backend verification boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// The caller successfully reserved this many checks for one input.
    Reserved {
        /// Number of signature checks granted by the reservation callback.
        checks: usize,
    },
    /// An SLH-DSA-B-128s primitive verification is starting.
    CryptoStarted,
    /// The backend returned this verification result.
    CryptoFinished {
        /// Whether the backend accepted the signature.
        valid: bool,
    },
}

pub(crate) type Callback = Arc<dyn Fn(Event) + Send + Sync>;
thread_local! {
    static OBSERVER: RefCell<Option<Callback>> = const { RefCell::new(None) };
}

/// Observe only synchronous work on this thread, restoring any prior observer
/// on return or unwind. Reserved checks carry the observer to other workers.
pub fn observe<R>(callback: Callback, work: impl FnOnce() -> R) -> R {
    struct Restore(Option<Callback>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OBSERVER.with(|observer| observer.replace(self.0.take()));
        }
    }
    let _restore = Restore(OBSERVER.with(|observer| observer.replace(Some(callback))));
    work()
}

/// The observer installed on this thread, if any.
pub(crate) fn current() -> Option<Callback> {
    OBSERVER.with(|observer| observer.borrow().clone())
}

pub(crate) fn emit(event: Event) {
    // Do not hold the RefCell borrow while invoking a potentially nested scope.
    if let Some(callback) = current() {
        callback(event);
    }
}
