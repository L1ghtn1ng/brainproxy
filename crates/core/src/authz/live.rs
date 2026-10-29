//! Live mode: while the proxy runs, each in-scope request it records that carries
//! credentials, uses a safe method and isn't a logout is also tested in the background
//! as other identities, all under one authz run. Proxied traffic never waits for it:
//! requests go through a bounded queue and are dropped (and counted) when it is full,
//! and each method, URL and body is tested once.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use regex::Regex;
use serde_json::{json, Value};
use tokio::sync::{oneshot, Semaphore};
use tokio::task::JoinSet;

use super::{has_credentials, AuthzConfig, AuthzTarget, Outcome, Recorder, Tester, SAFE_METHODS};
use crate::auth::AuthProfile;
use crate::error::{Error, Result};
use crate::http::{RawRequest, Target};
use crate::jobs::JobControl;

/// How long tests already under way may finish once the proxy stops.
const GRACE: Duration = Duration::from_secs(2);

pub struct LiveOptions {
    /// Requests waiting to be tested at most; more are dropped.
    pub queue: usize,
    /// Requests tested at once.
    pub concurrency: usize,
    /// Paths not tested (logging out would end the owner's session).
    pub exclude: Regex,
}

#[derive(Default)]
struct Counts {
    offered: AtomicU64,
    queued: AtomicU64,
    tested: AtomicU64,
    dropped: AtomicU64,
    duplicates: AtomicU64,
    methods: AtomicU64,
    excluded: AtomicU64,
    no_credentials: AtomicU64,
}

/// What the proxy offers recorded requests to. `offer` never blocks.
pub struct Live {
    run_id: i64,
    tx: tokio::sync::mpsc::Sender<AuthzTarget>,
    seen: Mutex<HashSet<u64>>,
    exclude: Regex,
    profiles: Vec<AuthProfile>,
    counts: Counts,
    tester: Arc<Tester>,
    ctl: JobControl,
}

/// The background worker; `finish` ends it once the proxy has stopped.
pub struct LiveWorker {
    live: Arc<Live>,
    task: tokio::task::JoinHandle<()>,
    shutdown: oneshot::Sender<()>,
    writer: std::thread::JoinHandle<Result<Recorder>>,
}

impl Live {
    /// Starts testing in the background under `run_id` (a job of kind `authz`). Needs a
    /// tokio runtime.
    pub fn start(
        project: &Path,
        run_id: i64,
        cfg: AuthzConfig,
        opts: LiveOptions,
        ctl: JobControl,
    ) -> Result<(Arc<Live>, LiveWorker)> {
        let tester = Arc::new(Tester::new(cfg, ctl.clone())?);
        let (tx, rx) = tokio::sync::mpsc::channel(opts.queue.max(1));
        let live = Arc::new(Live {
            run_id,
            tx,
            seen: Mutex::default(),
            exclude: opts.exclude,
            profiles: tester.profiles(),
            counts: Counts::default(),
            tester,
            ctl,
        });
        let (out_tx, out_rx) = mpsc::channel::<Outcome>();
        let mut recorder = Recorder::open(project, run_id)?;
        let writer = std::thread::spawn(move || -> Result<Recorder> {
            while let Ok(o) = out_rx.recv() {
                recorder.record(&o)?;
            }
            Ok(recorder)
        });
        let (shutdown, stop_rx) = oneshot::channel();
        let task = tokio::spawn(work(live.clone(), rx, out_tx, opts.concurrency.max(1), stop_rx));
        live.progress();
        Ok((live.clone(), LiveWorker { live, task, shutdown, writer }))
    }

    pub fn run_id(&self) -> i64 {
        self.run_id
    }

    /// Queues a recorded request for testing unless it is one not to test, already
    /// tested, or the queue is full.
    pub fn offer(&self, history_id: i64, target: &Target, request: &[u8]) {
        if self.ctl.stopped() {
            return;
        }
        let c = &self.counts;
        c.offered.fetch_add(1, Ordering::Relaxed);
        let raw = RawRequest::from_bytes(request.to_vec());
        let Ok(head) = raw.head() else { return };
        let method = head.method.to_ascii_uppercase();
        let path = head.target.split('?').next().unwrap_or("/");
        let skip = if !SAFE_METHODS.contains(&method.as_str()) {
            Some(&c.methods)
        } else if self.exclude.is_match(path) {
            Some(&c.excluded)
        } else if !has_credentials(request, &self.profiles) {
            Some(&c.no_credentials)
        } else {
            None
        };
        if let Some(n) = skip {
            n.fetch_add(1, Ordering::Relaxed);
            self.progress();
            return;
        }
        let key = {
            let mut h = DefaultHasher::new();
            (target.origin(), &method, &head.target, raw.body()).hash(&mut h);
            h.finish()
        };
        if !self.seen.lock().unwrap().insert(key) {
            c.duplicates.fetch_add(1, Ordering::Relaxed);
            self.progress();
            return;
        }
        let t = AuthzTarget { history_id: Some(history_id), target: target.clone(), request: request.to_vec() };
        if self.tx.try_send(t).is_ok() {
            c.queued.fetch_add(1, Ordering::Relaxed);
        } else {
            // Not tested, so a later copy may be.
            c.dropped.fetch_add(1, Ordering::Relaxed);
            self.seen.lock().unwrap().remove(&key);
        }
        self.progress();
    }

    /// Counts so far, as stored in the job's progress.
    pub fn stats(&self) -> Value {
        let c = &self.counts;
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let queued = n(&c.queued);
        let tested = n(&c.tested);
        json!({
            "identities": self.tester.identities(),
            "offered": n(&c.offered),
            "queued": queued,
            "tested": tested,
            "waiting": queued.saturating_sub(tested),
            "dropped_queue_full": n(&c.dropped),
            "duplicates": n(&c.duplicates),
            "skipped_methods": n(&c.methods),
            "skipped_excluded_paths": n(&c.excluded),
            "skipped_no_credentials": n(&c.no_credentials),
            "sent": self.tester.sent(),
        })
    }

    fn progress(&self) {
        self.ctl.set_progress(self.stats());
    }
}

async fn work(
    live: Arc<Live>,
    mut rx: tokio::sync::mpsc::Receiver<AuthzTarget>,
    out: mpsc::Sender<Outcome>,
    concurrency: usize,
    mut shutdown: oneshot::Receiver<()>,
) {
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut tests = JoinSet::new();
    loop {
        let t = tokio::select! {
            t = rx.recv() => match t { Some(t) => t, None => break },
            _ = &mut shutdown => break,
        };
        let permit = tokio::select! {
            p = sem.clone().acquire_owned() => p.expect("the semaphore is never closed"),
            _ = &mut shutdown => break,
        };
        let (live, out) = (live.clone(), out.clone());
        tests.spawn(async move {
            let _permit = permit;
            if live.ctl.stopped() {
                return;
            }
            let outcome = live.tester.test(&t).await;
            let _ = out.send(outcome);
            live.counts.tested.fetch_add(1, Ordering::Relaxed);
            live.progress();
        });
        while tests.try_join_next().is_some() {}
    }
    // Requests still queued are left untested; tests under way get a moment to finish.
    let deadline = tokio::time::sleep(GRACE);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            next = tests.join_next() => if next.is_none() { break },
            _ = &mut deadline => {
                tests.abort_all();
                break;
            }
        }
    }
}

impl LiveWorker {
    /// Ends the worker (call once the proxy no longer offers requests) and returns the
    /// run's summary.
    pub async fn finish(self) -> Result<Value> {
        let _ = self.shutdown.send(());
        let _ = self.task.await;
        let live = self.live;
        let mut v = live.stats();
        // The tests hold the senders to the writer; with the worker gone, it ends.
        let recorder = tokio::task::spawn_blocking(move || self.writer.join())
            .await
            .map_err(|e| Error::Protocol(e.to_string()))?
            .map_err(|_| Error::Protocol("authz writer panicked".into()))??;
        v["run_id"] = json!(live.run_id);
        v["verdicts"] = json!(recorder.verdicts());
        v["new_findings"] = json!(recorder.new_findings());
        v["stopped"] = json!(live.ctl.stopped());
        live.progress();
        Ok(v)
    }
}
