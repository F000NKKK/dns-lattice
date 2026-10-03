//! The pipelined engine behind the connection-reusing stream backends
//! ([`super::TcpBackend`] and the DoT backend).
//!
//! RFC 7766 §6.2.1.1 and RFC 7858 §3.3 allow a client to send several queries
//! on one connection without waiting for the answers, and a server to answer
//! them in any order. This engine does exactly that on top of the connection
//! [`Pool`](super::pool::Pool): every pooled connection runs one reader task
//! and one writer task, and many callers share it.
//!
//! # How a query travels
//!
//! 1. The caller encodes its query once and asks the pool for a lease.
//! 2. Registration is one synchronous step under the connection's lock: the
//!    connection picks a wire id that no pending or cancelled query uses,
//!    records the caller's waiter under it and queues the complete frame for
//!    the writer. The caller's own message id is never sent; it is restored on
//!    the answer. Nothing is half written by a caller, because only the
//!    writer task touches the socket, so a caller dropped at any `.await`
//!    leaves, at worst, an *orphan* (a tombstone that keeps its wire id
//!    reserved) and never a corrupt stream.
//! 3. The reader task assembles length-prefixed frames, looks the wire id up
//!    and hands the decoded message to the waiter. The caller then checks that
//!    the answer has the `QR` bit and the question it asked.
//!
//! # Failure handling
//!
//! - A frame whose id is pending but whose question does not match fails only
//!   that caller with [`Error::Transport`]; the framing is intact and the
//!   connection stays.
//! - A frame whose id matches nothing is dropped and counted. A late answer to
//!   a cancelled query is *not* unsolicited (the orphan recognises it), but one
//!   whose orphan was evicted or never existed is. The connection is closed
//!   after more than [`UNSOLICITED_LIMIT`] unsolicited frames in a row: the
//!   allowance is refilled by every frame that answers a pending query, and
//!   grows by one for every query that was cancelled or timed out (its late
//!   answer may legitimately arrive after its orphan was evicted), so a
//!   cancellation storm cannot close a healthy connection and the count is not
//!   cumulative over the connection's life.
//! - A frame that does not decode, a read or write error, or the peer closing
//!   the connection ends it: every waiter is failed and the pool stops using it.
//! - Three queries in a row that hit their deadline with no answer in between
//!   mark the connection dead (half-open detection), see the pool.
//!
//! # Retry rule
//!
//! A query is sent again, once, on a fresh connection, if and only if the
//! connection it failed on had already answered a query (so a stale pooled
//! connection is plausible), the failure is at connection level (the peer
//! closed or reset it, or a write failed), the opcode is `QUERY` and the
//! call's deadline has not passed. Timeouts, TLS errors, validation
//! mismatches and undecodable answers are never retried.
//!
//! # Bounds
//!
//! A connection holds at most `max_in_flight` pending and cancelled queries,
//! queues at most `max_in_flight` frames for its writer, and buffers at most
//! one frame (65 537 bytes) while reading.

#![deny(clippy::await_holding_lock)]

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use dns_lattice_core::{Error, Result};
use dns_lattice_model::{Message, Opcode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, timeout, timeout_at};

use super::pool::{
    AbortOnDrop, Connector, PendingTable, Pool, PoolConfig, PoolHooks, PoolStats, Taken,
};
use super::{IdCheck, validate_response};

/// The most bytes one length-prefixed frame can occupy: the 2-byte prefix and
/// a 65 535-byte message.
const MAX_FRAME_LEN: usize = 2 + u16::MAX as usize;
/// The first read buffer size; it grows up to [`MAX_FRAME_LEN`] only when a
/// frame needs it.
const INITIAL_READ_BUFFER: usize = 2048;
/// Unsolicited frames in a row a connection tolerates before it is closed.
const UNSOLICITED_LIMIT: u32 = 16;
/// Most frames the writer coalesces into one `write_all`.
const WRITE_BATCH: usize = 64;

/// How a stream pool opens the transport of one upstream.
pub(crate) trait StreamOpen: Send + Sync + 'static {
    /// The established byte stream (plain TCP, or TLS over it).
    type Stream: AsyncRead + AsyncWrite + Send + 'static;

    /// Opens a new stream. It must bound itself with the transport's connect
    /// (and handshake) timeouts: the pool runs it in a task of its own and
    /// does not cancel it on a caller's deadline.
    fn open(&self) -> impl Future<Output = Result<Self::Stream>> + Send;
}

/// Why a query on a connection failed, and whether the connection did.
#[derive(Debug, Clone)]
struct Failure {
    error: Error,
    /// The connection itself is gone (closed, reset, unwritable), so a
    /// different connection may succeed. Not set for timeouts, validation
    /// mismatches and undecodable answers.
    connection_level: bool,
}

impl Failure {
    fn closed(reason: impl Into<String>) -> Self {
        Failure {
            error: Error::Transport(reason.into()),
            connection_level: true,
        }
    }

    fn terminal(error: Error) -> Self {
        Failure {
            error,
            connection_level: false,
        }
    }
}

/// A caller waiting for the answer to one wire id.
struct Waiter {
    /// Tells this query from a later one that was handed the same id.
    serial: u64,
    tx: oneshot::Sender<std::result::Result<Message, Failure>>,
}

struct ConnState {
    table: PendingTable<Waiter>,
    closed: bool,
    /// How many more unsolicited frames the connection tolerates.
    slack: u32,
    slack_cap: u32,
}

/// The part of a connection its tasks and callers share. It holds no task
/// handle and no reference to the pool, so there is no reference cycle.
struct ConnShared {
    state: Mutex<ConnState>,
    /// The connection can no longer carry queries.
    dead: AtomicBool,
    /// At least one query received its answer here.
    answered: AtomicBool,
    next_serial: AtomicU64,
    closed: watch::Sender<bool>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ConnShared {
    /// Ends the connection: no new query is accepted, the tasks stop, and
    /// every waiter receives `failure`. Only the first call has an effect.
    fn fail(&self, failure: &Failure) {
        let waiters = {
            let mut st = lock(&self.state);
            if st.closed {
                return;
            }
            st.closed = true;
            st.table.drain_pending()
        };
        self.dead.store(true, Ordering::Release);
        self.closed.send_replace(true);
        for waiter in waiters {
            let _ = waiter.tx.send(Err(failure.clone()));
        }
    }

    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }
}

/// One pooled stream connection: its shared state, the queue to its writer
/// and the two tasks (aborted when the connection is dropped).
pub(crate) struct StreamConn {
    shared: Arc<ConnShared>,
    frames: mpsc::Sender<Vec<u8>>,
    reader: AbortOnDrop,
    writer: AbortOnDrop,
}

/// A registered query: its answer channel and the guard that cancels it.
struct Submitted {
    rx: oneshot::Receiver<std::result::Result<Message, Failure>>,
    guard: PendingGuard,
}

/// Turns a query that is abandoned before its answer arrives into an orphan,
/// so its wire id stays reserved and a late answer cannot reach a newer query.
struct PendingGuard {
    shared: Arc<ConnShared>,
    id: u16,
    serial: u64,
    armed: bool,
}

impl PendingGuard {
    /// The waiter is gone (answered or failed): nothing left to cancel.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut st = lock(&self.shared.state);
        let serial = self.serial;
        if st
            .table
            .orphan_if(self.id, Instant::now(), |w| w.serial == serial)
            .is_some()
        {
            // Its answer may still arrive after the orphan was evicted, so
            // the connection earns one more tolerated unsolicited frame.
            st.slack = st.slack.saturating_add(1).min(st.slack_cap);
        }
    }
}

fn build_frame(payload: &[u8], id: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 2);
    // The caller checked that the payload fits 16 bits.
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    if let Some(slot) = frame.get_mut(2..4) {
        slot.copy_from_slice(&id.to_be_bytes());
    }
    frame
}

impl StreamConn {
    /// Splits `stream` and starts the reader and writer tasks. Must run
    /// inside a Tokio runtime.
    fn spawn<S>(stream: S, hooks: PoolHooks, max_in_flight: usize, read_timeout: Duration) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let (frames, queue) = mpsc::channel(max_in_flight.max(1));
        let (closed, _) = watch::channel(false);
        let shared = Arc::new(ConnShared {
            state: Mutex::new(ConnState {
                table: PendingTable::new(max_in_flight, read_timeout),
                closed: false,
                slack: UNSOLICITED_LIMIT,
                slack_cap: UNSOLICITED_LIMIT.saturating_add(max_in_flight as u32),
            }),
            dead: AtomicBool::new(false),
            answered: AtomicBool::new(false),
            next_serial: AtomicU64::new(0),
            closed,
        });
        let reader = tokio::spawn(run_reader(read_half, Arc::clone(&shared), hooks));
        let writer = tokio::spawn(run_writer(
            write_half,
            queue,
            Arc::clone(&shared),
            read_timeout,
        ));
        StreamConn {
            shared,
            frames,
            reader: AbortOnDrop::new(reader.abort_handle()),
            writer: AbortOnDrop::new(writer.abort_handle()),
        }
    }

    /// Registers a query and queues its frame, synchronously.
    fn submit(&self, payload: &[u8]) -> std::result::Result<Submitted, Failure> {
        let shared = &self.shared;
        let (tx, rx) = oneshot::channel();
        let serial = shared.next_serial.fetch_add(1, Ordering::Relaxed);
        let mut st = lock(&shared.state);
        if st.closed {
            return Err(Failure::closed("upstream connection is closed"));
        }
        let Ok(id) = st.table.register(Waiter { serial, tx }, Instant::now()) else {
            return Err(Failure::terminal(Error::Transport(
                "upstream connection has no free query slot".to_string(),
            )));
        };
        if self.frames.try_send(build_frame(payload, id)).is_err() {
            // The writer is gone or cannot keep up: the connection is broken.
            let _ = st.table.take(id);
            drop(st);
            let failure = Failure::closed("upstream connection cannot take more writes");
            shared.fail(&failure);
            return Err(failure);
        }
        drop(st);
        Ok(Submitted {
            rx,
            guard: PendingGuard {
                shared: Arc::clone(shared),
                id,
                serial,
                armed: true,
            },
        })
    }

    /// Whether the connection has delivered at least one answer.
    fn has_answered(&self) -> bool {
        self.shared.answered.load(Ordering::Acquire)
    }

    /// Ends the connection and its tasks, failing every waiter.
    fn shutdown(&self) {
        self.shared
            .fail(&Failure::closed("upstream connection was closed"));
        self.reader.abort();
        self.writer.abort();
    }
}

/// Tells one frame what to do. Returns `false` when the connection ended.
fn dispatch(shared: &ConnShared, hooks: &PoolHooks, frame: &[u8]) -> bool {
    let Some(id_bytes) = frame.first_chunk::<2>() else {
        // Too short to carry an id: not a DNS message at all, and no query
        // is the offender.
        shared.fail(&Failure::closed("upstream sent an undecodable response"));
        return false;
    };
    let id = u16::from_be_bytes(*id_bytes);
    let taken = {
        let mut st = lock(&shared.state);
        let taken = st.table.take(id);
        match &taken {
            Taken::Pending(_) => st.slack = st.slack.max(UNSOLICITED_LIMIT),
            Taken::Orphaned => {}
            Taken::Unknown => {
                if st.slack == 0 {
                    drop(st);
                    hooks.record_unsolicited();
                    shared.fail(&Failure::closed(
                        "upstream sent too many unsolicited responses",
                    ));
                    return false;
                }
                st.slack -= 1;
            }
        }
        taken
    };
    match taken {
        Taken::Pending(waiter) => match Message::decode(frame) {
            Ok(message) => {
                shared.answered.store(true, Ordering::Release);
                let _ = waiter.tx.send(Ok(message));
                true
            }
            Err(err) => {
                // The peer sends garbage: do not trust the rest of the
                // stream. Only the query this frame answered receives the
                // decode error; the other queries on the connection were
                // healthy and see a lost connection, which the retry rule
                // and failover treat as retryable.
                let _ = waiter.tx.send(Err(Failure::terminal(err)));
                shared.fail(&Failure::closed("upstream sent an undecodable response"));
                false
            }
        },
        Taken::Orphaned => true,
        Taken::Unknown => {
            hooks.record_unsolicited();
            true
        }
    }
}

async fn run_reader<R: AsyncRead + Unpin>(mut read: R, shared: Arc<ConnShared>, hooks: PoolHooks) {
    let mut closed = shared.closed.subscribe();
    let mut buf: Vec<u8> = Vec::with_capacity(INITIAL_READ_BUFFER);
    loop {
        let mut consumed = 0;
        while let Some(rest) = buf.get(consumed..) {
            let Some(prefix) = rest.first_chunk::<2>() else {
                break;
            };
            let len = u16::from_be_bytes(*prefix) as usize;
            let Some(frame) = rest.get(2..2 + len) else {
                break;
            };
            if !dispatch(&shared, &hooks, frame) {
                return;
            }
            consumed += 2 + len;
        }
        if consumed > 0 {
            buf.drain(..consumed);
        }
        if buf.len() == buf.capacity() {
            // A complete frame never stays buffered, so a full buffer holds
            // part of one frame that is shorter than `MAX_FRAME_LEN`.
            let target = (buf.capacity() * 2).clamp(INITIAL_READ_BUFFER, MAX_FRAME_LEN);
            buf.reserve_exact(target.saturating_sub(buf.len()).max(1));
        }
        let read_some = tokio::select! {
            result = read.read_buf(&mut buf) => result,
            _ = closed.wait_for(|c| *c) => return,
        };
        match read_some {
            Ok(0) => {
                let reason = if buf.is_empty() {
                    "upstream closed the connection"
                } else {
                    "upstream closed the connection in the middle of a response"
                };
                shared.fail(&Failure::closed(reason));
                return;
            }
            Ok(_) => {}
            Err(err) => {
                shared.fail(&Failure::closed(err.to_string()));
                return;
            }
        }
    }
}

async fn run_writer<W: AsyncWrite + Unpin>(
    mut write: W,
    mut queue: mpsc::Receiver<Vec<u8>>,
    shared: Arc<ConnShared>,
    write_timeout: Duration,
) {
    let mut closed = shared.closed.subscribe();
    let mut batch: Vec<Vec<u8>> = Vec::new();
    let mut out: Vec<u8> = Vec::new();
    loop {
        let received = tokio::select! {
            n = queue.recv_many(&mut batch, WRITE_BATCH) => n,
            _ = closed.wait_for(|c| *c) => return,
        };
        if received == 0 {
            // Every sender is gone: the connection was dropped.
            return;
        }
        out.clear();
        for frame in batch.drain(..) {
            out.extend_from_slice(&frame);
        }
        let written = timeout(write_timeout, async {
            write.write_all(&out).await?;
            write.flush().await
        })
        .await;
        match written {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                shared.fail(&Failure::closed(err.to_string()));
                return;
            }
            Err(_) => {
                shared.fail(&Failure::terminal(Error::Timeout));
                return;
            }
        }
    }
}

/// Opens stream connections for the pool and describes how to probe and close
/// them.
pub(crate) struct StreamConnector<O: StreamOpen> {
    opener: O,
    max_in_flight: usize,
    read_timeout: Duration,
}

impl<O: StreamOpen> Connector for StreamConnector<O> {
    type Conn = StreamConn;

    async fn connect(&self, hooks: PoolHooks) -> Result<StreamConn> {
        let stream = self.opener.open().await?;
        Ok(StreamConn::spawn(
            stream,
            hooks,
            self.max_in_flight,
            self.read_timeout,
        ))
    }

    fn is_alive(&self, conn: &StreamConn) -> bool {
        !conn.shared.is_dead()
    }

    fn close(&self, conn: &StreamConn) {
        conn.shutdown();
    }
}

/// A failed attempt and whether the retry rule allows another one.
struct AttemptError {
    error: Error,
    retry: bool,
}

impl AttemptError {
    fn final_(error: Error) -> Self {
        AttemptError {
            error,
            retry: false,
        }
    }
}

/// The pooled, pipelined client of one stream upstream.
pub(crate) struct StreamPool<O: StreamOpen> {
    pool: Pool<StreamConnector<O>>,
    /// How long a query waits for its answer, and how long a write may take.
    read_timeout: Duration,
    /// The longest one call may take in total, retry included.
    call_budget: Duration,
}

impl<O: StreamOpen> StreamPool<O> {
    /// Creates the pool. No task is started and no connection opened until
    /// the first query. `call_budget` is the longest one call may take.
    pub(crate) fn new(
        config: PoolConfig,
        opener: O,
        read_timeout: Duration,
        call_budget: Duration,
    ) -> Self {
        let connector = Arc::new(StreamConnector {
            opener,
            max_in_flight: config.max_in_flight_value(),
            read_timeout,
        });
        StreamPool {
            pool: Pool::new(config, connector, read_timeout),
            read_timeout,
            call_budget,
        }
    }

    /// The pool's counters, after retiring connections that have died.
    pub(crate) fn stats(&self) -> PoolStats {
        self.pool.sweep();
        self.pool.stats()
    }

    /// Sends `query` on a pooled connection and returns the answer, with the
    /// caller's message id restored.
    pub(crate) async fn query(&self, query: &Message) -> Result<Message> {
        let payload = query.encode()?;
        if u16::try_from(payload.len()).is_err() {
            return Err(Error::MessageTooLong);
        }
        let now = Instant::now();
        let deadline = now
            .checked_add(self.call_budget)
            .unwrap_or_else(|| now + Duration::from_secs(60 * 60 * 24 * 365));
        let mut fresh = false;
        loop {
            match self.attempt(&payload, query, deadline, fresh).await {
                Ok(answer) => return Ok(answer),
                Err(failed) => {
                    if failed.retry && !fresh && Instant::now() < deadline {
                        self.pool.record_retry();
                        fresh = true;
                        continue;
                    }
                    return Err(failed.error);
                }
            }
        }
    }

    async fn attempt(
        &self,
        payload: &[u8],
        query: &Message,
        deadline: Instant,
        fresh: bool,
    ) -> std::result::Result<Message, AttemptError> {
        let lease = if fresh {
            self.pool.acquire_fresh(deadline).await
        } else {
            self.pool.acquire(deadline).await
        }
        .map_err(AttemptError::final_)?;
        let conn = Arc::clone(lease.conn());
        // A connection failure is retried only when it plausibly is a stale
        // pooled connection and the query is safe to send again.
        let connection_failed = |failure: Failure| {
            if failure.connection_level || conn.shared.is_dead() {
                lease.mark_dead();
            }
            AttemptError {
                retry: failure.connection_level
                    && conn.has_answered()
                    && matches!(query.header.opcode, Opcode::Query),
                error: failure.error,
            }
        };
        let Submitted { rx, mut guard } = match conn.submit(payload) {
            Ok(submitted) => submitted,
            Err(failure) => return Err(connection_failed(failure)),
        };
        let wait_until = Instant::now()
            .checked_add(self.read_timeout)
            .map_or(deadline, |t| t.min(deadline));
        match timeout_at(wait_until, rx).await {
            Err(_) => {
                // Dropping the guard orphans the slot: a late answer is
                // recognised and dropped.
                drop(guard);
                lease.note_timeout();
                Err(AttemptError::final_(Error::Timeout))
            }
            Ok(Err(_)) => {
                guard.disarm();
                Err(connection_failed(Failure::closed(
                    "upstream connection was closed",
                )))
            }
            Ok(Ok(Err(failure))) => {
                guard.disarm();
                Err(connection_failed(failure))
            }
            Ok(Ok(Ok(mut answer))) => {
                guard.disarm();
                // The wire id matched; the question and QR bit are checked
                // against the caller's query.
                validate_response(query, &answer, IdCheck::Ignore).map_err(AttemptError::final_)?;
                answer.header.id = query.header.id;
                lease.complete();
                Ok(answer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    use dns_lattice_model::{Class, Header, Name, Question, Rcode, RecordType};
    use tokio::io::DuplexStream;
    use tokio::time::{advance, sleep};

    use super::*;

    // ---- wire helpers ---------------------------------------------------------

    fn query_for(name: &str) -> Message {
        Message {
            header: Header {
                id: 11,
                qr: false,
                opcode: Opcode::Query,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                rcode: Rcode::NoError,
            },
            questions: vec![Question {
                name: Name::from_ascii(name).unwrap(),
                qtype: RecordType::A,
                qclass: Class::In,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    fn answer_to(query: &Message) -> Message {
        let mut answer = query.clone();
        answer.header.qr = true;
        answer
    }

    async fn read_query(stream: &mut DuplexStream) -> Option<Message> {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.ok()?;
        let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut payload).await.ok()?;
        Some(Message::decode(&payload).unwrap())
    }

    async fn write_message(stream: &mut DuplexStream, message: &Message) {
        let payload = message.encode().unwrap();
        let mut frame = (payload.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        let _ = stream.write_all(&frame).await;
    }

    // ---- scripted servers -----------------------------------------------------

    /// What a scripted server does on one connection; `index` counts
    /// connections from 0.
    type Script = Arc<
        dyn Fn(usize, DuplexStream) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>>
            + Send
            + Sync,
    >;

    struct Scripted {
        script: Script,
        accepted: Arc<AtomicUsize>,
    }

    impl StreamOpen for Scripted {
        type Stream = DuplexStream;

        async fn open(&self) -> Result<DuplexStream> {
            let index = self.accepted.fetch_add(1, Ordering::SeqCst);
            let (client, server) = tokio::io::duplex(1 << 20);
            tokio::spawn((self.script)(index, server));
            Ok(client)
        }
    }

    fn script<F, Fut>(f: F) -> Script
    where
        F: Fn(usize, DuplexStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Arc::new(move |i, s| Box::pin(f(i, s)))
    }

    const READ_TIMEOUT: Duration = Duration::from_secs(2);

    struct Harness {
        pool: Arc<StreamPool<Scripted>>,
        accepted: Arc<AtomicUsize>,
    }

    fn harness(config: PoolConfig, script: Script) -> Harness {
        let accepted = Arc::new(AtomicUsize::new(0));
        let pool = Arc::new(StreamPool::new(
            config,
            Scripted {
                script,
                accepted: Arc::clone(&accepted),
            },
            READ_TIMEOUT,
            Duration::from_secs(10),
        ));
        Harness { pool, accepted }
    }

    impl Harness {
        async fn ask(&self, name: &str) -> Result<Message> {
            self.pool.query(&query_for(name)).await
        }

        fn stats(&self) -> PoolStats {
            self.pool.stats()
        }
    }

    /// Answers every query at once.
    fn echo() -> Script {
        script(|_, mut s| async move {
            while let Some(query) = read_query(&mut s).await {
                write_message(&mut s, &answer_to(&query)).await;
            }
        })
    }

    async fn settle() {
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
    }

    // ---- reuse, pipelining, remapping -----------------------------------------

    #[tokio::test(start_paused = true)]
    async fn sequential_queries_share_one_connection() {
        let h = harness(PoolConfig::new(), echo());
        for i in 0..5 {
            let name = format!("n{i}.example");
            let answer = h.ask(&name).await.unwrap();
            assert_eq!(answer.questions, query_for(&name).questions);
            assert_eq!(answer.header.id, 11, "the caller's id is restored");
        }
        let stats = h.stats();
        assert_eq!(h.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(stats.queries(), 5);
        assert_eq!(stats.reused_queries(), 4);
        assert_eq!(stats.retries(), 0);
        assert_eq!(stats.in_flight(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn out_of_order_answers_reach_their_own_callers_even_with_equal_client_ids() {
        const N: usize = 8;
        // Collects N queries, then answers them in reverse order.
        let reversed = script(|_, mut s| async move {
            let mut seen = VecDeque::new();
            while seen.len() < N {
                let Some(q) = read_query(&mut s).await else {
                    return;
                };
                seen.push_back(q);
            }
            while let Some(q) = seen.pop_back() {
                write_message(&mut s, &answer_to(&q)).await;
            }
            while read_query(&mut s).await.is_some() {}
        });
        let h = harness(PoolConfig::new().max_connections(1), reversed);
        let calls = (0..N).map(|i| {
            let pool = Arc::clone(&h.pool);
            tokio::spawn(async move {
                // Every caller uses message id 11.
                let name = format!("q{i}.example");
                let answer = pool.query(&query_for(&name)).await.unwrap();
                (name, answer)
            })
        });
        for call in calls.collect::<Vec<_>>() {
            let (name, answer) = call.await.unwrap();
            assert_eq!(answer.questions, query_for(&name).questions);
            assert_eq!(answer.header.id, 11);
        }
        assert_eq!(h.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(h.stats().unsolicited(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_pipelined_burst_is_bounded_by_the_connection_limits() {
        // 2 slots in total: the third call waits for a free slot.
        let slow = script(|_, mut s| async move {
            while let Some(q) = read_query(&mut s).await {
                sleep(Duration::from_millis(500)).await;
                write_message(&mut s, &answer_to(&q)).await;
            }
        });
        let h = harness(PoolConfig::new().max_connections(1).max_in_flight(2), slow);
        let calls: Vec<_> = (0..3)
            .map(|i| {
                let pool = Arc::clone(&h.pool);
                tokio::spawn(async move { pool.query(&query_for(&format!("b{i}.example"))).await })
            })
            .collect();
        settle().await;
        assert_eq!(h.stats().in_flight(), 2, "at most max_in_flight admitted");
        for call in calls {
            call.await.unwrap().unwrap();
        }
        let stats = h.stats();
        assert!(stats.queued() >= 1, "{stats:?}");
        assert_eq!(stats.in_flight(), 0);
        assert_eq!(stats.connections_opened(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn load_scales_the_pool_up_to_max_connections() {
        let slow = script(|_, mut s| async move {
            while let Some(q) = read_query(&mut s).await {
                sleep(Duration::from_millis(100)).await;
                write_message(&mut s, &answer_to(&q)).await;
            }
        });
        let h = harness(PoolConfig::new().max_connections(3).max_in_flight(4), slow);
        let calls: Vec<_> = (0..12)
            .map(|i| {
                let pool = Arc::clone(&h.pool);
                tokio::spawn(async move { pool.query(&query_for(&format!("s{i}.example"))).await })
            })
            .collect();
        for call in calls {
            call.await.unwrap().unwrap();
        }
        assert_eq!(h.stats().connections_opened(), 3);
        assert_eq!(h.accepted.load(Ordering::SeqCst), 3);
    }

    // ---- connection loss and the retry rule -----------------------------------

    /// Answers `answers` queries, then closes the connection without
    /// answering the next one (it reads it first).
    fn close_on_query(answers: usize) -> Script {
        script(move |_, mut s| async move {
            for _ in 0..answers {
                let Some(q) = read_query(&mut s).await else {
                    return;
                };
                write_message(&mut s, &answer_to(&q)).await;
            }
            let _ = read_query(&mut s).await;
            drop(s);
        })
    }

    /// First connection: `close_on_query(first)`; later connections: echo.
    fn flaky_then_good(first: usize) -> Script {
        let flaky = close_on_query(first);
        let good = echo();
        script(move |i, s| if i == 0 { flaky(i, s) } else { good(i, s) })
    }

    #[tokio::test(start_paused = true)]
    async fn a_reused_connection_that_closes_with_a_query_in_flight_is_retried_once() {
        let h = harness(PoolConfig::new(), flaky_then_good(1));
        h.ask("a.example").await.unwrap();
        let answer = h
            .ask("b.example")
            .await
            .expect("retried on a fresh connection");
        assert_eq!(answer.questions, query_for("b.example").questions);
        let stats = h.stats();
        assert_eq!(stats.retries(), 1);
        assert_eq!(stats.connections_opened(), 2);
        assert_eq!(stats.closed_error(), 1);
        assert_eq!(h.accepted.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_fresh_connection_that_closes_is_not_retried() {
        let h = harness(PoolConfig::new(), close_on_query(0));
        let err = h.ask("a.example").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        let stats = h.stats();
        assert_eq!(stats.retries(), 0);
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(stats.closed_error(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_retry_that_fails_returns_the_transport_error() {
        // The first connection answers once and then closes on the next
        // query; the replacement closes on its first query too.
        let first = close_on_query(1);
        let later = close_on_query(0);
        let h = harness(
            PoolConfig::new(),
            script(move |i, s| if i == 0 { first(i, s) } else { later(i, s) }),
        );
        h.ask("a.example").await.unwrap();
        let err = h.ask("b.example").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        let stats = h.stats();
        assert_eq!(stats.retries(), 1, "retried exactly once");
        assert_eq!(stats.connections_opened(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_query_that_is_not_opcode_query_is_never_retried() {
        let h = harness(PoolConfig::new(), flaky_then_good(1));
        h.ask("a.example").await.unwrap();
        let mut notify = query_for("b.example");
        notify.header.opcode = Opcode::Notify;
        let err = h.pool.query(&notify).await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        assert_eq!(h.stats().retries(), 0);
        assert_eq!(h.accepted.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_closed_while_idle_is_replaced_without_failing_a_query() {
        // Answers one query and drops the connection while it is idle.
        let one_shot = script(|_, mut s| async move {
            if let Some(q) = read_query(&mut s).await {
                write_message(&mut s, &answer_to(&q)).await;
            }
            drop(s);
        });
        let h = harness(PoolConfig::new(), one_shot);
        for i in 0..4 {
            h.ask(&format!("i{i}.example"))
                .await
                .expect("transparent reconnect");
            settle().await;
        }
        let stats = h.stats();
        assert_eq!(stats.connections_opened(), 4);
        assert!(stats.retries() <= 3, "{stats:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_closed_in_the_middle_of_a_frame_is_a_connection_failure() {
        // The first connection answers once, then writes half a frame and
        // closes; later ones echo.
        let half = script(|i, mut s| async move {
            if i > 0 {
                while let Some(q) = read_query(&mut s).await {
                    write_message(&mut s, &answer_to(&q)).await;
                }
                return;
            }
            if let Some(q) = read_query(&mut s).await {
                write_message(&mut s, &answer_to(&q)).await;
            }
            let _ = read_query(&mut s).await;
            let _ = s.write_all(&[0, 100, 1, 2, 3]).await;
            drop(s);
        });
        let h = harness(PoolConfig::new(), half);
        h.ask("a.example").await.unwrap();
        h.ask("b.example")
            .await
            .expect("a reused connection is retried");
        assert_eq!(h.stats().retries(), 1);

        // On a fresh connection the same failure is final.
        let fresh_half = script(|_, mut s| async move {
            let _ = read_query(&mut s).await;
            let _ = s.write_all(&[0, 100, 1, 2, 3]).await;
            drop(s);
        });
        let h = harness(PoolConfig::new(), fresh_half);
        let err = h.ask("a.example").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        assert_eq!(h.stats().retries(), 0);
    }

    // ---- timeouts -------------------------------------------------------------

    /// Answers the first query, then reads and ignores everything.
    fn blackhole_after_one() -> Script {
        script(|_, mut s| async move {
            if let Some(q) = read_query(&mut s).await {
                write_message(&mut s, &answer_to(&q)).await;
            }
            while read_query(&mut s).await.is_some() {}
        })
    }

    #[tokio::test(start_paused = true)]
    async fn a_timeout_is_not_retried_and_keeps_the_connection() {
        let h = harness(PoolConfig::new(), blackhole_after_one());
        h.ask("a.example").await.unwrap();
        let started = Instant::now();
        let err = h.ask("b.example").await.unwrap_err();
        assert_eq!(err, Error::Timeout);
        assert_eq!(
            started.elapsed(),
            READ_TIMEOUT,
            "one read timeout, as before"
        );
        let stats = h.stats();
        assert_eq!(stats.retries(), 0);
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(stats.connections_open(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn three_timeouts_in_a_row_mark_the_connection_dead() {
        let h = harness(PoolConfig::new(), blackhole_after_one());
        h.ask("a.example").await.unwrap();
        for _ in 0..3 {
            assert_eq!(h.ask("x.example").await.unwrap_err(), Error::Timeout);
        }
        let stats = h.stats();
        assert_eq!(stats.closed_error(), 1);
        assert_eq!(stats.connections_open(), 0);
        // The next query gets a new connection (which blackholes after one
        // answer, so it succeeds exactly once).
        h.ask("y.example").await.unwrap();
        assert_eq!(h.stats().connections_opened(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_connect_that_never_completes_times_out_at_the_deadline() {
        struct Hang;
        impl StreamOpen for Hang {
            type Stream = DuplexStream;
            async fn open(&self) -> Result<DuplexStream> {
                std::future::pending().await
            }
        }
        let pool = StreamPool::new(
            PoolConfig::new(),
            Hang,
            READ_TIMEOUT,
            Duration::from_secs(5),
        );
        let started = Instant::now();
        let err = pool.query(&query_for("a.example")).await.unwrap_err();
        assert_eq!(err, Error::Timeout);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    // ---- validation -----------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn an_answer_with_an_unknown_id_is_dropped_and_the_query_times_out() {
        let wrong_id = script(|_, mut s| async move {
            while let Some(q) = read_query(&mut s).await {
                let mut answer = answer_to(&q);
                answer.header.id = q.header.id.wrapping_add(1);
                write_message(&mut s, &answer).await;
            }
        });
        let h = harness(PoolConfig::new(), wrong_id);
        let err = h.ask("a.example").await.unwrap_err();
        assert_eq!(err, Error::Timeout);
        let stats = h.stats();
        assert_eq!(stats.unsolicited(), 1);
        assert_eq!(stats.connections_open(), 1, "one stray frame is tolerated");
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_to_another_question_fails_only_that_caller() {
        let wrong_question = script(|_, mut s| async move {
            let mut first = true;
            while let Some(q) = read_query(&mut s).await {
                let mut answer = answer_to(&q);
                if first {
                    first = false;
                    answer.questions[0].name = Name::from_ascii("other.example").unwrap();
                }
                write_message(&mut s, &answer).await;
            }
        });
        let h = harness(PoolConfig::new(), wrong_question);
        let err = h.ask("a.example").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        h.ask("b.example").await.expect("the connection is intact");
        assert_eq!(h.stats().connections_opened(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_without_the_qr_bit_is_rejected() {
        let reflect = script(|_, mut s| async move {
            while let Some(q) = read_query(&mut s).await {
                write_message(&mut s, &q).await;
            }
        });
        let h = harness(PoolConfig::new(), reflect);
        let err = h.ask("a.example").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn an_undecodable_answer_fails_only_its_query_with_the_decode_error_and_closes() {
        // The server echoes the wire id it received, with a body too short
        // to be a DNS message (a 5-byte frame).
        let garbage = script(|_, mut s| async move {
            if let Some(q) = read_query(&mut s).await {
                let id = q.header.id.to_be_bytes();
                let _ = s.write_all(&[0, 5, id[0], id[1], 0, 0, 0]).await;
            }
            while read_query(&mut s).await.is_some() {}
        });
        let h = harness(PoolConfig::new(), garbage);
        let err = h.ask("a.example").await.unwrap_err();
        assert!(
            matches!(err, Error::Truncated { .. } | Error::CountMismatch),
            "{err:?}"
        );
        assert_eq!(h.stats().retries(), 0, "decode errors are never retried");
        assert_eq!(h.stats().connections_open(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_bystander_of_an_undecodable_answer_is_retried_on_a_new_connection() {
        // Connection 0 answers one query, then reads two more and answers the
        // first of them with garbage. Later connections answer normally.
        let garbage = script(|_, mut s| async move {
            if let Some(q) = read_query(&mut s).await {
                write_message(&mut s, &answer_to(&q)).await;
            }
            let (Some(x), Some(_y)) = (read_query(&mut s).await, read_query(&mut s).await) else {
                return;
            };
            let id = x.header.id.to_be_bytes();
            let _ = s.write_all(&[0, 5, id[0], id[1], 0, 0, 0]).await;
            while read_query(&mut s).await.is_some() {}
        });
        let good = echo();
        let h = harness(
            PoolConfig::new().max_connections(1),
            script(move |i, s| if i == 0 { garbage(i, s) } else { good(i, s) }),
        );
        h.ask("warm.example").await.unwrap();
        let x = tokio::spawn({
            let pool = Arc::clone(&h.pool);
            async move { pool.query(&query_for("x.example")).await }
        });
        // Let the first spawned query register before the second.
        settle().await;
        let y = tokio::spawn({
            let pool = Arc::clone(&h.pool);
            async move { pool.query(&query_for("y.example")).await }
        });
        let x = x.await.unwrap().unwrap_err();
        assert!(
            matches!(x, Error::Truncated { .. } | Error::CountMismatch),
            "the offender gets the decode error: {x:?}"
        );
        let y = y
            .await
            .unwrap()
            .expect("the bystander is retried and answered");
        assert_eq!(y.questions, query_for("y.example").questions);
        let stats = h.stats();
        assert_eq!(stats.retries(), 1, "only the bystander is retried");
        assert_eq!(stats.connections_opened(), 2);
        assert_eq!(stats.closed_error(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_frame_too_short_for_an_id_gives_every_query_a_connection_error() {
        let tiny = script(|_, mut s| async move {
            let _ = read_query(&mut s).await;
            let _ = s.write_all(&[0, 1, 7]).await;
            while read_query(&mut s).await.is_some() {}
        });
        let h = harness(PoolConfig::new(), tiny);
        let err = h.ask("a.example").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        assert_eq!(h.stats().connections_open(), 0);
    }

    // ---- unsolicited frames -----------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn orphaned_queries_buy_credit_for_late_answers_that_were_evicted() {
        // 20 queries are cancelled, their tombstones expire, and only then
        // does the server answer all of them: 20 unknown frames, more than
        // the base allowance of 16, with no answer to a pending query in
        // between. Each orphaning added one credit, so the connection lives.
        let late = script(|_, mut s| async move {
            let mut queries = Vec::new();
            for _ in 0..20 {
                match read_query(&mut s).await {
                    Some(q) => queries.push(q),
                    None => return,
                }
            }
            sleep(Duration::from_secs(4)).await;
            for q in &queries {
                write_message(&mut s, &answer_to(q)).await;
            }
            while let Some(q) = read_query(&mut s).await {
                write_message(&mut s, &answer_to(&q)).await;
            }
        });
        let h = harness(PoolConfig::new().max_connections(1), late);
        let cancelled: Vec<_> = (0..20)
            .map(|i| {
                let pool = Arc::clone(&h.pool);
                tokio::spawn(tokio::time::timeout(
                    Duration::from_millis(100),
                    async move { pool.query(&query_for(&format!("o{i}.example"))).await },
                ))
            })
            .collect();
        for handle in cancelled {
            assert!(handle.await.unwrap().is_err(), "dropped mid-flight");
        }
        advance(Duration::from_secs(3)).await; // past the tombstone lifetime
        let live = h
            .ask("live.example")
            .await
            .expect("the connection survives");
        assert_eq!(live.questions, query_for("live.example").questions);
        let stats = h.stats();
        assert_eq!(stats.unsolicited(), 20);
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(stats.closed_error(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_retry_never_lands_on_another_stale_connection() {
        // Every connection answers one query and hangs up on the second.
        // Connection 2 and later answer normally.
        let once = close_on_query(1);
        let good = echo();
        let h = harness(
            PoolConfig::new().max_connections(2).max_in_flight(1),
            script(move |i, s| if i < 2 { once(i, s) } else { good(i, s) }),
        );
        // Two concurrent queries open two connections, each answers once.
        let (a, b) = tokio::join!(h.ask("a.example"), h.ask("b.example"));
        a.unwrap();
        b.unwrap();
        assert_eq!(h.stats().connections_opened(), 2);
        // The next query hits a connection that closes; the retry must go to
        // a new connection rather than the other (equally stale) one.
        let answer = h.ask("c.example").await.expect("the retry succeeds");
        assert_eq!(answer.questions, query_for("c.example").questions);
        let stats = h.stats();
        assert_eq!(stats.retries(), 1);
        assert_eq!(stats.connections_opened(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn more_than_sixteen_unsolicited_frames_in_a_row_close_the_connection() {
        let flood = script(|_, mut s| async move {
            if let Some(q) = read_query(&mut s).await {
                // Junk ids never match a pending query: the only pending id is q's.
                for k in 1..=17u16 {
                    let mut junk = answer_to(&q);
                    junk.header.id = q.header.id.wrapping_add(k);
                    write_message(&mut s, &junk).await;
                }
            }
            while read_query(&mut s).await.is_some() {}
        });
        let h = harness(PoolConfig::new(), flood);
        let err = h.ask("a.example").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        let stats = h.stats();
        assert_eq!(stats.unsolicited(), 17);
        assert_eq!(stats.closed_error(), 1);
        assert_eq!(stats.connections_open(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_unsolicited_allowance_is_refilled_by_answers_and_is_not_cumulative() {
        // Ten stray frames before every answer: 50 in total over five
        // queries, never more than ten in a row.
        let noisy = script(|_, mut s| async move {
            while let Some(q) = read_query(&mut s).await {
                for k in 1..=10u16 {
                    let mut junk = answer_to(&q);
                    junk.header.id = q.header.id.wrapping_add(k);
                    write_message(&mut s, &junk).await;
                }
                write_message(&mut s, &answer_to(&q)).await;
            }
        });
        let h = harness(PoolConfig::new(), noisy);
        for i in 0..5 {
            h.ask(&format!("n{i}.example")).await.unwrap();
        }
        let stats = h.stats();
        assert_eq!(stats.unsolicited(), 50);
        assert_eq!(stats.connections_opened(), 1, "the connection survived");
        assert_eq!(stats.closed_error(), 0);
    }

    // ---- cancellation -----------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_query_does_not_disturb_the_connection_or_the_next_query() {
        // Reads two queries, answers the second first and the first late.
        let late = script(|_, mut s| async move {
            let Some(first) = read_query(&mut s).await else {
                return;
            };
            let Some(second) = read_query(&mut s).await else {
                return;
            };
            write_message(&mut s, &answer_to(&second)).await;
            sleep(Duration::from_secs(1)).await;
            write_message(&mut s, &answer_to(&first)).await;
            while let Some(q) = read_query(&mut s).await {
                write_message(&mut s, &answer_to(&q)).await;
            }
        });
        let h = harness(PoolConfig::new().max_connections(1), late);
        let cancelled = tokio::time::timeout(Duration::from_millis(100), h.ask("a.example")).await;
        assert!(cancelled.is_err(), "the first call is dropped mid-flight");
        assert_eq!(h.stats().in_flight(), 0, "the lease was released");

        let answer = h.ask("b.example").await.unwrap();
        assert_eq!(answer.questions, query_for("b.example").questions);
        // The late answer to the cancelled query lands on its orphan, not on
        // a new query and not as an unsolicited frame.
        advance(Duration::from_secs(2)).await;
        settle().await;
        let again = h.ask("c.example").await.unwrap();
        assert_eq!(again.questions, query_for("c.example").questions);
        let stats = h.stats();
        assert_eq!(stats.unsolicited(), 0);
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(stats.in_flight(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn answers_to_evicted_orphans_never_close_a_healthy_connection() {
        // Two slots. Each round: cancel A and B (two orphans), then C evicts
        // A's orphan, and the server finally answers A, B and C in order, so
        // A's answer is unsolicited. Forty rounds exceed the allowance of 16.
        let three_then_answer = script(|_, mut s| async move {
            loop {
                let mut batch = Vec::new();
                for _ in 0..3 {
                    let Some(q) = read_query(&mut s).await else {
                        return;
                    };
                    batch.push(q);
                }
                for q in &batch {
                    write_message(&mut s, &answer_to(q)).await;
                }
            }
        });
        let h = harness(
            PoolConfig::new().max_connections(1).max_in_flight(2),
            three_then_answer,
        );
        for round in 0..40 {
            for name in ["a.example", "b.example"] {
                let r = tokio::time::timeout(Duration::from_millis(10), h.ask(name)).await;
                assert!(r.is_err(), "round {round}: {name} stays unanswered");
            }
            let answer = h.ask("c.example").await.expect("C is answered");
            assert_eq!(answer.questions, query_for("c.example").questions);
        }
        let stats = h.stats();
        assert_eq!(stats.connections_opened(), 1, "{stats:?}");
        assert_eq!(stats.closed_error(), 0);
        assert!(stats.unsolicited() >= 17, "{stats:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_pool_closes_the_connection_and_ends_its_tasks() {
        let closed = Arc::new(AtomicBool::new(false));
        let closed_in_script = Arc::clone(&closed);
        let watch_close = script(move |_, mut s| {
            let closed = Arc::clone(&closed_in_script);
            async move {
                while let Some(q) = read_query(&mut s).await {
                    write_message(&mut s, &answer_to(&q)).await;
                }
                closed.store(true, Ordering::SeqCst);
            }
        });
        let h = harness(PoolConfig::new(), watch_close);
        h.ask("a.example").await.unwrap();
        assert!(!closed.load(Ordering::SeqCst));
        drop(h);
        settle().await;
        assert!(closed.load(Ordering::SeqCst), "the server saw the close");
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            0,
            "no reader, writer, janitor or connect task is left"
        );
    }

    // ---- idle and lifetime ------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn an_idle_connection_is_closed_and_a_later_query_reconnects() {
        let h = harness(
            PoolConfig::new().idle_timeout(Duration::from_secs(20)),
            echo(),
        );
        h.ask("a.example").await.unwrap();
        advance(Duration::from_secs(19)).await;
        settle().await;
        assert_eq!(h.stats().connections_open(), 1);
        advance(Duration::from_secs(2)).await;
        settle().await;
        let stats = h.stats();
        assert_eq!(stats.connections_open(), 0);
        assert_eq!(stats.closed_idle(), 1);
        h.ask("b.example").await.unwrap();
        assert_eq!(h.stats().connections_opened(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_past_its_lifetime_is_rotated_without_a_failed_query() {
        let h = harness(
            PoolConfig::new()
                .max_connections(1)
                .max_lifetime(Some(Duration::from_secs(3))),
            echo(),
        );
        for i in 0..10 {
            h.ask(&format!("r{i}.example"))
                .await
                .expect("no failed query");
            advance(Duration::from_millis(700)).await;
            settle().await;
        }
        let stats = h.stats();
        assert!(stats.connections_opened() >= 2, "{stats:?}");
        assert!(stats.closed_lifetime() >= 1, "{stats:?}");
        assert_eq!(stats.retries(), 0);
    }

    // ---- frame assembly ---------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn frames_split_across_reads_and_coalesced_in_one_read_are_assembled() {
        let dribble = script(|_, mut s| async move {
            let Some(q1) = read_query(&mut s).await else {
                return;
            };
            let Some(q2) = read_query(&mut s).await else {
                return;
            };
            // Both answers in one burst, written a byte at a time and then
            // together.
            let mut bytes = Vec::new();
            for q in [&q2, &q1] {
                let payload = answer_to(q).encode().unwrap();
                bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&payload);
            }
            let (head, tail) = bytes.split_at(5);
            for byte in head {
                let _ = s.write_all(&[*byte]).await;
                tokio::task::yield_now().await;
            }
            let _ = s.write_all(tail).await;
            while read_query(&mut s).await.is_some() {}
        });
        let h = harness(PoolConfig::new().max_connections(1), dribble);
        let (a, b) = tokio::join!(h.ask("a.example"), h.ask("b.example"));
        assert_eq!(a.unwrap().questions, query_for("a.example").questions);
        assert_eq!(b.unwrap().questions, query_for("b.example").questions);
    }

    #[test]
    fn the_wire_id_sits_in_the_first_two_bytes_of_an_encoded_message() {
        let query = query_for("a.example");
        let payload = query.encode().unwrap();
        let frame = build_frame(&payload, 0xBEEF);
        assert_eq!(&frame[..2], &(payload.len() as u16).to_be_bytes());
        let decoded = Message::decode(&frame[2..]).unwrap();
        assert_eq!(decoded.header.id, 0xBEEF);
        assert_eq!(decoded.questions, query.questions);
    }

    #[tokio::test(start_paused = true)]
    async fn the_largest_answer_a_frame_can_carry_is_read_whole() {
        // An answer close to 64 KiB: many A records.
        let big = script(|_, mut s| async move {
            while let Some(q) = read_query(&mut s).await {
                let mut answer = answer_to(&q);
                answer.answers = (0..2400u32)
                    .map(|i| dns_lattice_model::ResourceRecord {
                        name: Name::from_ascii("a.example").unwrap(),
                        rtype: RecordType::A,
                        class: Class::In,
                        ttl: 60,
                        rdata: dns_lattice_model::RData::A(std::net::Ipv4Addr::from(i)),
                    })
                    .collect();
                write_message(&mut s, &answer).await;
            }
        });
        let h = harness(PoolConfig::new(), big);
        let answer = h.ask("a.example").await.unwrap();
        assert_eq!(answer.answers.len(), 2400);
    }
}
