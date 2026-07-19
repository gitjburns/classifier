//! Benchmark load generator for the classifier service (`bench/SPEC.md` §2).
//!
//! Client-side scratch tooling: it drives `POST /v1/assess` over hand-rolled
//! keep-alive HTTP/1.1 on blocking sockets and reports throughput and latency
//! percentiles. It is a measuring instrument, not part of the service: it may
//! use wall clocks freely, it is exempt from the service diagnostics policy,
//! and it must never be wired into the service binary.

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use sha2::{Digest, Sha256};

/// One-line usage summary printed alongside argument errors.
const USAGE: &str = "usage: bench-load --addr <host:port> --token-file <path> \
--connections <n> --duration-secs <n> --content-bytes <n> [--warmup-secs <n>]";

/// Caps stored error samples so a failing run reports evidence without unbounded memory.
const MAX_ERROR_SAMPLES: usize = 5;

/// Bounds each socket wait so a hung server cannot wedge the run past its deadline.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause before reconnecting after a failure so a broken server is not hammered.
const RECONNECT_BACKOFF: Duration = Duration::from_millis(50);

/// Rejects a response whose headers never terminate instead of buffering forever.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Warmup applied when `--warmup-secs` is omitted, per the harness specification.
const DEFAULT_WARMUP_SECS: u64 = 5;

/// ASCII filler cycled to pad generated content to the requested size. The spaces break
/// base64/hex-alphabet runs so the encoded-blob analyzer cannot fire on filler text.
const CONTENT_FILLER: &str = "lorem ipsum benchmark filler text ";

/// Holds the validated command-line configuration for one benchmark run.
struct Args {
    addr: String,
    token_file: String,
    connections: usize,
    duration: Duration,
    warmup: Duration,
    content_bytes: usize,
}

/// Shares one run's immutable schedule and request-generation inputs across workers.
struct RunPlan {
    addr: String,
    token: String,
    content_bytes: usize,
    /// Completions before this instant belong to warmup and are discarded.
    measure_start: Instant,
    /// Workers stop issuing new requests once this instant passes.
    run_end: Instant,
}

/// Aggregates worker failures: a total count plus a bounded set of sample messages.
struct ErrorSink {
    count: AtomicU64,
    samples: Mutex<Vec<String>>,
}

impl ErrorSink {
    /// Creates the empty sink shared by every worker in one run.
    fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            samples: Mutex::new(Vec::new()),
        }
    }

    /// Counts one failure and keeps its message only while sample capacity remains.
    /// A poisoned sample mutex loses samples, never the authoritative count.
    fn record(&self, message: String) {
        self.count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut samples) = self.samples.lock()
            && samples.len() < MAX_ERROR_SAMPLES
        {
            samples.push(message);
        }
    }
}

/// Runs one configured benchmark and reports throughput and latency percentiles.
fn main() -> ExitCode {
    let args = match parse_args(env::args()) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("bench-load: {error}");
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    let token = match load_token(&args.token_file) {
        Ok(token) => token,
        Err(error) => {
            eprintln!("bench-load: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "bench-load addr={} connections={} warmup_secs={} duration_secs={} content_bytes={}",
        args.addr,
        args.connections,
        args.warmup.as_secs(),
        args.duration.as_secs(),
        args.content_bytes
    );

    let start = Instant::now();
    let plan = RunPlan {
        addr: args.addr,
        token,
        content_bytes: args.content_bytes,
        measure_start: start + args.warmup,
        run_end: start + args.warmup + args.duration,
    };
    let sequence = AtomicU64::new(0);
    let errors = ErrorSink::new();

    // Scoped threads let workers borrow the shared plan and sinks without reference
    // counting; the scope guarantees every worker finished before results are read.
    let mut latencies: Vec<u64> = Vec::new();
    thread::scope(|scope| {
        let plan = &plan;
        let sequence = &sequence;
        let errors = &errors;
        let handles: Vec<_> = (0..args.connections)
            .map(|worker_id| scope.spawn(move || run_worker(worker_id, plan, sequence, errors)))
            .collect();
        for handle in handles {
            match handle.join() {
                Ok(mut worker_latencies) => latencies.append(&mut worker_latencies),
                // A panicked worker loses its measurements; the run continues so the
                // remaining workers' evidence is still reported.
                Err(_) => {
                    eprintln!("bench-load: worker thread panicked; its measurements are lost")
                }
            }
        }
    });

    let successes = latencies.len();
    let error_count = errors.count.load(Ordering::Relaxed);
    latencies.sort_unstable();
    // Throughput divides by the configured duration even though tail requests may finish
    // slightly past the deadline; over a 30-second run the skew is negligible.
    let throughput = successes as f64 / args.duration.as_secs_f64();
    println!("requests_ok={successes} errors={error_count}");
    println!("throughput_rps={throughput:.1}");
    println!(
        "latency_ms p50={:.2} p95={:.2} p99={:.2} max={:.2}",
        millis(percentile_micros(&latencies, 50.0)),
        millis(percentile_micros(&latencies, 95.0)),
        millis(percentile_micros(&latencies, 99.0)),
        millis(latencies.last().copied().unwrap_or(0)),
    );
    if let Ok(samples) = errors.samples.lock() {
        for sample in samples.iter() {
            eprintln!("bench-load error sample: {sample}");
        }
    }

    if successes == 0 {
        eprintln!("bench-load: no successful requests");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Parses `--flag value` pairs, rejecting unknown flags, duplicates, and invalid values.
fn parse_args(mut args: env::Args) -> Result<Args, String> {
    // The first argument is the executable path, not a flag.
    args.next();
    let mut addr = None;
    let mut token_file = None;
    let mut connections = None;
    let mut duration_secs = None;
    let mut warmup_secs = None;
    let mut content_bytes = None;
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--addr" => &mut addr,
            "--token-file" => &mut token_file,
            "--connections" => &mut connections,
            "--duration-secs" => &mut duration_secs,
            "--warmup-secs" => &mut warmup_secs,
            "--content-bytes" => &mut content_bytes,
            unknown => return Err(format!("unknown argument {unknown:?}")),
        };
        set_once(slot, &flag, args.next())?;
    }

    let addr = addr.ok_or_else(|| "--addr is required".to_owned())?;
    let token_file = token_file.ok_or_else(|| "--token-file is required".to_owned())?;
    let connections = require_positive(connections.as_deref(), "--connections")?;
    let duration_secs = require_positive(duration_secs.as_deref(), "--duration-secs")?;
    let content_bytes = require_positive(content_bytes.as_deref(), "--content-bytes")?;
    // Zero is a valid warmup: it means every completed request is measured.
    let warmup_secs = match warmup_secs {
        Some(value) => parse_integer(&value, "--warmup-secs")?,
        None => DEFAULT_WARMUP_SECS,
    };

    Ok(Args {
        addr,
        token_file,
        connections: to_usize(connections, "--connections")?,
        duration: Duration::from_secs(duration_secs),
        warmup: Duration::from_secs(warmup_secs),
        content_bytes: to_usize(content_bytes, "--content-bytes")?,
    })
}

/// Stores a flag's value exactly once so repeated flags cannot silently override earlier ones.
fn set_once(slot: &mut Option<String>, flag: &str, value: Option<String>) -> Result<(), String> {
    let value = value.ok_or_else(|| format!("{flag} requires a value"))?;
    if slot.replace(value).is_some() {
        return Err(format!("{flag} was given more than once"));
    }
    Ok(())
}

/// Parses a required flag as a strictly positive integer.
fn require_positive(value: Option<&str>, flag: &str) -> Result<u64, String> {
    let value = value.ok_or_else(|| format!("{flag} is required"))?;
    let parsed = parse_integer(value, flag)?;
    if parsed == 0 {
        return Err(format!("{flag} must be at least 1"));
    }
    Ok(parsed)
}

/// Parses a flag value as a nonnegative integer with the flag name in the error.
fn parse_integer(value: &str, flag: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|error| format!("{flag} must be an integer: {error}"))
}

/// Converts a validated count into the platform index type used by collections.
fn to_usize(value: u64, flag: &str) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("{flag} exceeds the platform integer range"))
}

/// Loads the bearer token with the service's trailing-newline rule: at most one
/// trailing LF or CRLF is removed and every other byte is part of the token.
fn load_token(path: &str) -> Result<String, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("failed to read token file {path}: {error}"))?;
    let token = if let Some(stripped) = raw.strip_suffix("\r\n") {
        stripped
    } else if let Some(stripped) = raw.strip_suffix('\n') {
        stripped
    } else {
        raw.as_str()
    };
    if token.is_empty() {
        return Err(format!("token file {path} is empty"));
    }
    Ok(token.to_owned())
}

/// Drives one keep-alive connection until the run deadline and returns the
/// latencies, in whole microseconds, of requests completed after warmup.
fn run_worker(
    worker_id: usize,
    plan: &RunPlan,
    sequence: &AtomicU64,
    errors: &ErrorSink,
) -> Vec<u64> {
    let mut latencies = Vec::new();
    let mut connection: Option<TcpStream> = None;
    while Instant::now() < plan.run_end {
        if connection.is_none() {
            match connect(&plan.addr) {
                Ok(stream) => connection = Some(stream),
                Err(error) => {
                    errors.record(error);
                    thread::sleep(RECONNECT_BACKOFF);
                    continue;
                }
            }
        }
        let Some(stream) = connection.as_mut() else {
            continue;
        };

        let request_number = sequence.fetch_add(1, Ordering::Relaxed);
        let content = generate_content(worker_id, request_number, plan.content_bytes);
        let request = build_request(&plan.addr, &plan.token, &content);

        // Latency covers the socket round trip only; content generation and hashing
        // above are client-side costs excluded from the measurement.
        let started = Instant::now();
        let outcome = exchange(stream, &request);
        let completed = Instant::now();
        match outcome {
            Ok(()) => {
                // Warmup completions are discarded. A tail request completing just past
                // the deadline is kept because the service performed its work in full.
                if completed >= plan.measure_start {
                    latencies.push(duration_micros(completed - started));
                }
            }
            Err(error) => {
                errors.record(error);
                // The framing on this connection can no longer be trusted after a
                // failure, so it is dropped and rebuilt after a short pause.
                connection = None;
                thread::sleep(RECONNECT_BACKOFF);
            }
        }
    }
    latencies
}

/// Opens a benchmark connection with Nagle's algorithm disabled — so small requests
/// measure service latency rather than kernel batching — and bounded socket waits.
fn connect(addr: &str) -> Result<TcpStream, String> {
    let stream =
        TcpStream::connect(addr).map_err(|error| format!("connect to {addr} failed: {error}"))?;
    stream
        .set_nodelay(true)
        .and_then(|()| stream.set_read_timeout(Some(SOCKET_TIMEOUT)))
        .and_then(|()| stream.set_write_timeout(Some(SOCKET_TIMEOUT)))
        .map_err(|error| format!("socket configuration for {addr} failed: {error}"))?;
    Ok(stream)
}

/// Produces unique plain-ASCII content of approximately the requested byte length.
/// Uniqueness keeps content-hash index inserts realistically random; when the target
/// is smaller than the unique prefix, the whole prefix is used, slightly over target.
fn generate_content(worker_id: usize, request_number: u64, content_bytes: usize) -> String {
    let mut content = format!("bench worker {worker_id} request {request_number} ");
    while content.len() < content_bytes {
        let remaining = content_bytes - content.len();
        content.push_str(&CONTENT_FILLER[..remaining.min(CONTENT_FILLER.len())]);
    }
    content
}

/// Builds one complete HTTP/1.1 keep-alive request with the JSON assessment body.
fn build_request(addr: &str, token: &str, content: &str) -> Vec<u8> {
    let content_sha256 = hex::encode(Sha256::digest(content.as_bytes()));
    let body = json!({ "content": content, "content_sha256": content_sha256 }).to_string();
    format!(
        "POST /v1/assess HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\
Content-Type: application/json\r\nContent-Length: {length}\r\n\r\n{body}",
        length = body.len()
    )
    .into_bytes()
}

/// Sends one request and reads and validates its complete response on the connection.
fn exchange(stream: &mut TcpStream, request: &[u8]) -> Result<(), String> {
    stream
        .write_all(request)
        .map_err(|error| format!("request write failed: {error}"))?;
    let (status, body) = read_response(stream)?;
    validate_response(status, &body)
}

/// Reads exactly one Content-Length-framed HTTP/1.1 response from the connection.
/// Chunked or close-delimited responses are benchmark errors by specification.
fn read_response(stream: &mut TcpStream) -> Result<(u16, Vec<u8>), String> {
    let mut buffer: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(position) = find_header_end(&buffer) {
            break position;
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err("response headers exceed the header size bound".to_owned());
        }
        let read = stream
            .read(&mut chunk)
            .map_err(|error| format!("response read failed: {error}"))?;
        if read == 0 {
            return Err("connection closed before response headers completed".to_owned());
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let header_text = std::str::from_utf8(&buffer[..header_end])
        .map_err(|error| format!("response headers are not UTF-8: {error}"))?;
    let status = parse_status(header_text)?;
    let content_length = parse_content_length(header_text)?;

    // The header read may already hold body bytes; keep them and read the remainder.
    let body_start = header_end + 4;
    let mut body = buffer[body_start..].to_vec();
    while body.len() < content_length {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| format!("response read failed: {error}"))?;
        if read == 0 {
            return Err("connection closed before response body completed".to_owned());
        }
        body.extend_from_slice(&chunk[..read]);
    }
    // Only one request is in flight per connection, so bytes past Content-Length mean
    // the framing assumption broke; failing here forces a clean reconnect.
    if body.len() > content_length {
        return Err("response body exceeded its Content-Length".to_owned());
    }
    Ok((status, body))
}

/// Locates the CRLFCRLF terminator, returning the byte index where headers end.
fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Extracts the numeric status code from the HTTP/1.1 status line.
fn parse_status(header_text: &str) -> Result<u16, String> {
    let status_line = header_text
        .lines()
        .next()
        .ok_or_else(|| "response is missing a status line".to_owned())?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("malformed status line {status_line:?}"))?;
    code.parse::<u16>()
        .map_err(|error| format!("malformed status code {code:?}: {error}"))
}

/// Requires an explicit Content-Length header; the harness does not implement chunked framing.
fn parse_content_length(header_text: &str) -> Result<usize, String> {
    for line in header_text.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            let value = value.trim();
            return value
                .parse::<usize>()
                .map_err(|error| format!("invalid Content-Length {value:?}: {error}"));
        }
    }
    Err("response has no Content-Length header".to_owned())
}

/// Confirms the service completed the assessment with the expected `safe` verdict.
fn validate_response(status: u16, body: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(body)
        .map_err(|error| format!("response body is not UTF-8: {error}"))?;
    // Error bodies are compact reason JSON and never echo submitted content, so
    // including them in the sample is safe and preserves the diagnostic cause.
    if status != 200 {
        return Err(format!("unexpected status {status}: {text}"));
    }
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|error| format!("response body is not JSON: {error}"))?;
    match value.get("verdict").and_then(|verdict| verdict.as_str()) {
        Some("safe") => Ok(()),
        Some(other) => Err(format!("unexpected verdict {other:?}")),
        None => Err("response JSON has no verdict field".to_owned()),
    }
}

/// Converts a request latency into bounded whole microseconds for aggregation.
fn duration_micros(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

/// Returns the nearest-rank percentile from latencies sorted ascending, or zero when empty.
fn percentile_micros(sorted: &[u64], percentile: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((percentile / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

/// Renders stored microseconds as fractional milliseconds for the report.
fn millis(micros: u64) -> f64 {
    micros as f64 / 1000.0
}
