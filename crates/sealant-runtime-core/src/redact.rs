//! Secret redaction for recorded I/O (plan §18). Masks configured literal secrets (e.g. the values
//! of secret-looking env vars) and high-confidence token shapes, never silently — each masked span
//! is counted and surfaced as `transform.redacted` + the `redactedEvents` health counter.
//!
//! A [`Redactor`] is the immutable set of patterns. Each recorded stream (a process's stdout, its
//! stderr, a session's input) masks through its own [`StreamRedactor`], which records the same
//! bytes however the stream was split into reads: it holds back a suffix that could still begin a
//! secret, never releases it on a timer, and masks the union of every match.

use std::fmt;
use std::sync::Arc;

use sealant_protocol::{Base64Bytes, Encoding, IoChunk, StreamKind, StreamOffset, TransformMeta};

const REDACTED: &[u8] = b"***REDACTED***";

/// High-confidence secret token prefixes. A match is redacted only when the full token reaches
/// [`MIN_TOKEN_LEN`], to avoid masking ordinary words.
const TOKEN_PREFIXES: &[&[u8]] = &[
    b"sk-",
    b"ghp_",
    b"gho_",
    b"ghs_",
    b"github_pat_",
    b"AKIA",
    b"xoxb-",
    b"xoxp-",
    b"glpat-",
    b"AIza",
];

const MIN_TOKEN_LEN: usize = 16;

/// Literals shorter than this are ignored, to avoid masking common substrings.
const MIN_LITERAL_LEN: usize = 6;

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// The patterns recorded I/O is masked with: literal secrets plus the built-in token shapes.
#[derive(Default, Clone)]
pub struct Redactor {
    literals: Vec<Vec<u8>>,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor")
            .field("literals", &self.literals.len())
            .finish()
    }
}

impl Redactor {
    /// Build a redactor that masks the given literal secrets (in addition to built-in token shapes).
    /// Literals shorter than 6 bytes are ignored to avoid masking common substrings.
    #[must_use]
    pub fn new(literals: Vec<String>) -> Self {
        let literals = literals
            .into_iter()
            .filter(|l| l.len() >= MIN_LITERAL_LEN)
            .map(String::into_bytes)
            .collect();
        Self { literals }
    }

    /// Redact secrets in `input`. Returns the (possibly unchanged) bytes and the number of masked
    /// spans.
    #[must_use]
    pub fn redact(&self, input: &[u8]) -> (Vec<u8>, u32) {
        let mut out = Vec::with_capacity(input.len());
        let mut count = 0u32;
        let mut i = 0;
        'outer: while i < input.len() {
            for literal in &self.literals {
                if input[i..].starts_with(literal) {
                    out.extend_from_slice(REDACTED);
                    i += literal.len();
                    count += 1;
                    continue 'outer;
                }
            }
            for prefix in TOKEN_PREFIXES {
                if input[i..].starts_with(prefix) {
                    let mut end = i + prefix.len();
                    while end < input.len() && is_token_char(input[end]) {
                        end += 1;
                    }
                    if end - i >= MIN_TOKEN_LEN {
                        out.extend_from_slice(REDACTED);
                        i = end;
                        count += 1;
                        continue 'outer;
                    }
                }
            }
            out.push(input[i]);
            i += 1;
        }
        (out, count)
    }

    /// The same patterns plus each multi-line literal as a terminal echoes it: a PTY's output
    /// discipline (ONLCR) writes every LF as CRLF.
    #[must_use]
    pub fn for_pty(&self) -> Self {
        let mut literals = self.literals.clone();
        for literal in &self.literals {
            if literal.contains(&b'\n') {
                let mut crlf = Vec::with_capacity(literal.len() + 8);
                for &b in literal {
                    if b == b'\n' {
                        crlf.push(b'\r');
                    }
                    crlf.push(b);
                }
                literals.push(crlf);
            }
        }
        Self { literals }
    }

    /// A fresh masking state for one recorded stream, sharing these patterns.
    #[must_use]
    pub fn stream(self: &Arc<Self>) -> StreamRedactor {
        StreamRedactor {
            patterns: self.clone(),
            pending: Vec::new(),
            covered: Vec::new(),
            base: 0,
            literal_at: 0,
            token_at: 0,
            token: TokenScan::Searching,
            in_mask: false,
        }
    }
}

/// Where the token heuristic stands at the next byte it scans.
#[derive(Clone, Copy)]
enum TokenScan {
    Searching,
    /// A token prefix starts at this stream position and its run is still under the minimum.
    Candidate(u64),
    /// The run reached the minimum: every token byte up to the next delimiter is masked.
    Masking,
}

/// How a recorded stream ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinishReason {
    /// The writer closed: a suffix that could have begun a secret did not.
    Eof,
    /// Reading stopped early (a drain cutoff, a read error): a suffix that could begin a literal
    /// secret, or a token past its prefix, is masked.
    Cutoff,
}

/// One stream's masking state. Positions count raw bytes from the start of the stream.
pub struct StreamRedactor {
    patterns: Arc<Redactor>,
    /// Undecided raw bytes, from stream position `base`.
    pending: Vec<u8>,
    /// Per pending byte: already known to lie in a match.
    covered: Vec<bool>,
    base: u64,
    /// The next position a literal match is looked for at.
    literal_at: u64,
    /// The next position the token heuristic scans.
    token_at: u64,
    token: TokenScan,
    /// The last recorded output is a marker whose span may continue.
    in_mask: bool,
}

impl fmt::Debug for StreamRedactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamRedactor").finish_non_exhaustive()
    }
}

impl StreamRedactor {
    /// Mask the next raw bytes of the stream. The chunk holds what is now decided, which can
    /// include bytes held from earlier pushes and leaves out a suffix that could still begin a
    /// secret.
    pub fn push(&mut self, raw: &[u8]) -> MaskedChunk {
        self.pending.extend_from_slice(raw);
        self.covered.resize(self.pending.len(), false);
        self.scan(false);
        let token_hold = match self.token {
            TokenScan::Candidate(start) => start,
            TokenScan::Searching | TokenScan::Masking => self.token_at,
        };
        self.emit_until(self.literal_at.min(token_hold))
    }

    /// End the stream and record everything still held. Call before the stream's terminal event.
    pub fn finish(mut self, reason: FinishReason) -> MaskedChunk {
        let end = self.end();
        if reason == FinishReason::Cutoff {
            let literal = (self.literal_at < end).then_some(self.literal_at);
            let token = match self.token {
                TokenScan::Candidate(start) => Some(start),
                TokenScan::Searching | TokenScan::Masking => None,
            };
            if let Some(from) = literal.into_iter().chain(token).min() {
                let from = self.index(from);
                self.covered[from..].fill(true);
            }
        }
        self.scan(true);
        self.emit_until(end)
    }

    fn end(&self) -> u64 {
        self.base + self.pending.len() as u64
    }

    fn index(&self, position: u64) -> usize {
        usize::try_from(position - self.base).unwrap_or(usize::MAX)
    }

    /// Advance both scans over the pending bytes. A scan stops where more bytes could change its
    /// answer, unless `at_end` says none will come.
    fn scan(&mut self, at_end: bool) {
        let end = self.end();
        while self.literal_at < end {
            let i = self.index(self.literal_at);
            let rest = &self.pending[i..];
            let mut undecided = false;
            for literal in &self.patterns.literals {
                if rest.starts_with(literal) {
                    self.covered[i..i + literal.len()].fill(true);
                } else if !at_end && literal.starts_with(rest) {
                    undecided = true;
                }
            }
            if undecided {
                break;
            }
            self.literal_at += 1;
        }
        while self.token_at < end {
            let i = self.index(self.token_at);
            if !is_token_char(self.pending[i]) {
                self.token = TokenScan::Searching;
            } else {
                if let TokenScan::Searching = self.token {
                    let rest = &self.pending[i..];
                    if TOKEN_PREFIXES.iter().any(|p| rest.starts_with(p)) {
                        self.token = TokenScan::Candidate(self.token_at);
                    } else if !at_end && TOKEN_PREFIXES.iter().any(|p| p.starts_with(rest)) {
                        break;
                    }
                }
                match self.token {
                    TokenScan::Searching => {}
                    TokenScan::Candidate(start) => {
                        if self.token_at + 1 - start >= MIN_TOKEN_LEN as u64 {
                            let from = self.index(start);
                            self.covered[from..=i].fill(true);
                            self.token = TokenScan::Masking;
                        }
                    }
                    TokenScan::Masking => self.covered[i] = true,
                }
            }
            self.token_at += 1;
        }
    }

    /// Record the pending bytes before stream position `upto`: one marker per covered span.
    fn emit_until(&mut self, upto: u64) -> MaskedChunk {
        let n = self.index(upto);
        let mut recorded = Vec::with_capacity(n);
        let mut redactions = 0;
        for (&b, &covered) in self.pending[..n].iter().zip(&self.covered[..n]) {
            if !covered {
                recorded.push(b);
                self.in_mask = false;
            } else if !self.in_mask {
                recorded.extend_from_slice(REDACTED);
                redactions += 1;
                self.in_mask = true;
            }
        }
        self.pending.drain(..n);
        self.covered.drain(..n);
        self.base = upto;
        MaskedChunk {
            recorded,
            consumed: n as u64,
            redactions,
        }
    }
}

/// What a stream records for the raw bytes it has decided. Only a [`StreamRedactor`] makes one,
/// so nothing recorded can come from raw bytes that skipped masking.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct MaskedChunk {
    recorded: Vec<u8>,
    consumed: u64,
    redactions: u32,
}

impl MaskedChunk {
    /// The bytes to record, secrets masked.
    #[must_use]
    pub fn recorded(&self) -> &[u8] {
        &self.recorded
    }

    /// How many raw stream bytes this chunk stands for: a stream's offset advances by this.
    #[must_use]
    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Masked spans that start in this chunk.
    #[must_use]
    pub fn redactions(&self) -> u32 {
        self.redactions
    }

    /// Whether any raw byte this chunk stands for was masked (a span begun in an earlier chunk
    /// can cover bytes here without a new marker).
    #[must_use]
    pub fn is_redacted(&self) -> bool {
        self.redactions > 0 || self.recorded.len() as u64 != self.consumed
    }

    /// The telemetry chunk recording it at raw position `offset` of `stream`; `None` when it
    /// stands for no raw byte yet.
    #[must_use]
    pub fn io_chunk(&self, stream: StreamKind, offset: StreamOffset) -> Option<IoChunk> {
        (self.consumed > 0).then(|| IoChunk {
            stream,
            encoding: Encoding::Base64,
            byte_count: self.recorded.len() as u64,
            stream_offset: offset,
            content: Some(Base64Bytes::new(self.recorded.as_slice())),
            artifact: None,
            transform: self.is_redacted().then_some(TransformMeta {
                redacted: true,
                truncated: false,
                coalesced: false,
                original_byte_count: Some(self.consumed),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"super-secret-value-123";

    fn patterns(literals: &[&str]) -> Arc<Redactor> {
        Arc::new(Redactor::new(
            literals.iter().map(|l| (*l).to_owned()).collect(),
        ))
    }

    /// Mask `input` pushed in `pieces`, checking each step against the whole-input answer.
    fn masked(redactor: &Arc<Redactor>, pieces: &[&[u8]], reason: FinishReason) -> MaskedRun {
        let mut stream = redactor.stream();
        let mut run = MaskedRun::default();
        for piece in pieces {
            run.add(stream.push(piece));
        }
        run.add(stream.finish(reason));
        run
    }

    #[derive(Default, Debug)]
    struct MaskedRun {
        recorded: Vec<u8>,
        chunks: Vec<MaskedChunk>,
        consumed: u64,
        redactions: u32,
    }

    impl MaskedRun {
        fn add(&mut self, chunk: MaskedChunk) {
            self.recorded.extend_from_slice(chunk.recorded());
            self.consumed += chunk.consumed();
            self.redactions += chunk.redactions();
            self.chunks.push(chunk);
        }
    }

    fn whole(redactor: &Arc<Redactor>, input: &[u8]) -> (Vec<u8>, u32) {
        let run = masked(redactor, &[input], FinishReason::Eof);
        (run.recorded, run.redactions)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// The masking rules over a whole input, written apart from the streaming code: every byte of
    /// every literal occurrence, and every token the original one-pass scan masked, with one
    /// marker per covered span.
    fn reference(literals: &[Vec<u8>], input: &[u8]) -> (Vec<u8>, u32) {
        let mut covered = vec![false; input.len()];
        for literal in literals {
            for start in 0..input.len() {
                if input[start..].starts_with(literal) {
                    covered[start..start + literal.len()].fill(true);
                }
            }
        }
        let mut i = 0;
        while i < input.len() {
            if TOKEN_PREFIXES.iter().any(|p| input[i..].starts_with(p)) {
                let mut end = i;
                while end < input.len() && is_token_char(input[end]) {
                    end += 1;
                }
                if end - i >= MIN_TOKEN_LEN {
                    covered[i..end].fill(true);
                    i = end;
                    continue;
                }
            }
            i += 1;
        }
        let mut out = Vec::new();
        let mut spans = 0;
        for (idx, &b) in input.iter().enumerate() {
            if !covered[idx] {
                out.push(b);
            } else if idx == 0 || !covered[idx - 1] {
                out.extend_from_slice(REDACTED);
                spans += 1;
            }
        }
        (out, spans)
    }

    /// A seeded xorshift generator, so a failing case reruns from its seed.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n as u64) as usize
        }
    }

    #[test]
    fn redacts_known_token_shapes() {
        let (out, n) = whole(
            &Arc::new(Redactor::default()),
            b"using sk-abcdef012345678901234567 now",
        );
        assert_eq!(n, 1);
        assert_eq!(out, b"using ***REDACTED*** now");
    }

    #[test]
    fn redacts_configured_literal_secret() {
        let (out, n) = whole(
            &patterns(&["super-secret-value-123"]),
            b"TOKEN=super-secret-value-123\n",
        );
        assert_eq!(n, 1);
        assert_eq!(out, b"TOKEN=***REDACTED***\n");
    }

    #[test]
    fn leaves_ordinary_text_and_short_tokens_alone() {
        let (out, n) = whole(&Arc::new(Redactor::default()), b"hello world, sk-short");
        assert_eq!(n, 0);
        assert_eq!(out, b"hello world, sk-short");
    }

    #[test]
    fn counts_multiple_redactions_and_is_binary_safe() {
        let mut input = b"\x00\xffliteralsecret AKIA0123456789ABCDEF\x00".to_vec();
        input.extend_from_slice(b" ghp_0123456789abcdefghij");
        let (out, n) = whole(&patterns(&["literalsecret"]), &input);
        assert_eq!(n, 3);
        assert_eq!(
            out,
            b"\x00\xff***REDACTED*** ***REDACTED***\x00 ***REDACTED***"
        );
    }

    #[test]
    fn a_literal_split_across_pushes_is_masked() {
        let run = masked(
            &patterns(&["super-secret-value-123"]),
            &[b"TOKEN=super-sec", b"ret-value-123\n"],
            FinishReason::Eof,
        );
        assert_eq!(run.recorded, b"TOKEN=***REDACTED***\n");
        assert!(run.chunks.iter().all(|c| !contains(c.recorded(), b"super")));
    }

    #[test]
    fn overlapping_literals_mask_their_union() {
        let redactor = patterns(&["abcdef", "defghi"]);
        let (out, n) = whole(&redactor, b"xxabcdefghiyy");
        assert_eq!(out, b"xx***REDACTED***yy");
        assert_eq!(n, 1);
        let run = masked(&redactor, &[b"xxabcde", b"fgh", b"iyy"], FinishReason::Eof);
        assert_eq!(run.recorded, b"xx***REDACTED***yy");
    }

    #[test]
    fn a_pty_patterns_mask_a_multiline_secret_as_the_terminal_echoes_it() {
        let base = patterns(&["line-one\nline-two"]);
        let echoed: &[u8] = b"> line-one\r\nline-two\r\n";
        let (out, _) = whole(&base, echoed);
        assert!(contains(&out, b"line-one"), "pipe patterns keep LF only");
        let pty = Arc::new(base.for_pty());
        let (out, n) = whole(&pty, echoed);
        assert_eq!(out, b"> ***REDACTED***\r\n");
        assert_eq!(n, 1);
        let (out, _) = whole(&pty, b"line-one\nline-two");
        assert_eq!(out, REDACTED, "the LF form still masks under a PTY");
    }

    #[test]
    fn only_a_suffix_that_could_begin_a_secret_is_held() {
        let redactor = patterns(&["0123456789abcdef"]);
        let mut stream = redactor.stream();
        let chunk = stream.push(b"text 0123456789abcde");
        assert_eq!(chunk.recorded(), b"text ");
        assert_eq!(
            chunk.consumed(),
            5,
            "15 bytes held: one short of the literal"
        );
        let chunk = stream.push(b"!");
        assert_eq!(chunk.recorded(), b"0123456789abcde!");
        assert_eq!(chunk.consumed(), 16);
        let chunk = stream.push(b"plain text.");
        assert_eq!(chunk.recorded(), b"plain text.");
        assert_eq!(chunk.consumed(), 11);
    }

    #[test]
    fn a_long_token_is_masked_up_to_its_delimiter_in_any_split() {
        let redactor = Arc::new(Redactor::default());
        let input: &[u8] = b"key ghp_0123456789abcdefghijklmnopqrstuvwxyz0123456789 end";
        let bytes: Vec<&[u8]> = input.chunks(1).collect();
        let run = masked(&redactor, &bytes, FinishReason::Eof);
        assert_eq!(run.recorded, b"key ***REDACTED*** end");
        assert_eq!(run.redactions, 1);
        let mut stream = redactor.stream();
        let _ = stream.push(b"key ghp_0123456789abcdef");
        let chunk = stream.push(b"ghijklmnopqrstuvwxyz");
        assert!(
            chunk.recorded().is_empty(),
            "the token's tail records nothing"
        );
        assert_eq!(chunk.consumed(), 20);
        assert!(
            chunk.is_redacted(),
            "the tail is masked by the span begun before it"
        );
        assert_eq!(chunk.redactions(), 0, "and starts no new span");
    }

    #[test]
    fn a_cutoff_masks_what_could_still_be_a_secret() {
        let redactor = patterns(&["super-secret-value-123"]);
        let run = masked(&redactor, &[b"pass: super-sec"], FinishReason::Cutoff);
        assert_eq!(run.recorded, b"pass: ***REDACTED***");
        let run = masked(&redactor, &[b"pass: super-sec"], FinishReason::Eof);
        assert_eq!(
            run.recorded, b"pass: super-sec",
            "at true EOF it was not a secret"
        );

        let tokens = Arc::new(Redactor::default());
        let run = masked(&tokens, &[b"auth sk-0123456"], FinishReason::Cutoff);
        assert_eq!(
            run.recorded, b"auth ***REDACTED***",
            "a token past its prefix"
        );
        let run = masked(&tokens, &[b"a task"], FinishReason::Cutoff);
        assert_eq!(run.recorded, b"a task", "a token prefix alone is no secret");
    }

    #[test]
    fn every_partition_records_what_one_pass_records() {
        let literals = [
            "super-secret-value-123",
            "abcdef",
            "defghi",
            "été-漢字-pw",
            "line-one\nline-two",
        ];
        let base = patterns(&literals);
        let fragments: &[&[u8]] = &[
            SECRET,
            b"abcdefghi",
            b"abcde",
            "été-漢字-pw".as_bytes(),
            "été-漢".as_bytes(),
            b"line-one\nline-two",
            b"line-one\r\nline-two",
            b"line-one\r\n",
            b"ghp_0123456789abcdefghij",
            b"sk-short",
            b"sk-",
            b"AKIA",
            b"\r\n",
            b" ",
            b"plain text ",
            b"\x00\xff",
            b"super-",
        ];
        for redactor in [base.clone(), Arc::new(base.for_pty())] {
            let longest = redactor.literals.iter().map(Vec::len).max().unwrap_or(0);
            let bound = (longest - 1).max(MIN_TOKEN_LEN - 1) as u64;
            for seed in 1..=400u64 {
                let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
                let mut input = Vec::new();
                for _ in 0..rng.below(12) + 1 {
                    input.extend_from_slice(fragments[rng.below(fragments.len())]);
                }
                let (want, spans) = reference(&redactor.literals, &input);
                let mut pieces = Vec::new();
                let mut at = 0;
                while at < input.len() {
                    let len = if seed % 5 == 0 {
                        1
                    } else {
                        (rng.below(9) + 1).min(input.len() - at)
                    };
                    pieces.push(&input[at..at + len]);
                    at += len;
                }
                let mut stream = redactor.stream();
                let mut recorded = Vec::new();
                let mut pushed = 0u64;
                let mut consumed = 0u64;
                let mut redactions = 0;
                for piece in &pieces {
                    let chunk = stream.push(piece);
                    pushed += piece.len() as u64;
                    consumed += chunk.consumed();
                    redactions += chunk.redactions();
                    recorded.extend_from_slice(chunk.recorded());
                    assert!(
                        want.starts_with(&recorded),
                        "seed {seed}: recorded {:?} before the whole answer {:?}",
                        String::from_utf8_lossy(&recorded),
                        String::from_utf8_lossy(&want)
                    );
                    assert!(
                        pushed - consumed <= bound,
                        "seed {seed}: held past the bound"
                    );
                }
                let last = stream.finish(FinishReason::Eof);
                consumed += last.consumed();
                redactions += last.redactions();
                recorded.extend_from_slice(last.recorded());
                assert_eq!(
                    String::from_utf8_lossy(&recorded),
                    String::from_utf8_lossy(&want),
                    "seed {seed}"
                );
                assert_eq!(consumed, input.len() as u64, "seed {seed}");
                assert_eq!(redactions, spans, "seed {seed}");
                for literal in &redactor.literals {
                    assert!(
                        !contains(&recorded, literal),
                        "seed {seed}: a literal recorded"
                    );
                }
            }
        }
    }

    #[test]
    fn debug_prints_no_pattern_or_pending_byte() {
        let redactor = patterns(&["super-secret-value-123"]);
        let mut stream = redactor.stream();
        let _ = stream.push(b"super-secret");
        let shown = format!("{redactor:?} {stream:?}");
        assert!(!shown.contains("super"), "{shown}");
        assert!(!shown.contains("115, 117, 112"), "nor its bytes: {shown}");
    }
}
