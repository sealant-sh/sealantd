//! One recorded stream: its masking state, its raw offset, and its `io.chunk` events.

use std::fmt;
use std::sync::Arc;

use sealant_protocol::{CaptureMethod, Confidence, EventPayload, StreamKind, StreamOffset};
use sealant_runtime_core::{FinishReason, MaskedChunk, RuntimeStatus, StreamRedactor};

use crate::{Correlation, EventBus};

/// Records one stream (a process's stdout or stderr, a session's output or input) as masked
/// `io.chunk` events. Each read goes through [`StreamRecorder::read`], and the stream's end, or a
/// cut in it, through [`StreamRecorder::end`]; a journaled stream uses their `_journaled` forms.
pub struct StreamRecorder {
    bus: Arc<EventBus>,
    status: Arc<RuntimeStatus>,
    correlation: Correlation,
    method: CaptureMethod,
    stream: StreamKind,
    masker: StreamRedactor,
    offset: StreamOffset,
}

impl fmt::Debug for StreamRecorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamRecorder")
            .field("stream", &self.stream)
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

impl StreamRecorder {
    /// A recorder for `stream`, masking with `masker`, from raw offset 0.
    #[must_use]
    pub fn new(
        bus: Arc<EventBus>,
        status: Arc<RuntimeStatus>,
        correlation: Correlation,
        method: CaptureMethod,
        stream: StreamKind,
        masker: StreamRedactor,
    ) -> Self {
        Self {
            bus,
            status,
            correlation,
            method,
            stream,
            masker,
            offset: StreamOffset::ZERO,
        }
    }

    /// Record the next raw bytes of the stream.
    pub fn read(&mut self, raw: &[u8]) {
        let _ = self.read_journaled(raw, |_| ());
    }

    /// End the stream, or cut it, recording what the masker still holds. Call before the stream's
    /// terminal event; bytes read after it start a new masking state at the same offset.
    pub fn end(&mut self, reason: FinishReason) {
        let _ = self.end_journaled(reason, |_| ());
    }

    /// [`StreamRecorder::read`] for a journaled stream: `journal` gets the masked chunk before
    /// its event is published, so a reader the event wakes finds the bytes journaled.
    pub fn read_journaled<T>(
        &mut self,
        raw: &[u8],
        journal: impl FnOnce(&MaskedChunk) -> T,
    ) -> (MaskedChunk, T) {
        let chunk = self.masker.push(raw);
        let journaled = journal(&chunk);
        self.publish(&chunk);
        (chunk, journaled)
    }

    /// [`StreamRecorder::end`] for a journaled stream.
    pub fn end_journaled<T>(
        &mut self,
        reason: FinishReason,
        journal: impl FnOnce(&MaskedChunk) -> T,
    ) -> (MaskedChunk, T) {
        let chunk = self.masker.finish(reason);
        let journaled = journal(&chunk);
        self.publish(&chunk);
        (chunk, journaled)
    }

    fn publish(&mut self, chunk: &MaskedChunk) {
        self.status.add_redacted(chunk.redactions());
        if let Some(io) = chunk.io_chunk(self.stream, self.offset) {
            self.bus.publish_recorded(
                &self.correlation,
                self.method,
                Confidence::Observed,
                EventPayload::IoChunk(io),
            );
        }
        self.offset = self.offset.advance(chunk.consumed());
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::disallowed_types, reason = "the tests read io.chunk events")]
    use super::*;
    use sealant_protocol::{EventEnvelope, IoChunk};
    use sealant_runtime_core::{Clock, IdGenerator, Redactor, new_runtime_id};
    use tokio::sync::broadcast::Receiver;

    fn recorder(literals: &[&str]) -> (StreamRecorder, Receiver<EventEnvelope>) {
        let rt = new_runtime_id();
        let bus = Arc::new(EventBus::new(
            rt.clone(),
            Arc::new(Clock::new()),
            Arc::new(IdGenerator::new(&rt)),
            64,
        ));
        let rx = bus.subscribe();
        let redactor = Arc::new(Redactor::new(
            literals.iter().map(|l| (*l).to_owned()).collect(),
        ));
        let recorder = StreamRecorder::new(
            bus,
            Arc::new(RuntimeStatus::new()),
            Correlation::new(),
            CaptureMethod::Pipe,
            StreamKind::Stdout,
            redactor.stream(),
        );
        (recorder, rx)
    }

    fn io_chunk(rx: &mut Receiver<EventEnvelope>) -> Option<IoChunk> {
        match rx.try_recv().ok()?.payload {
            EventPayload::IoChunk(chunk) => Some(chunk),
            _ => None,
        }
    }

    /// An io.chunk with content published past the recorder is refused.
    #[test]
    #[should_panic(expected = "io.chunk content is published through StreamRecorder")]
    fn the_bus_refuses_io_chunk_content_from_anywhere_else() {
        let (recorder, _rx) = recorder(&[]);
        let masked = Arc::new(Redactor::default()).stream().push(b"raw");
        let chunk = masked
            .io_chunk(StreamKind::Stdout, StreamOffset::ZERO)
            .expect("a chunk");
        recorder.bus.publish(
            &Correlation::new(),
            CaptureMethod::Pipe,
            Confidence::Observed,
            EventPayload::IoChunk(chunk),
        );
    }

    /// A journal sees each chunk before its event is published.
    #[test]
    fn the_journal_sees_a_chunk_before_its_event() {
        let (mut recorder, mut rx) = recorder(&[]);
        let (_, published_first) = recorder.read_journaled(b"hello", |_| rx.try_recv().is_ok());
        assert!(!published_first, "no event before the journal");
        let chunk = io_chunk(&mut rx).expect("then the event");
        assert_eq!(chunk.content.expect("content").as_slice(), b"hello");
    }

    /// Offsets count raw bytes: a held part publishes nothing, and the chunk that decides it
    /// starts where the held bytes did. A cut masks what is held and the stream goes on.
    #[test]
    fn offsets_count_raw_bytes_across_holds_and_cuts() {
        let (mut recorder, mut rx) = recorder(&["split-secret-value-42"]);
        recorder.read(b"pw=split-secr");
        let first = io_chunk(&mut rx).expect("the decided part");
        assert_eq!(
            (first.stream_offset.get(), first.byte_count),
            (0, 3),
            "pw= at 0"
        );
        recorder.end(FinishReason::Cutoff);
        let cut = io_chunk(&mut rx).expect("the cut");
        assert_eq!(cut.stream_offset.get(), 3);
        assert_eq!(cut.content.expect("content").as_slice(), b"***REDACTED***");
        recorder.read(b"next");
        let next = io_chunk(&mut rx).expect("after the cut");
        assert_eq!(next.stream_offset.get(), 13, "3 + the 10 held bytes");
    }
}
