//! The span pipeline, built before it may start a thread.
//!
//! A microVM guest must stay on one thread until it has set its environment, and the VM runner
//! until it has dropped privileges, yet both make spans before then. [`Deferred`] is the
//! provider's processor from the start: it holds up to [`PENDING`] finished spans until
//! [`Deferred::run`] gives it the batch processor (whose thread starts then) or [`Deferred::off`]
//! drops them. Its [`Sampler`] records nothing once the pipeline is off.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use opentelemetry::trace::{Link, SpanKind, TraceId};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::Resource;

use crate::conventions;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{
    BatchSpanProcessor, Sampler as SdkSampler, SamplingDecision, SamplingResult, ShouldSample,
    Span, SpanData, SpanProcessor,
};

/// Finished spans held before the pipeline starts (a boot's worth).
pub(crate) const PENDING: usize = 1024;

#[derive(Debug)]
enum Stage {
    Pending(VecDeque<SpanData>),
    Running(BatchSpanProcessor),
    Off,
}

#[derive(Debug)]
pub(crate) struct Shared {
    stage: RwLock<Stage>,
    /// The sample rate's bits (an f64).
    rate: AtomicU64,
    resource: Mutex<Option<Resource>>,
    /// What every exported span carries ([`conventions::finish`]).
    common: RwLock<Vec<KeyValue>>,
}

impl Shared {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            stage: RwLock::new(Stage::Pending(VecDeque::new())),
            rate: AtomicU64::new(1.0_f64.to_bits()),
            resource: Mutex::new(None),
            common: RwLock::new(Vec::new()),
        })
    }

    fn rate(&self) -> f64 {
        f64::from_bits(self.rate.load(Ordering::Relaxed))
    }

    fn is_off(&self) -> bool {
        matches!(
            *self.stage.read().unwrap_or_else(PoisonError::into_inner),
            Stage::Off
        )
    }

    /// Set `key` on every span exported from now on, replacing an earlier value.
    pub(crate) fn tag(&self, attribute: KeyValue) {
        let mut common = self.common.write().unwrap_or_else(PoisonError::into_inner);
        common.retain(|kv| kv.key != attribute.key);
        common.push(attribute);
    }

    /// Hand `span` to `processor` with what Sentry needs to show it.
    fn export(&self, processor: &BatchSpanProcessor, mut span: SpanData) {
        conventions::finish(
            &mut span,
            &self.common.read().unwrap_or_else(PoisonError::into_inner),
        );
        processor.on_end(span);
    }

    /// Start exporting through `processor`, held spans first. Extra resource attributes (the
    /// environment and release, known only now) join the provider's; `common` joins every span's.
    pub(crate) fn run(
        &self,
        mut processor: BatchSpanProcessor,
        extra: Vec<KeyValue>,
        common: Vec<KeyValue>,
        rate: f64,
    ) {
        for attribute in common {
            self.tag(attribute);
        }
        self.rate.store(rate.to_bits(), Ordering::Relaxed);
        let base = self
            .resource
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| Resource::builder_empty().build());
        let resource = Resource::builder_empty()
            .with_attributes(
                base.iter()
                    .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
            )
            .with_attributes(extra)
            .build();
        processor.set_resource(&resource);
        let mut stage = self.stage.write().unwrap_or_else(PoisonError::into_inner);
        let held = match std::mem::replace(&mut *stage, Stage::Off) {
            Stage::Pending(held) => held,
            // Started twice: keep the first pipeline.
            running @ Stage::Running(_) => {
                *stage = running;
                return;
            }
            Stage::Off => VecDeque::new(),
        };
        for span in held {
            self.export(&processor, span);
        }
        *stage = Stage::Running(processor);
    }

    /// Export nothing, now or later: held spans are dropped.
    pub(crate) fn off(&self) {
        let mut stage = self.stage.write().unwrap_or_else(PoisonError::into_inner);
        if matches!(*stage, Stage::Pending(_)) {
            *stage = Stage::Off;
        }
    }

    /// Export what is queued, within `timeout`, and stop.
    fn shutdown(&self, timeout: Duration) -> OTelSdkResult {
        match &*self.stage.read().unwrap_or_else(PoisonError::into_inner) {
            Stage::Running(processor) => processor.shutdown_with_timeout(timeout),
            Stage::Pending(_) | Stage::Off => Ok(()),
        }
    }
}

/// The provider's one processor.
#[derive(Debug)]
pub(crate) struct Deferred(pub(crate) Arc<Shared>);

impl SpanProcessor for Deferred {
    fn on_start(&self, _span: &mut Span, _cx: &Context) {}

    fn on_end(&self, span: SpanData) {
        {
            let stage = self.0.stage.read().unwrap_or_else(PoisonError::into_inner);
            match &*stage {
                Stage::Running(processor) => return self.0.export(processor, span),
                Stage::Off => return,
                Stage::Pending(_) => {}
            }
        }
        let mut stage = self.0.stage.write().unwrap_or_else(PoisonError::into_inner);
        match &mut *stage {
            Stage::Pending(held) => {
                if held.len() == PENDING {
                    held.pop_front();
                }
                held.push_back(span);
            }
            Stage::Running(processor) => self.0.export(processor, span),
            Stage::Off => {}
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        match &*self.0.stage.read().unwrap_or_else(PoisonError::into_inner) {
            Stage::Running(processor) => processor.force_flush(),
            Stage::Pending(_) | Stage::Off => Ok(()),
        }
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.0.shutdown(timeout)
    }

    fn set_resource(&mut self, resource: &Resource) {
        *self
            .0
            .resource
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(resource.clone());
    }
}

/// Parent-based: a caller's sampled flag decides; a new trace is kept at the configured rate.
#[derive(Clone, Debug)]
pub(crate) struct Sampler(pub(crate) Arc<Shared>);

impl ShouldSample for Sampler {
    fn should_sample(
        &self,
        parent_context: Option<&Context>,
        trace_id: TraceId,
        name: &str,
        span_kind: &SpanKind,
        attributes: &[KeyValue],
        links: &[Link],
    ) -> SamplingResult {
        if self.0.is_off() {
            return SamplingResult {
                decision: SamplingDecision::Drop,
                attributes: Vec::new(),
                trace_state: parent_context
                    .map(|cx| {
                        use opentelemetry::trace::TraceContextExt as _;
                        cx.span().span_context().trace_state().clone()
                    })
                    .unwrap_or_default(),
            };
        }
        SdkSampler::ParentBased(Box::new(SdkSampler::TraceIdRatioBased(self.0.rate())))
            .should_sample(parent_context, trace_id, name, span_kind, attributes, links)
    }
}
