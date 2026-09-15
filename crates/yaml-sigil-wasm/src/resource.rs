// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Explicit policy and admission before JavaScript byte inputs are copied.

use std::num::NonZeroUsize;

use wasm_bindgen::prelude::*;
use yaml_sigil_core::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm,
    ArtifactResourceLimits as CoreLimits, ArtifactResourceResult,
    pb::{EncodeError, EncodeErrorKind},
};

/// Reusable, opt-in complete-artifact resource policy.
#[wasm_bindgen]
#[derive(Clone, Default)]
pub struct ArtifactResourceLimits {
    pub(super) inner: CoreLimits,
}

#[wasm_bindgen]
impl ArtifactResourceLimits {
    /// Select the implementation's default 4 MiB ceiling.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable every optional resource dimension known to this version.
    pub fn unbounded() -> Self {
        Self {
            inner: CoreLimits::unbounded(),
        }
    }

    /// Return a new policy with a positive integer byte ceiling.
    ///
    /// Invalid configuration throws a JavaScript RangeError. Validate as a
    /// number before integer conversion so WebAssembly cannot truncate it.
    #[wasm_bindgen(js_name = withMaxArtifactBytes)]
    pub fn with_max_artifact_bytes(&self, maximum: JsValue) -> Result<Self, JsValue> {
        let maximum = maximum.as_f64().and_then(valid_maximum).ok_or_else(|| {
            js_sys::RangeError::new("maxArtifactBytes must be an integer from 1 to 4294967295")
        })?;
        Ok(Self {
            inner: self.inner.clone().with_max_artifact_bytes(maximum),
        })
    }

    /// Return a policy with only the complete-artifact ceiling disabled.
    #[wasm_bindgen(js_name = withoutMaxArtifactByteLimit)]
    pub fn without_max_artifact_byte_limit(&self) -> Self {
        Self {
            inner: self.inner.clone().without_max_artifact_byte_limit(),
        }
    }

    /// Return the byte ceiling, or undefined when it is disabled.
    #[wasm_bindgen(getter, js_name = maxArtifactBytes)]
    pub fn max_artifact_bytes(&self) -> Option<f64> {
        self.inner
            .max_artifact_bytes()
            .map(|value| value.get() as f64)
    }
}

fn valid_maximum(value: f64) -> Option<NonZeroUsize> {
    // Keep the wasm32 policy range identical when compiling native tests.
    if !value.is_finite() || value.fract() != 0.0 || !(1.0..=u32::MAX as f64).contains(&value) {
        return None;
    }
    NonZeroUsize::new(value as usize)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Failure {
    InvalidByteInput,
    Resource(&'static str),
    Encoding(&'static str),
}

impl Failure {
    pub(super) fn status(self) -> &'static str {
        match self {
            Self::InvalidByteInput => "invocation_error",
            Self::Resource(_) => "resource_error",
            Self::Encoding(_) => "encode_error",
        }
    }

    pub(super) fn code(self) -> &'static str {
        match self {
            Self::InvalidByteInput => "invalid_byte_input",
            Self::Resource(code) | Self::Encoding(code) => code,
        }
    }
}

impl From<ArtifactResourceError> for Failure {
    fn from(error: ArtifactResourceError) -> Self {
        Self::Resource(match error.kind() {
            ArtifactResourceErrorKind::InputArtifactTooLarge => "input_artifact_too_large",
            ArtifactResourceErrorKind::OutputArtifactTooLarge => "output_artifact_too_large",
            ArtifactResourceErrorKind::SizeComputationOverflow => "size_computation_overflow",
            _ => "other",
        })
    }
}

impl From<EncodeError> for Failure {
    fn from(error: EncodeError) -> Self {
        Self::Encoding(match error.kind() {
            EncodeErrorKind::MessageTooLarge => "message_too_large",
            _ => "other",
        })
    }
}

pub(super) fn flatten_encoding<T>(
    value: ArtifactResourceResult<Result<T, EncodeError>>,
) -> Result<T, Failure> {
    Ok(value??)
}

impl ArtifactResourceLimits {
    /// Core's slice-based admission requires bytes already in Rust memory.
    /// Apply the same ceiling to the JavaScript length before invoking any
    /// code that can copy, parse, or otherwise process that input.
    pub(super) fn with_admitted_input<T>(
        &self,
        length: usize,
        process: impl FnOnce() -> T,
    ) -> Result<T, Failure> {
        if self
            .inner
            .max_artifact_bytes()
            .is_some_and(|maximum| length > maximum.get())
        {
            return Err(Failure::Resource("input_artifact_too_large"));
        }
        Ok(process())
    }

    /// Component bytes are a conclusive lower bound, not the encoded size.
    /// Rust's resource-aware operation still checks envelope overhead and the
    /// final output. No temporary component buffer exists before admission.
    pub(super) fn with_admitted_output<T>(
        &self,
        form: ArtifactResourceForm,
        lengths: &[usize],
        copy: impl FnOnce() -> T,
    ) -> Result<T, Failure> {
        let minimum = lengths
            .iter()
            .try_fold(0usize, |total, length| total.checked_add(*length))
            .ok_or_else(|| self.inner.size_computation_overflow(form))?;
        self.inner.check_output_size_lower_bound(form, minimum)?;
        Ok(copy())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn finite(maximum: usize) -> ArtifactResourceLimits {
        ArtifactResourceLimits {
            inner: CoreLimits::unbounded()
                .with_max_artifact_bytes(NonZeroUsize::new(maximum).unwrap()),
        }
    }

    #[test]
    fn policy_values_are_checked_before_integer_conversion() {
        for value in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -1.0,
            -0.0,
            0.0,
            1.5,
            4_294_967_296.0,
        ] {
            assert!(valid_maximum(value).is_none(), "accepted {value}");
        }
        for value in [1.0, 4_194_304.0, 4_294_967_295.0] {
            assert_eq!(valid_maximum(value).unwrap().get() as f64, value);
        }
        assert_eq!(ArtifactResourceLimits::new().inner, CoreLimits::default());
        assert_eq!(
            ArtifactResourceLimits::unbounded().max_artifact_bytes(),
            None
        );
    }

    #[test]
    fn admission_precedes_copying_or_processing() {
        let touched = Cell::new(false);
        let limits = finite(4);
        assert_eq!(
            limits.with_admitted_input(5, || touched.set(true)),
            Err(Failure::Resource("input_artifact_too_large"))
        );
        assert!(!touched.get());
        assert_eq!(
            limits.with_admitted_output(ArtifactResourceForm::Protobuf, &[3, 2], || touched
                .set(true)),
            Err(Failure::Resource("output_artifact_too_large"))
        );
        assert!(!touched.get());
        limits.with_admitted_input(4, || touched.set(true)).unwrap();
        assert!(touched.get());
        limits
            .with_admitted_output(ArtifactResourceForm::Yaml, &[2, 2], || ())
            .unwrap();
        ArtifactResourceLimits::unbounded()
            .with_admitted_input(usize::MAX, || ())
            .unwrap();
    }

    #[test]
    fn overflow_and_format_failures_remain_separate_from_the_ceiling() {
        let limits = ArtifactResourceLimits::unbounded();
        assert_eq!(
            limits.with_admitted_output(ArtifactResourceForm::Yaml, &[usize::MAX, 1], || panic!(
                "must not copy"
            )),
            Err(Failure::Resource("size_computation_overflow"))
        );
        let error = yaml_sigil_core::pb::check_encoded_message_size(usize::MAX).unwrap_err();
        assert_eq!(Failure::from(error), Failure::Encoding("message_too_large"));
        let error = finite(4)
            .inner
            .check_input_size(ArtifactResourceForm::Yaml, &[0; 5])
            .unwrap_err();
        assert_eq!(
            Failure::from(error),
            Failure::Resource("input_artifact_too_large")
        );
    }
}
