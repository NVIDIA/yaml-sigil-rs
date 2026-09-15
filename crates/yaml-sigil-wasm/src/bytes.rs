// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Fallible copies from a fixed, intrinsically measured JavaScript byte view.

use std::cell::LazyCell;

use js_sys::{Array, Function, Reflect, Symbol, Uint8Array};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::resource::Failure;

#[wasm_bindgen]
extern "C" {
    // Passing a slice lets the generated binding construct the exact destination
    // view. Keep the entire import fallible so a detached source cannot skip
    // Rust destructors, including a reusable resource policy's borrow guard.
    #[wasm_bindgen(catch, js_namespace = Reflect, js_name = apply)]
    fn copy_bytes(
        set: &Function,
        destination: &mut [u8],
        arguments: &Array,
    ) -> Result<JsValue, JsValue>;
}

struct Intrinsics {
    constructor: Function,
    tag: Function,
    length: Function,
    buffer: Function,
    offset: Function,
    values: Function,
    set: Function,
}

impl Intrinsics {
    fn load() -> Result<Self, JsValue> {
        let constructor = Reflect::get(&js_sys::global(), &"Uint8Array".into())?;
        let prototype = Reflect::get(&constructor, &"prototype".into())?;
        let prototype = Reflect::get_prototype_of(&prototype)?;
        let getter = |name: JsValue| -> Result<Function, JsValue> {
            let descriptor = Reflect::get_own_property_descriptor(&prototype, &name)?;
            Reflect::get(&descriptor, &"get".into())?.dyn_into()
        };
        Ok(Self {
            constructor: constructor.dyn_into()?,
            tag: getter(Symbol::to_string_tag().into())?,
            length: getter("length".into())?,
            buffer: getter("buffer".into())?,
            offset: getter("byteOffset".into())?,
            values: Reflect::get(&prototype, &"values".into())?.dyn_into()?,
            set: Reflect::get(&prototype, &"set".into())?.dyn_into()?,
        })
    }
}

thread_local! {
    static INTRINSICS: LazyCell<Result<Intrinsics, JsValue>> = LazyCell::new(Intrinsics::load);
}

fn with_intrinsics<T>(
    operation: impl FnOnce(&Intrinsics) -> Result<T, JsValue>,
) -> Result<T, Failure> {
    INTRINSICS.with(|intrinsics| {
        let intrinsics = intrinsics.as_ref().map_err(|_| Failure::InvalidByteInput)?;
        operation(intrinsics).map_err(|_| Failure::InvalidByteInput)
    })
}

pub(super) struct ByteInput {
    view: JsValue,
    length: usize,
}

impl ByteInput {
    pub(super) fn new(input: &Uint8Array) -> Result<Self, Failure> {
        with_intrinsics(|intrinsics| {
            // Intrinsic accessors bypass shadowed properties, subclass hooks,
            // and cross-realm instanceof checks. values validates attachment
            // and bounds, including empty views, without reading any bytes.
            if intrinsics.tag.call0(input)?.as_string().as_deref() != Some("Uint8Array") {
                return Err(JsValue::UNDEFINED);
            }
            intrinsics.values.call0(input)?;
            let length = intrinsics.length.call0(input)?;
            let Some(size) = length.as_f64() else {
                return Err(JsValue::UNDEFINED);
            };
            if !(0.0..=u32::MAX as f64).contains(&size) || size.fract() != 0.0 {
                return Err(JsValue::UNDEFINED);
            }
            let buffer = intrinsics.buffer.call0(input)?;
            let offset = intrinsics.offset.call0(input)?;
            let arguments = Array::new();
            arguments.push(&buffer);
            arguments.push(&offset);
            arguments.push(&length);
            // Explicit length prevents a growable shared buffer from increasing
            // the source extent between admission, allocation, and copying.
            let view = Reflect::construct(&intrinsics.constructor, &arguments)?;
            Ok(Self {
                view,
                length: size as usize,
            })
        })
    }

    pub(super) fn len(&self) -> usize {
        self.length
    }

    fn copy_to(&self, destination: &mut [u8]) -> Result<(), Failure> {
        if destination.len() != self.length {
            return Err(Failure::InvalidByteInput);
        }
        with_intrinsics(|intrinsics| {
            let arguments = Array::new();
            arguments.push(&self.view);
            // Native set validates both views and copies only the fixed source
            // extent. A subsequent detach or resize is a caught copy failure.
            copy_bytes(&intrinsics.set, destination, &arguments)?;
            Ok(())
        })
    }

    pub(super) fn to_vec(&self) -> Result<Vec<u8>, Failure> {
        let mut bytes = vec![0; self.length];
        self.copy_to(&mut bytes)?;
        Ok(bytes)
    }

    pub(super) fn to_secret_vec(&self) -> Result<Zeroizing<Vec<u8>>, Failure> {
        // Initialize and install zeroization before the fallible copy, so an
        // error also clears any partially copied private-key bytes.
        let mut bytes = Zeroizing::new(vec![0; self.length]);
        self.copy_to(&mut bytes)?;
        Ok(bytes)
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg(feature = "browser-tests")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    fn javascript(input: &JsValue, body: &str) -> JsValue {
        Function::new_with_args("input", &format!("{{ {body} }}"))
            .call1(&JsValue::UNDEFINED, input)
            .unwrap()
    }

    #[wasm_bindgen_test]
    fn shadowed_metadata_never_controls_the_copy() {
        let input: Uint8Array = javascript(
            &JsValue::UNDEFINED,
            "const input = new Uint8Array([9, 1, 2, 3, 9]).subarray(1, 4);\n\
             for (const name of ['length', 'byteLength', 'byteOffset', 'buffer',\n\
                                 'constructor', 'subarray', 'set', Symbol.iterator, Symbol.toStringTag]) {\n\
                 Object.defineProperty(input, name, {get() { throw new Error('unexpected getter'); }});\n\
             }\n\
             return input;",
        )
        .unchecked_into();
        let input = ByteInput::new(&input).unwrap();
        assert_eq!(input.len(), 3);
        assert_eq!(input.to_vec().unwrap(), [1, 2, 3]);
        assert_eq!(input.to_secret_vec().unwrap().as_slice(), [1, 2, 3]);
        assert_eq!(input.copy_to(&mut [0; 2]), Err(Failure::InvalidByteInput));
    }

    #[wasm_bindgen_test]
    fn detached_and_out_of_bounds_inputs_are_rejected() {
        for body in [
            "const buffer = new ArrayBuffer(4);\n\
             const input = new Uint8Array(buffer);\n\
             structuredClone(buffer, {transfer: [buffer]}); return input;",
            "const buffer = new ArrayBuffer(4, {maxByteLength: 8});\n\
             const input = new Uint8Array(buffer, 2, 2);\n\
             buffer.resize(1); return input;",
        ] {
            let input = javascript(&JsValue::UNDEFINED, body).unchecked_into();
            assert!(matches!(
                ByteInput::new(&input),
                Err(Failure::InvalidByteInput)
            ));
        }
        let empty = ByteInput::new(&Uint8Array::new_with_length(0)).unwrap();
        assert!(empty.to_vec().unwrap().is_empty());
    }

    #[wasm_bindgen_test]
    fn detach_after_admission_is_a_fallible_copy() {
        let input = Uint8Array::from([1, 2, 3].as_slice());
        let prepared = ByteInput::new(&input).unwrap();
        javascript(
            &input,
            "structuredClone(input.buffer, {transfer: [input.buffer]});",
        );
        let mut destination = [7; 3];
        assert_eq!(
            prepared.copy_to(&mut destination),
            Err(Failure::InvalidByteInput)
        );
        assert_eq!(destination, [7; 3]);
        assert_eq!(prepared.to_vec(), Err(Failure::InvalidByteInput));
        assert_eq!(prepared.to_secret_vec(), Err(Failure::InvalidByteInput));
    }

    #[wasm_bindgen_test]
    fn resize_after_admission_keeps_the_original_extent() {
        let input: Uint8Array = javascript(
            &JsValue::UNDEFINED,
            "const buffer = new ArrayBuffer(3, {maxByteLength: 8});\n\
             const input = new Uint8Array(buffer); input.set([1, 2, 3]); return input;",
        )
        .unchecked_into();
        let prepared = ByteInput::new(&input).unwrap();
        javascript(&input, "input.buffer.resize(8); input[3] = 9;");
        assert_eq!(prepared.to_vec().unwrap(), [1, 2, 3]);
        javascript(&input, "input.buffer.resize(2);");
        assert_eq!(prepared.to_vec(), Err(Failure::InvalidByteInput));
    }
}
