// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const vm = require("node:vm");
const { Worker } = require("node:worker_threads");

function snapshot(result) {
  try {
    const value = { status: result.status, code: result.code };
    for (const name of ["artifact", "payload", "signatureCarrier", "modifiedPayload", "algorithm"]) {
      const presence = `has${name[0].toUpperCase()}${name.slice(1)}`;
      if (presence in result) {
        value[presence] = result[presence];
        value[name] = name === "algorithm" ? result[name] : Array.from(result[name]);
      }
    }
    return value;
  } finally {
    result.free();
  }
}

function rejected(result) {
  const value = snapshot(result);
  assert.equal(value.status, "invocation_error");
  assert.equal(value.code, "invalid_byte_input");
  for (const [name, field] of Object.entries(value)) {
    if (name.startsWith("has")) assert.equal(field, false);
    if (Array.isArray(field)) assert.deepEqual(field, []);
  }
}

function offsetView(bytes, BufferType = ArrayBuffer, growable = false) {
  const buffer = growable
    ? new BufferType(bytes.length + 4, { maxByteLength: bytes.length + 64 })
    : new BufferType(bytes.length + 4);
  const view = new Uint8Array(buffer, 2, bytes.length);
  view.set(bytes);
  return view;
}

function detached() {
  const input = new Uint8Array(8);
  structuredClone(input.buffer, { transfer: [input.buffer] });
  return input;
}

function outOfBounds() {
  const input = offsetView([1, 2, 3], ArrayBuffer, true);
  input.buffer.resize(1);
  return input;
}

module.exports = async function byteInputRegressions(api) {
  const algorithm = "ECDSA_SECP256R1_SHA256_RAW_RS64";
  const payload = new Uint8Array([0, 255, 10, 128, 1]);
  const carrier = new Uint8Array([255, 0, 1, 128]);
  const privateKey = new Uint8Array(32).fill(3);
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(privateKey);
  // Uncompressed point encoding follows Standards for Efficient Cryptography 1
  // (SEC 1). That material is not relicensed under this file's Apache-2.0 declaration.
  const publicKey = new Uint8Array(ecdh.getPublicKey(null, "uncompressed"));
  const artifact = api.sign(payload, algorithm, privateKey, undefined, false, "protobuf");
  assert.equal(artifact.status, "success");
  const signedBytes = artifact.artifact;
  artifact.free();

  let lengthReads = 0;
  const variants = [
    ["inflated length", (bytes) => Object.defineProperty(offsetView(bytes), "length", { value: 4096 })],
    ["zero length", (bytes) => Object.defineProperty(offsetView(bytes), "length", { value: 0 })],
    ["changing length", (bytes) => {
      return Object.defineProperty(offsetView(bytes), "length", {
        get() { lengthReads += 1; return lengthReads % 2 === 1 ? 8 : 4096; },
      });
    }],
    ["shadowed properties", (bytes) => {
      const input = offsetView(bytes);
      for (const name of ["length", "byteLength", "byteOffset", "buffer", "subarray", "set",
        "values", "constructor", Symbol.iterator, Symbol.toStringTag]) {
        Object.defineProperty(input, name, { get() { assert.fail(`read ${String(name)}`); } });
      }
      return input;
    }],
    ["subclass", (bytes) => {
      class Bytes extends Uint8Array {
        static get [Symbol.species]() { assert.fail("species accessed"); }
      }
      return new Bytes(bytes);
    }],
    ["cross realm", (bytes) => vm.runInNewContext("Uint8Array.from(bytes)", { bytes })],
    ["Node Buffer", (bytes) => Buffer.from(bytes)],
    ["shared buffer", (bytes) => offsetView(bytes, SharedArrayBuffer)],
    ["growable shared buffer", (bytes) => offsetView(bytes, SharedArrayBuffer, true)],
    ["resizable buffer", (bytes) => offsetView(bytes, ArrayBuffer, true)],
  ];
  const invalid = [
    () => undefined, () => null, () => ({}), () => [],
    () => new Uint16Array(8), () => new Uint8ClampedArray(8),
    () => new DataView(new ArrayBuffer(8)),
    () => Object.create(Uint8Array.prototype),
    () => new Proxy(new Uint8Array(8), { get() { assert.fail("proxy property read"); } }),
    detached, outOfBounds,
  ];

  // Exercise every byte parameter through the generated exports, including the
  // reference-counted policy borrow that direct Rust calls cannot test.
  for (const bounded of [false, true]) {
    const limits = new api.ArtifactResourceLimits();
    const suffix = bounded ? "WithResourceLimits" : "";
    const policy = bounded ? [limits] : [];
    const operations = [
      ["compose", [payload, carrier], (p, c) => api[`compose${suffix}`](p, c, "protobuf", ...policy)],
      ["decompose", [signedBytes], (a) => api[`decompose${suffix}`](a, "protobuf", "strict", ...policy)],
      ["sign", [payload, privateKey], (p, k) => api[`sign${suffix}`](p, algorithm, k, undefined, false, "protobuf", ...policy)],
      ["verify", [signedBytes, publicKey], (a, k) => api[`verify${suffix}`](a, "protobuf", algorithm, k, ...policy)],
    ];
    try {
      for (const [name, inputs, call] of operations) {
        const expected = snapshot(call(...inputs));
        for (let index = 0; index < inputs.length; index += 1) {
          for (const [variant, make] of variants) {
            const args = inputs.slice();
            args[index] = make(inputs[index]);
            assert.deepEqual(snapshot(call(...args)), expected, `${name}${suffix} input ${index} ${variant}`);
          }
          for (const make of invalid) {
            const args = inputs.slice();
            args[index] = make();
            rejected(call(...args));
            assert.deepEqual(snapshot(call(...inputs)), expected, "operation remains usable after rejection");
            const nextPolicy = limits.withMaxArtifactBytes(1024);
            assert.equal(nextPolicy.maxArtifactBytes, 1024);
            nextPolicy.free();
          }
          // Change the buffer after admission, at the imported copy itself.
          // Restore Reflect.apply before inspecting results or reusing policy.
          for (const change of ["detach", "grow"]) {
            const args = inputs.map((input) => {
              if (change === "detach") return input.slice();
              const buffer = new SharedArrayBuffer(input.length, { maxByteLength: input.length + 8 });
              const view = new Uint8Array(buffer);
              view.set(input);
              return view;
            });
            const apply = Reflect.apply;
            const set = Object.getPrototypeOf(Uint8Array.prototype).set;
            let copies = 0;
            let result;
            try {
              Reflect.apply = (target, destination, copyArgs) => {
                if (target === set && copies++ === index) {
                  const buffer = copyArgs[0].buffer;
                  if (change === "detach") structuredClone(buffer, { transfer: [buffer] });
                  else buffer.grow(buffer.maxByteLength);
                }
                return apply(target, destination, copyArgs);
              };
              result = call(...args);
            } finally {
              Reflect.apply = apply;
            }
            assert.ok(copies > index, "buffer change reached the selected byte copy");
            if (change === "detach") rejected(result);
            else {
              assert.equal(args[index].length, inputs[index].length + 8);
              assert.deepEqual(snapshot(result), expected, "growth keeps the admitted extent");
            }
            assert.deepEqual(snapshot(call(...inputs)), expected, "operation releases policy borrow");
          }
        }
      }
    } finally {
      limits.free();
    }
  }

  assert.equal(lengthReads, 0, "changing length getters are never invoked");

  // Admission and key-shape checks must use actual lengths, even when ordinary
  // property reads would report an acceptable size.
  const defaults = new api.ArtifactResourceLimits();
  const tiny = defaults.withMaxArtifactBytes(1);
  const hiddenLength = (bytes, size) => Object.defineProperty(bytes.slice(), "length", { value: size });
  try {
    for (const result of [
      api.composeWithResourceLimits(hiddenLength(payload, 0), carrier, "protobuf", tiny),
      api.signWithResourceLimits(hiddenLength(payload, 0), algorithm, privateKey, undefined, false, "protobuf", tiny),
      api.decomposeWithResourceLimits(hiddenLength(signedBytes, 0), "invalid", undefined, tiny),
      api.verifyWithResourceLimits(hiddenLength(signedBytes, 0), "invalid", "invalid", publicKey, tiny),
    ]) {
      assert.equal(snapshot(result).status, "resource_error");
    }
    assert.equal(snapshot(api.sign(payload, algorithm, hiddenLength(privateKey.subarray(1), 32),
      undefined, false, "protobuf")).code, "invalid_signing_key");
    assert.equal(snapshot(api.verify(signedBytes, "protobuf", algorithm,
      hiddenLength(publicKey.subarray(1), 65))).code, "key_resolution_failure");
  } finally {
    tiny.free();
    defaults.free();
  }

  await growingSharedBuffer(api, carrier);
  console.log("Generated byte-input regressions passed (all eight exports and every byte parameter).");
};

async function growingSharedBuffer(api, carrier) {
  // The worker only grows the buffer; existing bytes remain unchanged. Start
  // each call with a length-tracking view while growth continues concurrently.
  const initialSize = 1024 * 1024;
  const buffer = new SharedArrayBuffer(initialSize, { maxByteLength: 32 * initialSize });
  const input = new Uint8Array(buffer);
  input.fill(0x5a);
  const control = new Int32Array(new SharedArrayBuffer(12));
  const worker = new Worker(`
    const { workerData } = require("node:worker_threads");
    const { buffer, control } = workerData;
    Atomics.store(control, 0, 1);
    Atomics.notify(control, 0);
    while (Atomics.load(control, 1) === 0) Atomics.wait(control, 1, 0);
    while (Atomics.load(control, 2) === 0 && buffer.byteLength < buffer.maxByteLength) {
      buffer.grow(Math.min(buffer.byteLength + 4096, buffer.maxByteLength));
      Atomics.wait(control, 2, 0, 1);
    }
  `, { eval: true, workerData: { buffer, control } });
  const limits = api.ArtifactResourceLimits.unbounded();
  try {
    assert.notEqual(Atomics.wait(control, 0, 0, 10000), "timed-out", "worker started");
    Atomics.store(control, 1, 1);
    Atomics.notify(control, 1);
    const before = buffer.byteLength;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const sizeBefore = buffer.byteLength;
      const result = attempt % 2 === 0
        ? api.compose(input, carrier, "protobuf")
        : api.composeWithResourceLimits(input, carrier, "protobuf", limits);
      const sizeAfter = buffer.byteLength;
      assert.equal(result.status, "success");
      const split = api.decompose(result.artifact, "protobuf", "strict");
      result.free();
      assert.equal(split.status, "ok");
      const copied = split.payload;
      split.free();
      assert.ok(copied.length >= sizeBefore && copied.length <= sizeAfter);
      assert.ok(copied.subarray(0, initialSize).every((byte) => byte === 0x5a));
      assert.ok(copied.subarray(initialSize).every((byte) => byte === 0));
    }
    assert.ok(buffer.byteLength > before, "worker grew the buffer during generated calls");
  } finally {
    Atomics.store(control, 2, 1);
    Atomics.notify(control, 2);
    await worker.terminate();
    limits.free();
  }
}
