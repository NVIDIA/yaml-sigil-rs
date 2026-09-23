// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");

const modulePath = process.argv[2];
assert.ok(modulePath, "generated module path is required");
const api = require(path.resolve(modulePath));

const P256 = "ECDSA_SECP256R1_SHA256_RAW_RS64";
const encoder = new TextEncoder();
const payload = encoder.encode("name: generated-api\n");

const carrier = encoder.encode("opaque signature carrier");
const composed = api.compose(payload, carrier, "protobuf");
assert.equal(composed.status, "success");
assert.equal(composed.code, undefined);
assert.equal(composed.hasArtifact, true);
assert.ok(composed.artifact instanceof Uint8Array);

payload[0] = "X".charCodeAt(0);
const decomposed = api.decompose(composed.artifact, "protobuf", "strict");
assert.equal(decomposed.status, "ok");
assert.equal(decomposed.hasPayload, true);
assert.equal(decomposed.hasSignatureCarrier, true);
assert.deepEqual(
  Array.from(decomposed.payload),
  Array.from(encoder.encode("name: generated-api\n")),
);
assert.deepEqual(Array.from(decomposed.signatureCarrier), Array.from(carrier));

const firstArtifact = composed.artifact;
const originalFirstByte = firstArtifact[0];
firstArtifact[0] ^= 0xff;
assert.equal(composed.artifact[0], originalFirstByte);

const signingKey = new Uint8Array(32).fill(3);
const ecdh = crypto.createECDH("prime256v1");
ecdh.setPrivateKey(signingKey);
// These point encodings follow Standards for Efficient Cryptography 1
// (SEC 1). That standards material is not relicensed under this file's
// Apache-2.0 declaration.
const verifyingKey = new Uint8Array(ecdh.getPublicKey(null, "uncompressed"));
const compressedKey = new Uint8Array(ecdh.getPublicKey(null, "compressed"));
assert.equal(verifyingKey.length, 65);
assert.equal(compressedKey.length, 33);

const wrongLength = api.sign(
  encoder.encode("name: generated-api\n"),
  P256,
  signingKey.subarray(1),
  undefined,
  false,
  "yaml",
);
assert.equal(wrongLength.status, "invocation_error");
assert.equal(wrongLength.code, "invalid_signing_key");

const signed = api.sign(
  encoder.encode("name: generated-api\n"),
  P256,
  signingKey,
  undefined,
  false,
  "yaml",
);
signingKey.fill(0);
assert.equal(signed.status, "success");
assert.equal(signed.hasArtifact, true);
assert.equal(signed.hasModifiedPayload, false);

const compressed = api.verify(signed.artifact, "yaml", P256, compressedKey);
assert.equal(compressed.status, "invocation_error");
assert.equal(compressed.code, "key_resolution_failure");

const verified = api.verify(signed.artifact, "yaml", P256, verifyingKey);
assert.equal(verified.status, "verified");
assert.equal(verified.hasPayload, true);
assert.equal(verified.hasAlgorithm, true);
assert.equal(verified.algorithm, P256);
assert.deepEqual(
  Array.from(verified.payload),
  Array.from(encoder.encode("name: generated-api\n")),
);

const defaults = new api.ArtifactResourceLimits();
assert.equal(defaults.maxArtifactBytes, 4 * 1024 * 1024);
assert.equal(api.ArtifactResourceLimits.unbounded().maxArtifactBytes, undefined);
assert.equal(defaults.withoutMaxArtifactByteLimit().maxArtifactBytes, undefined);
assert.equal(defaults.withMaxArtifactBytes(1).maxArtifactBytes, 1);
assert.equal(defaults.withMaxArtifactBytes(4294967295).maxArtifactBytes, 4294967295);
for (const invalid of [
  undefined, null, {}, true, "1", 1n,
  0, -0, -1, 1.5, NaN, Infinity, -Infinity, 4294967296,
]) {
  assert.throws(() => defaults.withMaxArtifactBytes(invalid), RangeError);
}
assert.equal(defaults.maxArtifactBytes, 4 * 1024 * 1024);

const exact = defaults.withMaxArtifactBytes(signed.artifact.length);
const short = defaults.withMaxArtifactBytes(signed.artifact.length - 1);
const boundedVerified = api.verifyWithResourceLimits(
  signed.artifact, "yaml", P256, verifyingKey, exact,
);
assert.equal(boundedVerified.status, "verified");
const refused = api.verifyWithResourceLimits(
  signed.artifact, "yaml", P256, verifyingKey, short,
);
assert.equal(refused.status, "resource_error");
assert.equal(refused.code, "input_artifact_too_large");
assert.equal(refused.hasPayload, false);
assert.equal(refused.hasAlgorithm, false);
assert.equal(refused.payload.length, 0);
const boundedSplit = api.decomposeWithResourceLimits(
  signed.artifact, "yaml", undefined, exact,
);
assert.equal(boundedSplit.status, "ok");
assert.equal(api.composeWithResourceLimits(
  boundedSplit.payload, boundedSplit.signatureCarrier, "yaml", exact,
).status, "success");
const smallOutput = api.composeWithResourceLimits(
  boundedSplit.payload, boundedSplit.signatureCarrier, "yaml", short,
);
assert.equal(smallOutput.status, "resource_error");
assert.equal(smallOutput.code, "output_artifact_too_large");
assert.equal(smallOutput.hasArtifact, false);
const boundedSigned = api.signWithResourceLimits(
  encoder.encode("name: generated-api\n"), P256, new Uint8Array(32).fill(3),
  undefined, false, "yaml", exact,
);
assert.equal(boundedSigned.status, "success");
assert.equal(boundedSigned.artifact.length, signed.artifact.length);
assert.notDeepEqual(Array.from(boundedSigned.artifact), Array.from(signed.artifact));
assert.equal(api.verify(
  boundedSigned.artifact, "yaml", P256, verifyingKey,
).status, "verified");

// Exercise the real default signer when Web Crypto entropy acquisition fails.
const webCrypto = globalThis.crypto;
const randomValuesDescriptor = Object.getOwnPropertyDescriptor(webCrypto, "getRandomValues");
let entropyCalls = 0;
Object.defineProperty(webCrypto, "getRandomValues", {
  configurable: true,
  value() {
    entropyCalls += 1;
    throw new Error("test entropy failure");
  },
});
try {
  for (const form of ["yaml", "protobuf"]) {
    const args = [
      encoder.encode("name: entropy-failure\n"), P256, new Uint8Array(32).fill(3),
      undefined, false, form,
    ];
    for (const result of [api.sign(...args), api.signWithResourceLimits(...args, defaults)]) {
      assert.equal(result.status, "signer_error");
      assert.equal(result.code, "key_operation_failure");
      assert.equal(result.hasArtifact, false);
      assert.equal(result.hasModifiedPayload, false);
      assert.equal(result.artifact.length, 0);
    }
  }
  assert.equal(entropyCalls, 4);
} finally {
  if (randomValuesDescriptor) {
    Object.defineProperty(webCrypto, "getRandomValues", randomValuesDescriptor);
  } else {
    delete webCrypto.getRandomValues;
  }
}

// Input admission precedes selectors and key processing for bounded calls.
const tiny = defaults.withMaxArtifactBytes(1);
assert.equal(api.verifyWithResourceLimits(
  new Uint8Array(2), "invalid", "invalid", new Uint8Array(), tiny,
).status, "resource_error");
assert.equal(api.decomposeWithResourceLimits(
  new Uint8Array(2), "invalid", undefined, tiny,
).status, "resource_error");

// Mix the default and explicit contracts in both directions. Namespace calls
// must return the original classes and accept the same resource-policy object.
assert.deepEqual(Object.keys(api.v1alpha1).sort(), [
  "compose", "composeWithResourceLimits", "decompose", "decomposeWithResourceLimits",
  "sign", "signWithResourceLimits", "verify", "verifyWithResourceLimits",
]);
for (const [producer, consumer] of [[api.v1alpha1, api], [api, api.v1alpha1]]) {
  for (const form of ["yaml", "protobuf"]) {
    const owned = [];
    const keep = (value) => { owned.push(value); return value; };
    try {
      const input = encoder.encode("namespace: v1alpha1\n");
      const outer = form === "protobuf" ? "strict" : undefined;
      const signed = keep(producer.sign(
        input, P256, new Uint8Array(32).fill(3), undefined, false, form,
      ));
      assert.ok(signed instanceof api.SignResult);
      assert.equal(signed.status, "success");
      const limits = keep(new api.ArtifactResourceLimits());
      const exact = keep(limits.withMaxArtifactBytes(signed.artifact.length));
      const short = keep(limits.withMaxArtifactBytes(signed.artifact.length - 1));

      const verified = keep(consumer.verify(signed.artifact, form, P256, verifyingKey));
      assert.ok(verified instanceof api.VerifyResult);
      assert.equal(verified.status, "verified");
      assert.deepEqual(verified.payload, input);
      const split = keep(consumer.decompose(signed.artifact, form, outer));
      assert.ok(split instanceof api.DecomposeResult);
      assert.equal(split.status, "ok");
      const joined = keep(producer.compose(split.payload, split.signatureCarrier, form));
      assert.ok(joined instanceof api.ComposeResult);
      assert.equal(joined.status, "success");
      assert.deepEqual(joined.artifact, signed.artifact);

      const boundedSign = keep(producer.signWithResourceLimits(
        input, P256, new Uint8Array(32).fill(3), undefined, false, form, exact,
      ));
      assert.ok(boundedSign instanceof api.SignResult);
      assert.equal(boundedSign.status, "success");
      const boundedVerify = keep(consumer.verifyWithResourceLimits(
        boundedSign.artifact, form, P256, verifyingKey, exact,
      ));
      assert.ok(boundedVerify instanceof api.VerifyResult);
      assert.equal(boundedVerify.status, "verified");
      assert.deepEqual(boundedVerify.payload, input);
      const boundedSplit = keep(consumer.decomposeWithResourceLimits(
        boundedSign.artifact, form, outer, exact,
      ));
      assert.ok(boundedSplit instanceof api.DecomposeResult);
      assert.equal(boundedSplit.status, "ok");
      const boundedJoin = keep(producer.composeWithResourceLimits(
        boundedSplit.payload, boundedSplit.signatureCarrier, form, exact,
      ));
      assert.ok(boundedJoin instanceof api.ComposeResult);
      assert.equal(boundedJoin.status, "success");
      assert.deepEqual(boundedJoin.artifact, boundedSign.artifact);

      for (const refused of [
        keep(consumer.verifyWithResourceLimits(signed.artifact, form, P256, verifyingKey, short)),
        keep(consumer.decomposeWithResourceLimits(signed.artifact, form, outer, short)),
      ]) {
        assert.equal(refused.status, "resource_error");
        assert.equal(refused.code, "input_artifact_too_large");
        assert.equal(refused.hasPayload, false);
      }
      for (const refused of [
        keep(producer.composeWithResourceLimits(split.payload, split.signatureCarrier, form, short)),
        keep(producer.signWithResourceLimits(
          input, P256, new Uint8Array(32).fill(3), undefined, false, form, short,
        )),
      ]) {
        assert.equal(refused.status, "resource_error");
        assert.equal(refused.code, "output_artifact_too_large");
        assert.equal(refused.hasArtifact, false);
      }
    } finally {
      for (const value of owned.reverse()) value.free();
    }
  }
}

async function checkByteInputs() {
  const regressions = require("./byte_inputs.cjs");
  await regressions(api);
  await regressions({ ...api, ...api.v1alpha1 });
}

checkByteInputs().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
