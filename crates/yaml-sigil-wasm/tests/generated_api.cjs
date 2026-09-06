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
