# Cryptographic providers

`yaml-sigil-rs` can prepare and verify artifacts while your adapter performs
the cryptographic operation. Your private key can remain in a native library,
an HSM, or a KMS. You can also implement the public
[`yaml-sigil-traits`](https://crates.io/crates/yaml-sigil-traits) contracts
directly when you need control over the complete operation.

The default convenience APIs continue to accept `ed25519-dalek` and `p256`
keys. Provider support adds integration choices without requiring a migration
from those APIs.

## Three useful integration choices

| Path | What you gain | What you supply or give up |
|------|---------------|---------------------------|
| Qualified provider operations. | This workspace's artifact processing, key and signature checks, per-output signing verification, and finite verification-provider qualification. | An adapter that meets the boundary's cryptographic behavior. Verification qualification needs the exact configured instance to bind the public test keys. |
| Explicitly unqualified provider operations. | The same artifact processing and structural checks, while using a provider with different cryptographic acceptance behavior or one that cannot run the qualification suite. | Your own evidence that its signing and verification behavior fits your requirements. Signing skips output self-verification; verification skips the fixed suite. |
| Direct `yaml-sigil-traits` implementation. | Your own associated key types, operations, async strategy, and choice of implementation helpers. No provider wrapper or qualification prerequisite. | The complete operation and evidence for its capabilities and conformance claims. The traits do not automatically run this workspace's checks. |

All three are supported choices. Select the path according to your needs.
Unqualified operations still perform cryptographic signing or verification;
the name identifies which additional evidence this workspace does not require.
Direct trait implementations can use `yaml-sigil-core` and other helpers
selectively, or own the operation entirely. Implementing a trait does not
establish conformance, and choosing that path does not fix a provider's
cryptographic compatibility difference. That difference may be acceptable
for your application.

Choose signing and verification independently. For example, the native
[`ring` and `aws-lc-rs` examples](../examples/README.md#local-cryptographic-providers)
use qualified signing for both algorithms and explicitly unqualified Ed25519
verification. Their pinned native verifiers reject some mixed-order cases
that this implementation accepts. They use qualified P-256 verification.

> [!WARNING]
> Unqualified signing skips independent output self-verification, and
> unqualified verification skips the fixed qualification suite. You, the
> integration implementer, own the additional risk and compatibility
> assessment. Structural checks cannot detect a validly encoded signature
> for the wrong message or key. A native sign/verify round trip does not prove
> compatibility across all inputs.

The dedicated
[`ring-unqualified-provider` example](../examples/README.md#explicitly-unqualified-provider)
selects that choice for both signing and verification with either algorithm.
It demonstrates retained structural checks and native verification without
requiring qualification. Its pinned `ring` verifier has the mixed-order
Ed25519 acceptance difference described above.

## Why bind a key

Associate each opaque provider handle with one algorithm and its canonical
public key. The signing builder validates
the public key and retains that association. Qualified signing verifies every
real output against that key and the final message before returning an
artifact. A valid signature made with the wrong private key therefore fails.
The builder never asks for a synthetic signing challenge or private-key bytes.

A verification factory binds exactly the supplied public key to a handle.
Each handle must preserve its own binding when the factory creates another
handle. Store the key or a stable key identifier in each handle. Handles can
share a client, but locking a shared "current key" only serializes access;
another bind can still change the key that an earlier handle uses.

Both qualification suites keep multiple bindings live and interleave valid
and cross-key checks. They recheck earlier handles after later binds and
require each handle to reject the other key's signature. These tests detect
several caching and handle-reuse mistakes. They do not prove every later
handle is correct.

Public-key validation also runs on the unqualified path. Ed25519 keys use 32
canonical compressed octets and must satisfy this implementation's key
admissibility rules. P-256 uses the 65-octet uncompressed point encoding from
*Standards for Efficient Cryptography 1 (SEC 1)*. Signature structural checks
require canonical Ed25519 `R || S` or in-range P-256 big-endian `r || s`, each
exactly 64 octets. An unqualified operation cannot bypass these checks; use
direct traits if your integration needs to own them.

The artifact's unsigned `keyid` is a lookup hint. It does not authorize a key,
prove identity, or replace a deployment trust policy. Select the artifact form
and trusted keys from application context before verification.

## Synchronous and asynchronous adapters

| Operation | Synchronous contract | Asynchronous contract |
|-----------|----------------------|-----------------------|
| Sign with an initialized handle. | `signature::Signer<[u8; 64]> + Sync`. | `AsyncProviderSigner`. |
| Verify with a bound handle. | `signature::Verifier<[u8; 64]>` and `ProviderVerifier`. | `AsyncProviderVerifier`. |
| Bind public bytes to a verifier. | `ProviderVerifierFactory`. | `AsyncProviderVerifierFactory`. |
| Select qualification. | `VerificationProviderBuilder::qualify` or `build_unqualified`. | `AsyncVerificationProviderBuilder::qualify().await` or `build_unqualified`. |

The operation receives the final message bytes. Do not prehash them before
calling the adapter. YAML signing applies
authorized final-newline normalization before the operation. Protobuf payload
bytes remain unchanged. A P-256 adapter hashes those message bytes with
SHA-256 exactly once and exchanges fixed-width signatures, never DER. Its
verifier must accept both high-S and low-S for qualification. Ed25519
qualification includes canonical mixed-order inputs accepted by the slot's
cofactored verification equation.

The async traits use native returned futures with `Send` guarantees and
`Send + Sync` adapters. An async adapter does not need a synchronous trait
implementation. Its factory's `Verifier<'factory>` associated type can borrow
a client or configuration. Binding can borrow temporary public-key input
until completion; the returned handle cannot retain that input borrow.
Neither the client nor the bound handle needs to be `'static`.

Fetch or initialize a remote signing key and obtain its public bytes before
using `AsyncProviderSigningKeyBuilder`. Its `build` and `build_unqualified`
methods perform local validation. Signing, verification binding,
qualification calls, and signature verification can suspend while awaiting
the provider.

`ProviderAsyncSigner` and `ProviderAsyncVerifier` implement the existing
re-exported `AsyncSigner` and `AsyncVerifier` traits using qualified provider
keys. `UnqualifiedProviderAsyncSigner` and
`UnqualifiedProviderAsyncVerifier` provide the explicit alternatives. Their
associated keys carry the adapter lifetime. The corresponding async free
functions cover these operations and expose metadata and pre-verification reuse.
The existing `DefaultAsyncSigner` and `DefaultAsyncVerifier` still perform
local synchronous cryptography when polled; introducing these adapters does
not change their scheduling.

Parsing, structural checks, output assembly, and qualified signing's local
self-verification remain synchronous work around the await. Public bound-key
types hide the implementation's dynamic dispatch. Internally, signing boxes
one future per operation; verification boxes a bound handle and one future
per operation, including qualification operations. The factory binding
contract itself uses a native returned future.

The library chooses no executor or blocking pool. `Send` allows an executor
to move a future between threads; it does not prove an SDK avoids blocking.
Place blocking operations appropriately in your adapter. Own your timeouts,
retry and concurrency policies, credentials, remote error translation, and
request cancellation semantics. Dropping a pending library future drops the
pending adapter future; it cannot promise to cancel an already submitted
remote operation. Dropped qualification exposes no partially qualified
provider.

The [`async-provider` example](../examples/README.md#asynchronous-provider)
uses a blocking worker with a private key store and awaits channel replies.
It demonstrates both choices with fresh P-256 keys and no external service.
The `ring` and `aws-lc-rs` examples demonstrate synchronous adapters only.

## Qualification and error handling

The costs below follow the current implementation's operations and allocation
sites. They are not benchmark timings. Payload size, native library behavior,
SDK scheduling, and service latency determine the cost of your integration.

### One-time qualification

Verification qualification consumes one configured adapter instance, runs a
finite public-only suite, and records each algorithm separately. Reuse that
instance for application bindings. Replacing or reconfiguring it requires
qualification again. State is opaque and non-serializable. A rejected slot
cannot create a qualified key; another qualified slot remains usable.

Qualification provides evidence for compatibility and catches common adapter
mistakes. You still choose and trust the adapter code. An implementation can
recognize the fixed inputs, pass them, and misbehave on other inputs; this
mechanism does not attempt to prevent deliberate evasion. Use per-handle key
state and test your adapter's actual configuration and lifecycle.

The synchronous and asynchronous suites make these adapter calls when all
checks succeed.

| Algorithm | Public-key binds | Signature verifications |
|-----------|------------------|-------------------------|
| Ed25519. | 3. | 12. |
| P-256. | 2. | 11. |
| Both slots. | 5. | 23. |

Both builders attempt Ed25519 and then P-256 sequentially, including async
qualification. Each slot stops at its first failure, but the builder still
attempts the other slot. Count SDK requests and network round trips separately
from adapter calls. An adapter may perform multiple requests or
internal retries for one call. The library adds no retry or deadline.
The implementation is in
[`provider.rs`](../crates/yaml-sigil-verification/src/provider.rs) and
[`async_provider.rs`](../crates/yaml-sigil-verification/src/async_provider.rs).

A service that cannot bind the suite's public keys cannot qualify through
this mechanism. The unqualified path remains available. A finite number of
qualification calls does not bound wall-clock time, remote billing, or
resource consumption inside a provider. Reuse qualified instances and bound
application keys to avoid repeating setup work for each artifact.

### Per-operation costs

Signing-key builders validate the supplied public key locally. Both signing
paths make zero synthetic signing calls during construction. Binding a
verification key validates its public bytes and calls the factory once;
remote binding costs depend on that adapter.

| Operation | Qualified provider | Unqualified provider | Direct traits |
|-----------|--------------------|----------------------|---------------|
| Sign an admitted message successfully. | One provider sign and one local cryptographic verification of its output. | One provider sign; no local cryptographic output verification. | Depends on the implementation and selected helpers. |
| Verify an admitted, structurally valid signed artifact with a bound key. | One provider verification after local checks. Qualification is not repeated. | One provider verification after the same local checks. | Depends on the implementation and selected helpers. |
| Reuse a bound key. | No repeated builder or qualification calls. | No repeated builder calls. | Implementation-owned. |

Qualified signing's extra verification hashes the final message again and
performs local public-key cryptography. Its cost grows with payload size as
well as the algorithm's fixed cryptographic work. Unqualified signing omits
that check while retaining signature-structure validation. Qualified artifact
verification does not perform a second RustCrypto verification. Both
verification paths use the provider's result.

Both provider paths share artifact parsing, payload copying, framing, and
structural checks. Scanning, copying, and message hashing grow with payload
size; public-key and signature validation operate on fixed-size inputs.
Reusing a bound key avoids binding work, but verification still validates its
canonical public bytes at use. Provider operations use dynamic dispatch;
synchronous verification factories return boxed handles.

Async provider operations add a boxed future for each sign or verification
call. The private verification bridge also boxes each bound handle, including
qualification handles. The factory's native binding future is not boxed by
the library. These allocation and dispatch costs also apply to async
qualification. Awaiting lets other tasks progress during provider I/O; it
does not accelerate local parsing or cryptography. Remote latency may dominate
these costs, so measure the actual SDK and workload.

The default RustCrypto convenience APIs need no provider qualification or
provider-future boxing. Direct trait implementations choose their own
allocation, dispatch, checks, and helper reuse. Neither comparison establishes
that one integration is always faster.

### Failures and retries

Qualification status is separate from `VerifierOptions` and artifact
processing capabilities. Explicitly disable algorithms your operation does
not offer. A capability list does not certify an arbitrary adapter or turn a
failed slot into a qualified one.

Both qualified and unqualified verification use the provider's verdict.
Neither retries through RustCrypto or another path. `SignatureMismatch`
becomes `SignedButFailedVerification`; `ProviderFailure` becomes
`InvocationError::KeyResolutionFailure`. Synchronous `ProviderVerifier` has
a default classification that treats every `signature::Error` as mismatch.
Override it when the provider can fail operationally. Async verification
requires an explicit classified outcome. Signing operation errors, malformed
signatures, and failed qualified output checks become
`SignError::KeyOperationFailure`.

An early malformed-input rejection or an opted-in resource preflight can
avoid provider calls. That does not imply zero local parsing or validation
work. A bad output or failed qualified self-check is discovered after the
signing call has already been paid for. YAML's exact final-size check can
also reject after signing, as described below. If your application retries,
it incurs the repeated provider and local work and owns the retry policy.

## Optional artifact limits

Whole-artifact limits are opt-in operational policy. They do not establish
conformance and do not alter the separate 16,384-octet YAML signature-carrier
constraint. Ordinary provider operations and trait facades remain unbounded
by this optional policy.

Use `sign_with_provider_and_resource_limits` or
`sign_with_unqualified_provider_and_resource_limits` for bounded synchronous
signing. Their async counterparts are
`sign_with_async_provider_and_resource_limits` and
`sign_with_unqualified_async_provider_and_resource_limits`.

These functions reuse the existing signing preflight and exact output checks.
After request-shape validation, protobuf output computes the exact encoded
length before scanning caller buffers or invoking a provider. YAML first
checks a conclusive lower bound. It checks the exact serialized output size
after signing and carrier serialization, before allocating the complete
artifact. Escaping can make that final check necessary even after a successful
preflight. Resource rejection is the outer result, a protobuf encoding error
has its own middle layer, and the existing `SignOutcome` remains inside.

Verification already has an equivalent admission boundary. Call
`ArtifactResourceLimits::check_input_size` on the original encoded artifact
before a provider operation, or call `pre_verify_with_resource_limits` and
pass its admitted response to a provider `verify_from_pre_verify` operation.
Both approaches work with sync or async and either qualification choice.
There is no separate provider verification-limit family because those
existing checks already reject before artifact-dependent parsing, copying,
or verification. If binding itself requires remote work, apply admission
before that work too. Checking extracted payload length afterward is not an
equivalent encoded-input limit.

## Checklist of checks and evidence

These tables describe the checks and tests maintained in this workspace.
“Tested” means the named repository regressions exercise a behavior with test
adapters. It is narrower than a guarantee about an integrator's provider.

### Checks applied during an operation

| Check | Qualified provider | Unqualified provider | Direct traits |
|-------|--------------------|----------------------|---------------|
| Artifact framing, parsing, options, and verifier-state mapping. | Applied by this workspace. | Applied by this workspace. | Implementation-owned; helpers are optional. |
| Canonical admissible public keys and signature structure. | Applied locally. | Applied locally. | Implementation-owned. |
| Every real signature matches the bound key and final message. | Self-verified before returning an artifact. | No local cryptographic output check. | Implementation-owned. |
| Fixed verification qualification suite. | Required per algorithm and instance. | Not run. | Not required by the traits. |
| Bound provider verdict without fallback. | Authoritative. | Authoritative. | Implementation-owned. |
| Whole-artifact resource admission. | Only when explicitly selected. | Only when explicitly selected. | Implementation-owned. |

### Repository test coverage

| Test or evidence | Qualified provider | Unqualified provider | Direct traits |
|------------------|--------------------|----------------------|---------------|
| YAML and protobuf payload bytes, signing, verification, metadata, and pre-verification reuse. | Tested with sync and async adapters. | Tested with sync and async adapters. | Default RustCrypto trait implementations run the workspace suites. Custom implementations are not tested automatically. |
| Invalid keys, malformed signatures, provider failures, and no fallback. | Tested. | Tested through shared checks and explicit bypass cases. | Custom mappings are not tested automatically. |
| Ed25519 valid, invalid, and mixed-order verification cases. | Fixed qualification suite, with sync/async status and call-count parity tests. | Suite intentionally skipped; native generated-key round trips are tested. | Applicable local fixtures exercise only the default implementations. |
| P-256 high-S/low-S acceptance. | Fixed qualification suite and regressions. | Suite intentionally skipped; operation round trips are tested. | Applicable local fixtures exercise the defaults. |
| Multiple live handles and cross-key rejection in both directions for Ed25519 and P-256. | Sync and async suites reject cached, retargeted, invalidated, or overly broad key bindings in regressions. | Suite intentionally skipped; the adapter owns binding correctness. | Custom binding behavior is not tested automatically. |
| Protection against an adapter deliberately evading qualification. | Not provided; the adapter is trusted code. | Not provided. | Not provided by implementing traits. |
| Runnable YAML examples with fresh keys, file/stdin/default input, and independent checking of printed output. | Native examples test qualified signing for both algorithms and qualified P-256 verification; the async example tests qualified P-256. | The dedicated `ring` example tests both operations unqualified for both algorithms without qualification; the async example tests unqualified P-256. | No runnable custom direct-trait example; default trait implementations run workspace tests. |
| Borrowed clients and keys, `Send + Sync`, pending/wake/drop behavior. | Tested with controllable async adapters. | Borrowed-key round trips are tested; shared async plumbing retains the same contracts. | External traits require `Send`; runtime behavior of custom implementations is not tested here. |
| Bounded signing rejects early and checks the exact final output. | Tested for both algorithms and forms, sync and async. | Tested for both algorithms and forms, sync and async. | Custom operations must implement their own policy. |
| Input-size rejection before artifact-dependent provider verification. | Existing shared admission helper is available. | Tested with an operation counter. | Custom operations must select and test admission. |
| Every applicable conformance fixture against each provider. | Not tested. | Not tested. | Default implementations run the workspace fixture suites; arbitrary associated key types need test-driver adaptation. |
| RNG quality, nonce-generation policy, constant-time behavior, side channels, key storage, and service authorization. | Not established by qualification or output self-verification. | Not established. | Not established by implementing traits. |
| Real SDK scheduling, network cancellation, timeouts, rate limits, and all deployment platforms. | Not tested. | Not tested. | Integrator-owned. |
| FIPS validation or other certification. | Not established. | Not established. | Not established. |

Evidence lives in the signing unit tests,
[`provider_paths.rs`](../crates/yaml-sigil-verification/tests/provider_paths.rs),
[`async_provider_tests.rs`](../crates/yaml-sigil-verification/src/async_provider_tests.rs),
compiling API rustdoc, and the runnable examples, including
[`ring_unqualified_provider.rs`](../examples/ring_unqualified_provider.rs).
These generated-key round trips do not establish a provider's acceptance
behavior across the full input space. The
[focused async fixture test](../crates/yaml-sigil-conformance/tests/provider_async.rs)
also covers P-256 high-S/low-S and malformed signatures through both provider
facades. The
[conformance record](./conformance-validation.md) names fixture coverage and
known implementation behavior. Keep qualification evidence distinct from
those complete artifact suites.

### Establishing complete conformance

Our qualification offers narrower evidence than complete conformance.
For any of the three paths, establish the following for the complete
implementation and the exact provider configuration you intend to claim.

- [ ] Identify every applicable normative requirement and advertised profile
  in the selected YamlSigil specification, including requirements not covered
  by available fixtures.
- [ ] Run the applicable artifact, algorithm, malformed-input, key-resolution,
  metadata, and runtime fixtures through the actual integration. Adapt the
  workspace test drivers where their RustCrypto associated-key bounds do not fit.
- [ ] Test correct signature generation as well as acceptance, including
  algorithm-specific randomness and nonce requirements. A signature that
  self-verifies does not prove how it was generated.
- [ ] Exercise each offered sync and async operation, supported form,
  configuration, and claimed profile. Verify capability advertisements and
  error classification against actual behavior.
- [ ] Resolve normative failures before claiming complete conformance.
  Document remaining deliberate divergences and the resulting narrower claim.

Separately validate deployment security and operational requirements. Neither
the fixture suite nor provider qualification certifies an HSM, KMS, library
build, or deployment as FIPS validated.

## Existing RustCrypto types

The `0.6` convenience APIs expose `ed25519-dalek` 3.x and `p256` 0.14
key types. Synchronous provider adapters implement `signature` 3.x traits.
Update your direct dependencies together; Cargo treats types and traits from
incompatible versions as distinct. See Cargo's
[version incompatibility guidance](https://doc.rust-lang.org/cargo/reference/resolver.html#version-incompatibility-hazards).

For P-256, replace `to_encoded_point` with `to_sec1_point` and `SigningKey::random`
with the `p256::elliptic_curve::Generate` trait. The
[`async-provider` example](../examples/async_provider.rs) uses
`try_generate_from_rng` with `rand` 0.10's fallible `SysRng`.
Public-key bytes, signature encodings, and the external `yaml-sigil-traits`
contracts retain their existing formats and behavior.

You can own an application wrapper and implement `TryFrom` into these existing
public types when conversion validates public bytes, or `From` when it is
infallible. Compiling examples accompany
[`resolve_ed25519_verifying_key`](../crates/yaml-sigil-verification/src/lib.rs)
and `resolve_p256_verifying_key`. This does not require exporting a provider's
private key. Opaque private-key operations use the provider adapters, and
direct traits permit entirely different associated key types.

We can introduce a library-owned wrapper if a concrete compatibility or
consumer requirement warrants it. Provider support does not itself require
that migration, and it makes no promise that today's RustCrypto types remain
the boundary indefinitely.
