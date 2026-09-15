// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Example-owned discovery through GitHub's anonymous account SSH-key APIs.

use std::io::Read as _;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::VerifyingKey;
use ssh_key::{Fingerprint, HashAlg, PublicKey};
use ureq::http::{HeaderMap, Response, StatusCode, Uri};
use yaml_sigil_verification::resolve_ed25519_verifying_key;

// These are example discovery policies, not YamlSigil artifact constraints.
const MAX_DISCOVERY_BYTES: usize = 256 * 1024;
const MAX_PAGES_PER_RESOURCE: usize = 10;
const PER_PAGE: usize = 100;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const API_VERSION: &str = "2026-03-10";
const RATE_LIMIT_HELP: &str = "See examples/github-keys/README.md, 'GitHub API rate limits and offline runs', for retry guidance and the explicit public-key option: https://github.com/NVIDIA/yaml-sigil-rs/blob/main/examples/github-keys/README.md#github-api-rate-limits-and-offline-runs";

#[derive(Clone, Debug)]
pub(super) struct GitHubAccount(String);

impl GitHubAccount {
    pub(super) fn key_urls(&self) -> [String; 2] {
        [
            format!("{}/keys", self.0),
            format!("{}/ssh_signing_keys", self.0),
        ]
    }
}

impl FromStr for GitHubAccount {
    type Err = anyhow::Error;

    fn from_str(username: &str) -> Result<Self> {
        // Construct a fixed account prefix for both key resources. Callers
        // cannot select another origin, port, or path.
        ensure!(
            (1..=39).contains(&username.len())
                && username
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !username.starts_with('-')
                && !username.ends_with('-')
                && !username.contains("--"),
            "expected a GitHub username, such as ddurst-nvidia (not a URL)"
        );
        Ok(Self(format!("https://api.github.com/users/{username}")))
    }
}

#[derive(Clone)]
pub(super) struct Candidate {
    pub(super) key: VerifyingKey,
    pub(super) fingerprint: Fingerprint,
    // Set only by discovery, never from an artifact's untrusted keyid hint.
    pub(super) source: Option<String>,
}

pub(super) fn fetch(account: &GitHubAccount) -> Result<Vec<Candidate>> {
    let agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .max_redirects_will_error(true)
        .http_status_as_error(false)
        .timeout_global(Some(REQUEST_TIMEOUT))
        .build()
        .new_agent();
    fetch_pages(account, |url| {
        // Both public account key resources permit anonymous GETs.
        // No token, gh login, private key, or authenticated fallback is used.
        agent
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .header("User-Agent", "yaml-sigil-github-keys-example")
            .call()
            .context("could not fetch GitHub public SSH keys")
    })
}

// Inject the HTTP boundary so tests exercise complete discovery, including
// later-page errors. Never return a partial key set as a successful lookup.
pub(super) fn fetch_pages(
    account: &GitHubAccount,
    mut get: impl FnMut(&str) -> Result<Response<ureq::Body>>,
) -> Result<Vec<Candidate>> {
    let mut remaining = MAX_DISCOVERY_BYTES;
    let mut candidates = Vec::new();
    for endpoint in account.key_urls() {
        let keys = fetch_resource_pages(&endpoint, &mut remaining, &mut get)?;
        // An empty or unsupported-only list does not hide usable keys in the
        // other registration category. Finish both lookups before returning.
        for mut candidate in parse_candidates(&keys.join("\n"))? {
            if !candidates
                .iter()
                .any(|known: &Candidate| known.key == candidate.key)
            {
                candidate.source = Some(endpoint.clone());
                candidates.push(candidate);
            }
        }
    }
    ensure!(
        !candidates.is_empty(),
        "GitHub account lists no supported Ed25519 public keys"
    );
    Ok(candidates)
}

fn fetch_resource_pages(
    endpoint: &str,
    remaining: &mut usize,
    get: &mut impl FnMut(&str) -> Result<Response<ureq::Body>>,
) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    for page in 1..=MAX_PAGES_PER_RESOURCE {
        let url = format!("{endpoint}?per_page={PER_PAGE}&page={page}");
        let response = get(&url)?;
        check_status(&response)?;
        let has_next = has_next_page(response.headers(), endpoint, page)?;
        keys.extend(read_page(response, remaining)?);
        if !has_next {
            return Ok(keys);
        }
    }
    bail!(
        "GitHub public-key discovery exceeds the {MAX_PAGES_PER_RESOURCE}-page limit for {endpoint}"
    )
}

fn check_status(response: &Response<ureq::Body>) -> Result<()> {
    let status = response.status();
    let exhausted = response
        .headers()
        .get("x-ratelimit-remaining")
        .is_some_and(|value| value == "0");
    if status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN
            && (exhausted || response.headers().contains_key("retry-after")))
    {
        let number = |name: &str| {
            response
                .headers()
                .get(name)?
                .to_str()
                .ok()?
                .parse::<u64>()
                .ok()
        };
        if let Some(seconds) = number("retry-after") {
            bail!(
                "GitHub public-key lookup returned HTTP {status}; anonymous API rate limit reached; retry after {seconds} seconds.\n{RATE_LIMIT_HELP}"
            );
        }
        if let Some(reset) = number("x-ratelimit-reset") {
            bail!(
                "GitHub public-key lookup returned HTTP {status}; anonymous API rate limit reached; retry after Unix timestamp {reset}.\n{RATE_LIMIT_HELP}"
            );
        }
        bail!(
            "GitHub public-key lookup returned HTTP {status}; anonymous API rate limit reached; retry later.\n{RATE_LIMIT_HELP}"
        );
    }
    ensure!(
        status == StatusCode::OK,
        "GitHub public-key lookup returned HTTP {status}"
    );
    Ok(())
}

fn has_next_page(headers: &HeaderMap, endpoint: &str, page: usize) -> Result<bool> {
    let expected: Uri = endpoint.parse()?;
    let (_, resource) = expected
        .path()
        .rsplit_once('/')
        .context("invalid key URL")?;
    let suffix = format!("/{resource}");
    let mut next = false;
    // GitHub documents comma-separated <URL>; rel="..." entries. This parser
    // handles that format and rejects malformed links rather than guessing.
    for header in headers.get_all("link") {
        for link in header
            .to_str()
            .context("invalid GitHub Link header")?
            .split(',')
        {
            let (target, parameters) = link
                .trim()
                .split_once('>')
                .context("malformed GitHub pagination link")?;
            let target = target
                .strip_prefix('<')
                .context("malformed GitHub pagination URL")?;
            let mut relation = None;
            ensure!(
                parameters.trim_start().starts_with(';'),
                "missing GitHub link relation"
            );
            for parameter in parameters.split(';').skip(1) {
                let (name, value) = parameter
                    .trim()
                    .split_once('=')
                    .context("malformed GitHub link parameter")?;
                if name == "rel" {
                    ensure!(relation.is_none(), "duplicate GitHub link relation");
                    relation = Some(value.trim_matches('"'));
                }
            }
            let is_next = relation
                .context("missing GitHub link relation")?
                .split_ascii_whitespace()
                .any(|rel| rel == "next");
            if !is_next {
                continue;
            }
            ensure!(!next, "multiple next-page links from GitHub");
            let uri: Uri = target.parse().context("invalid GitHub pagination URL")?;
            // GitHub can canonicalize username routes to /user/NUMERIC_ID/...
            // in Link headers. Read only the next page number; always rebuild
            // the request with the caller-selected username above.
            let numeric_alias = uri
                .path()
                .strip_prefix("/user/")
                .and_then(|path| path.strip_suffix(suffix.as_str()))
                .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()));
            ensure!(
                uri.scheme_str() == Some("https")
                    && uri
                        .authority()
                        .is_some_and(|authority| authority.as_str() == "api.github.com")
                    && !target.contains('#')
                    && (uri.path() == expected.path() || numeric_alias),
                "GitHub pagination link leaves the expected public-key resource"
            );
            let mut next_page = None;
            let mut per_page = None;
            for parameter in uri
                .query()
                .context("GitHub pagination link has no query")?
                .split('&')
            {
                let (name, value) = parameter
                    .split_once('=')
                    .context("invalid GitHub pagination parameter")?;
                let destination = match name {
                    "page" => &mut next_page,
                    "per_page" => &mut per_page,
                    _ => bail!("unexpected GitHub pagination parameter"),
                };
                ensure!(
                    destination.is_none(),
                    "duplicate GitHub pagination parameter"
                );
                *destination = Some(
                    value
                        .parse::<usize>()
                        .context("invalid GitHub page number")?,
                );
            }
            ensure!(
                next_page == Some(page + 1) && per_page == Some(PER_PAGE),
                "GitHub pagination must advance one page with per_page={PER_PAGE}"
            );
            next = true;
        }
    }
    Ok(next)
}

fn read_page(mut response: Response<ureq::Body>, remaining: &mut usize) -> Result<Vec<String>> {
    let media_type = response
        .headers()
        .get("content-type")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.split(';').next());
    ensure!(
        media_type.is_some_and(|value| {
            value.trim().eq_ignore_ascii_case("application/json")
                || value
                    .trim()
                    .eq_ignore_ascii_case("application/vnd.github+json")
        }),
        "GitHub public-key lookup did not return JSON"
    );
    // One extra byte distinguishes a complete response at the budget from a
    // truncated key set. Share the budget across every page in this lookup.
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(*remaining as u64 + 1)
        .read_to_end(&mut bytes)
        .context("could not read GitHub public-key page")?;
    ensure!(
        bytes.len() <= *remaining,
        "GitHub public-key discovery exceeds limit 256 KiB"
    );
    *remaining -= bytes.len();
    let records: Vec<serde_json::Value> =
        serde_json::from_slice(&bytes).context("invalid GitHub public-key JSON")?;
    records
        .into_iter()
        .map(|record| {
            let key = record
                .get("key")
                .and_then(|value| value.as_str())
                .context("GitHub public-key entry has no string key")?;
            ensure!(
                !key.trim().is_empty()
                    && !key.contains(['\r', '\n'])
                    && !key.trim_start().starts_with('#'),
                "GitHub public-key entry must contain one OpenSSH public key"
            );
            Ok(key.to_owned())
        })
        .collect()
}

// This also reads the offline fixture's OpenSSH public-key snapshot. API key
// fields have already been checked to contain exactly one nonempty line each.
pub(super) fn parse_export(export: &str) -> Result<Vec<Candidate>> {
    let candidates = parse_candidates(export)?;
    ensure!(!candidates.is_empty(), "no supported Ed25519 public keys");
    Ok(candidates)
}

fn parse_candidates(export: &str) -> Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    for (index, line) in export.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let public = PublicKey::from_openssh(line).map_err(|error| {
            anyhow::anyhow!("malformed OpenSSH key on line {}: {error}", index + 1)
        })?;
        let Some(ed25519) = public.key_data().ed25519() else {
            // Unsupported algorithms can coexist with ordinary Ed25519 keys.
            continue;
        };
        // The base64 field is an SSH wire blob, not a raw Ed25519 point.
        // Let ssh-key decode it, then use the library's admissibility resolver.
        let key = resolve_ed25519_verifying_key(ed25519.as_ref())
            .with_context(|| format!("inadmissible Ed25519 key on line {}", index + 1))?;
        if !candidates
            .iter()
            .any(|candidate: &Candidate| candidate.key == key)
        {
            candidates.push(Candidate {
                key,
                fingerprint: public.fingerprint(HashAlg::Sha256),
                source: None,
            });
        }
    }
    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> GitHubAccount {
        "ddurst-nvidia".parse().unwrap()
    }

    fn endpoint() -> String {
        account().key_urls()[1].clone()
    }

    fn fetch_single_resource(
        mut get: impl FnMut(&str) -> Result<Response<ureq::Body>>,
    ) -> Result<Vec<Candidate>> {
        let mut remaining = MAX_DISCOVERY_BYTES;
        let keys = fetch_resource_pages(&endpoint(), &mut remaining, &mut get)?;
        parse_export(&keys.join("\n"))
    }

    fn response(status: u16, media_type: &str, bytes: Vec<u8>) -> Response<ureq::Body> {
        Response::builder()
            .status(status)
            .header("content-type", media_type)
            .body(ureq::Body::builder().data(bytes))
            .unwrap()
    }

    fn key(seed: u8) -> String {
        let native = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        PublicKey::new(
            ssh_key::public::Ed25519PublicKey(native.verifying_key().to_bytes()).into(),
            "synthetic test",
        )
        .to_openssh()
        .unwrap()
    }

    fn page(keys: &[String], next: Option<usize>) -> Response<ureq::Body> {
        page_at(&endpoint(), keys, next)
    }

    fn page_at(endpoint: &str, keys: &[String], next: Option<usize>) -> Response<ureq::Body> {
        let records: Vec<_> = keys
            .iter()
            .map(|key| serde_json::json!({"key": key, "id": 1, "title": "ignored metadata"}))
            .collect();
        let mut response = response(
            200,
            "application/json; charset=utf-8",
            serde_json::to_vec(&records).unwrap(),
        );
        if let Some(next) = next {
            response.headers_mut().insert(
                "link",
                format!(
                    "<{}?per_page={PER_PAGE}&page={next}>; rel=\"next\"",
                    endpoint
                )
                .parse()
                .unwrap(),
            );
        }
        response
    }

    #[test]
    fn account_accepts_only_usernames_and_constructs_both_public_urls() {
        for username in ["ddurst-nvidia", "Alice1", "a", &"a".repeat(39)] {
            assert_eq!(
                username.parse::<GitHubAccount>().unwrap().key_urls(),
                [
                    format!("https://api.github.com/users/{username}/keys"),
                    format!("https://api.github.com/users/{username}/ssh_signing_keys"),
                ]
            );
        }
        for invalid in [
            "",
            &"a".repeat(40),
            "-alice",
            "alice-",
            "alice--bob",
            "alice_bob",
            "álîce",
            " alice",
            "alice\n",
            "@alice",
            "alice.keys",
            "alice/extra",
            "../alice",
            "%61lice",
            "alice?x=1",
            "alice#fragment",
            "https://github.com/alice.keys",
            "https://api.github.com/users/alice/ssh_signing_keys",
        ] {
            assert!(invalid.parse::<GitHubAccount>().is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn discovery_collects_every_page_and_deduplicates_keys() {
        let first = key(7);
        let last = key(8);
        let mut responses = vec![
            page(std::slice::from_ref(&first), Some(2)),
            page(&[], Some(3)),
            page(&[first, last.clone()], None),
        ]
        .into_iter();
        let mut requested = Vec::new();
        let candidates = fetch_single_resource(|url| {
            requested.push(url.to_owned());
            Ok(responses.next().unwrap())
        })
        .unwrap();
        assert_eq!(
            requested,
            (1..=3)
                .map(|page| format!("{}?per_page=100&page={page}", endpoint().as_str()))
                .collect::<Vec<_>>()
        );
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[1].fingerprint,
            PublicKey::from_openssh(&last)
                .unwrap()
                .fingerprint(HashAlg::Sha256)
        );
        assert!(responses.next().is_none());
    }

    #[test]
    fn discovery_combines_both_registration_types_and_deduplicates_keys() {
        let account = account();
        let [authentication, signing] = account.key_urls();
        let mut responses = [
            page_at(&authentication, &[key(7)], Some(2)),
            page_at(&authentication, &[key(8)], None),
            page_at(&signing, &[key(8)], Some(2)),
            page_at(&signing, &[key(9)], None),
        ]
        .into_iter();
        let mut requested = Vec::new();
        let candidates = fetch_pages(&account, |url| {
            requested.push(url.to_owned());
            Ok(responses.next().unwrap())
        })
        .unwrap();
        assert_eq!(
            requested,
            [
                format!("{authentication}?per_page=100&page=1"),
                format!("{authentication}?per_page=100&page=2"),
                format!("{signing}?per_page=100&page=1"),
                format!("{signing}?per_page=100&page=2"),
            ]
        );
        assert_eq!(candidates.len(), 3);
        for (candidate, seed) in candidates.iter().zip([7, 8, 9]) {
            assert_eq!(
                candidate.fingerprint,
                PublicKey::from_openssh(&key(seed))
                    .unwrap()
                    .fingerprint(HashAlg::Sha256)
            );
        }
        assert_eq!(
            candidates[0].source.as_deref(),
            Some(authentication.as_str())
        );
        assert_eq!(
            candidates[1].source.as_deref(),
            Some(authentication.as_str())
        );
        assert_eq!(candidates[2].source.as_deref(), Some(signing.as_str()));
        assert!(responses.next().is_none());
    }

    #[test]
    fn either_registration_list_can_be_empty_or_have_only_unsupported_keys() {
        let p256 = p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
        let unsupported = PublicKey::new(
            ssh_key::public::EcdsaPublicKey::NistP256(p256.verifying_key().to_encoded_point(false))
                .into(),
            "unsupported algorithm",
        )
        .to_openssh()
        .unwrap();
        let account = account();
        let urls = account.key_urls();
        for populated_url in &urls {
            for other_keys in [vec![], vec![unsupported.clone()]] {
                let mut calls = 0;
                let candidates = fetch_pages(&account, |url| {
                    calls += 1;
                    let keys = if url.starts_with(populated_url) {
                        vec![key(7)]
                    } else {
                        other_keys.clone()
                    };
                    Ok(page(&keys, None))
                })
                .unwrap();
                assert_eq!(calls, 2);
                assert_eq!(candidates.len(), 1);
                assert_eq!(
                    candidates[0].source.as_deref(),
                    Some(populated_url.as_str())
                );
            }
        }
        assert!(fetch_pages(&account, |_| Ok(page(&[], None))).is_err());
        assert!(
            fetch_pages(&account, |_| Ok(page(
                std::slice::from_ref(&unsupported),
                None
            )))
            .is_err()
        );
    }

    #[test]
    fn second_resource_failures_never_return_a_partial_key_set() {
        for second in [
            response(403, "application/json", vec![]),
            response(200, "application/json", b"not JSON".to_vec()),
            page(&["not an SSH key".to_owned()], None),
        ] {
            let mut responses = [page(&[key(7)], None), second].into_iter();
            assert!(fetch_pages(&account(), |_| Ok(responses.next().unwrap())).is_err());
            assert!(responses.next().is_none());
        }
        let mut calls = 0;
        let result = fetch_pages(&account(), |_| {
            calls += 1;
            if calls == 2 {
                bail!("connection failed")
            }
            Ok(page(&[key(7)], None))
        });
        assert!(result.is_err());
        assert_eq!(calls, 2);
    }

    #[test]
    fn discovery_shares_the_byte_budget_and_bounds_each_resource() {
        let mut first = serde_json::to_vec(&serde_json::json!([{"key": key(7)}])).unwrap();
        first.resize(MAX_DISCOVERY_BYTES - 2, b' ');
        for extra in [false, true] {
            let last = if extra {
                b"[] ".to_vec()
            } else {
                b"[]".to_vec()
            };
            let mut responses = [
                response(200, "application/json", first.clone()),
                response(200, "application/json", last),
            ]
            .into_iter();
            let result = fetch_pages(&account(), |_| Ok(responses.next().unwrap()));
            if extra {
                assert!(result.err().unwrap().to_string().contains("limit 256 KiB"));
            } else {
                assert_eq!(result.unwrap().len(), 1);
            }
        }
        let account = account();
        let [authentication, signing] = account.key_urls();
        let mut calls = 0;
        let mut signing_pages = 0;
        let result = fetch_pages(&account, |url| {
            calls += 1;
            if url.starts_with(&authentication) {
                return Ok(page(&[key(7)], None));
            }
            signing_pages += 1;
            Ok(page_at(&signing, &[key(8)], Some(signing_pages + 1)))
        });
        assert!(result.err().unwrap().to_string().contains("page limit"));
        assert_eq!(calls, MAX_PAGES_PER_RESOURCE + 1);
    }

    #[test]
    fn numeric_pagination_aliases_cannot_switch_registration_resources() {
        let urls = account().key_urls();
        for (index, endpoint) in urls.iter().enumerate() {
            let resource = endpoint.rsplit('/').next().unwrap();
            let other = &urls[1 - index];
            let mut headers = HeaderMap::new();
            headers.insert(
                "link",
                format!(
                    "<https://api.github.com/user/123/{resource}?per_page=100&page=2>; rel=\"next\""
                )
                .parse()
                .unwrap(),
            );
            assert!(has_next_page(&headers, endpoint, 1).unwrap());
            for wrong in [
                other.clone(),
                format!(
                    "https://api.github.com/user/123/{}",
                    other.rsplit('/').next().unwrap()
                ),
            ] {
                headers.insert(
                    "link",
                    format!("<{wrong}?per_page=100&page=2>; rel=\"next\"")
                        .parse()
                        .unwrap(),
                );
                assert!(has_next_page(&headers, endpoint, 1).is_err());
            }
        }
    }

    #[test]
    fn later_page_failures_never_return_a_partial_key_set() {
        for second in [
            response(403, "application/json", vec![]),
            response(200, "application/json", b"not JSON".to_vec()),
        ] {
            let mut responses = [page(&[key(7)], Some(2)), second].into_iter();
            assert!(fetch_single_resource(|_| Ok(responses.next().unwrap())).is_err());
            assert!(responses.next().is_none());
        }
        let mut calls = 0;
        let error = fetch_single_resource(|_| {
            calls += 1;
            if calls == 2 {
                bail!("connection failed")
            }
            Ok(page(&[key(7)], Some(2)))
        })
        .err()
        .unwrap();
        assert_eq!(calls, 2);
        assert!(error.to_string().contains("connection failed"));
    }

    #[test]
    fn pagination_stays_on_the_selected_account_and_rejects_incomplete_links() {
        let mut headers = HeaderMap::new();
        // Numeric aliases supply pagination only; requests retain the username.
        headers.insert("link", "<https://api.github.com/user/123/ssh_signing_keys?per_page=100&page=2>; rel=\"next\", <https://api.github.com/user/123/ssh_signing_keys?per_page=100&page=5>; rel=\"last\"".parse().unwrap());
        assert!(has_next_page(&headers, &endpoint(), 1).unwrap());
        let mut first = page(&[key(7)], None);
        first.headers_mut().extend(headers);
        let mut responses = [first, page(&[key(8)], None)].into_iter();
        fetch_single_resource(|url| {
            assert!(
                url.starts_with("https://api.github.com/users/ddurst-nvidia/ssh_signing_keys?")
            );
            Ok(responses.next().unwrap())
        })
        .unwrap();
        let endpoint = endpoint();
        for target in [
            "https://other.example/users/ddurst-nvidia/ssh_signing_keys?per_page=100&page=2"
                .to_owned(),
            "http://api.github.com/users/ddurst-nvidia/ssh_signing_keys?per_page=100&page=2"
                .to_owned(),
            "https://user@api.github.com/users/ddurst-nvidia/ssh_signing_keys?per_page=100&page=2"
                .to_owned(),
            "https://api.github.com:443/users/ddurst-nvidia/ssh_signing_keys?per_page=100&page=2"
                .to_owned(),
            "https://api.github.com/users/someone-else/ssh_signing_keys?per_page=100&page=2"
                .to_owned(),
            format!("{}?per_page=100&page=2#fragment", endpoint.as_str()),
            format!("{}?per_page=100&page=1", endpoint.as_str()),
            format!("{}?per_page=100&page=3", endpoint.as_str()),
            format!("{}?per_page=30&page=2", endpoint.as_str()),
            format!("{}?per_page=100&page=2&page=2", endpoint.as_str()),
            format!("{}?per_page=100&page=2&extra=value", endpoint.as_str()),
            endpoint.as_str().to_owned(),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("link", format!("<{target}>; rel=\"next\"").parse().unwrap());
            assert!(has_next_page(&headers, &endpoint, 1).is_err(), "{target}");
        }
        for link in [
            "not a link",
            "<https://api.github.com/>; title=\"missing relation\"",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("link", link.parse().unwrap());
            assert!(has_next_page(&headers, &endpoint, 1).is_err());
        }
        let mut repeated = page(&[], Some(2));
        let duplicate = repeated.headers()["link"].clone();
        repeated.headers_mut().append("link", duplicate);
        assert!(has_next_page(repeated.headers(), &endpoint, 1).is_err());
    }

    #[test]
    fn discovery_limits_fail_instead_of_truncating_the_key_set() {
        let mut first = serde_json::to_vec(&serde_json::json!([{"key": key(7)}])).unwrap();
        first.resize(MAX_DISCOVERY_BYTES - 2, b' ');
        for extra in [false, true] {
            let mut first_page = response(200, "application/json", first.clone());
            first_page
                .headers_mut()
                .extend(page(&[], Some(2)).headers().clone());
            let last = if extra {
                b"[] ".to_vec()
            } else {
                b"[]".to_vec()
            };
            let mut responses = [first_page, response(200, "application/json", last)].into_iter();
            let result = fetch_single_resource(|_| Ok(responses.next().unwrap()));
            if extra {
                assert!(result.err().unwrap().to_string().contains("limit 256 KiB"));
            } else {
                assert_eq!(result.unwrap().len(), 1);
            }
        }
        let mut calls = 0;
        let error = fetch_single_resource(|_| {
            calls += 1;
            Ok(page(&[key(7)], Some(calls + 1)))
        })
        .err()
        .unwrap();
        assert_eq!(calls, MAX_PAGES_PER_RESOURCE);
        assert!(error.to_string().contains("page limit"));
    }

    #[test]
    fn response_rejects_denials_redirects_html_and_malformed_key_records() {
        for status in [204, 206, 301, 302, 401, 403, 404, 429, 500] {
            let error = check_status(&response(status, "application/json", vec![])).unwrap_err();
            assert!(error.to_string().contains(&status.to_string()));
        }
        for (media, bytes) in [
            ("text/html", b"<html>login</html>".to_vec()),
            ("text/plain", key(7).into_bytes()),
            ("application/json", vec![0xff]),
            ("application/json", b"{}".to_vec()),
            ("application/json", b"[{}]".to_vec()),
            ("application/json", b"[{\"key\":null}]".to_vec()),
            ("application/json", b"[{\"key\":\"\"}]".to_vec()),
            ("application/json", b"[{\"key\":\"# comment\"}]".to_vec()),
            (
                "application/json",
                serde_json::to_vec(&serde_json::json!([{"key":format!("{}\n{}",key(7),key(8))}]))
                    .unwrap(),
            ),
        ] {
            let mut remaining = MAX_DISCOVERY_BYTES;
            assert!(read_page(response(200, media, bytes), &mut remaining).is_err());
        }
        assert!(fetch_single_resource(|_| Ok(page(&["not a key".to_owned()], None))).is_err());
        assert!(fetch_single_resource(|_| Ok(page(&[], None))).is_err());
    }

    #[test]
    fn rate_limits_report_when_to_retry_without_authentication() {
        let mut response = response(403, "application/json", vec![]);
        response
            .headers_mut()
            .insert("x-ratelimit-remaining", "0".parse().unwrap());
        response
            .headers_mut()
            .insert("x-ratelimit-reset", "1234567890".parse().unwrap());
        let error = check_status(&response).unwrap_err().to_string();
        assert!(error.contains("anonymous API rate limit"));
        assert!(error.contains("1234567890"));
        assert!(error.contains("README.md#github-api-rate-limits-and-offline-runs"));
        response
            .headers_mut()
            .insert("retry-after", "30".parse().unwrap());
        assert!(
            check_status(&response)
                .unwrap_err()
                .to_string()
                .contains("30 seconds")
        );
        response
            .headers_mut()
            .insert("retry-after", "invalid".parse().unwrap());
        response
            .headers_mut()
            .insert("x-ratelimit-reset", "invalid".parse().unwrap());
        assert!(
            check_status(&response)
                .unwrap_err()
                .to_string()
                .contains("retry later")
        );
    }

    #[test]
    fn response_preserves_read_and_timeout_errors() {
        struct TimedOut;
        impl std::io::Read for TimedOut {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
            }
        }
        let response = Response::builder()
            .header("content-type", "application/json")
            .body(ureq::Body::builder().reader(TimedOut))
            .unwrap();
        let mut remaining = MAX_DISCOVERY_BYTES;
        assert!(read_page(response, &mut remaining).is_err());
        assert_eq!(remaining, MAX_DISCOVERY_BYTES);
    }
}
