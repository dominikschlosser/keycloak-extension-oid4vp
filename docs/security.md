# Security

## Revocation

| Layer | Covers | Check |
|-------|--------|-------|
| Token Status List | A single credential | The verifier reads the credential's status |
| CRL | The certificates that signed the credential | The verifier checks the chain's leaf and intermediates, each against the CRL of its issuing CA |

- **Skipped by the CRL check:** Trust anchors and pinned certificates, because the trust source withdraws those itself, and certificates without a CRL distribution point, unless `crlEndpoint` covers them. A certificate with unreadable or only non-http(s) points, or without a path to an anchor, fires the event, and `crlRequired` rejects it.
- **Status list signatures:** The verifier checks a status list against the revocation certificates of the trust source. The realm issuer provider, the `default-trust` adapter and a trust list without `/Revocation` services provide none, so the signature stays unverified and whoever serves the status URI decides the status. Each such download logs a warning and fires `TrustMaterialFailedEvent` with `UNSIGNED`.
- **Identifier lists:** A credential that references an identifier list (ISO/IEC 18013-5 second edition) stays unchecked, and the verifier logs a warning. A credential with both an identifier list and a status list still gets the status list check.
- **Settings:** CRL settings live on the trust material identity provider, because each trust domain has its own CAs. The provider that accepts the chain decides how the chain is checked. When several providers accept the same chain, the first one decides.
- **Cache:** Each trust material provider keeps its own CRL cache and downloads the CRL itself, even when it shares a CA with another provider.

### CRL Download

- **Background download:** A background task fetches a CRL that is missing or expired, and each node runs one such task per provider and CRL. A login uses the cached CRL and does not wait for a refresh.
- **Revocation delay:** While the CA is reachable, a revocation normally takes effect after the cache TTL plus one refresh.
- **First download:** A login that finds no CRL waits up to 3 seconds for the download, unless a failure is cached and `crlRequired` is off, so the first presentation for an issuer is checked as well. The wait repeats on each node after a restart, because the cache is held in memory.
- **No known CRL:** With `crlRequired` the login ignores a cached failure and starts a download or joins the running one, and the verifier rejects the credential only when that attempt brings no CRL. An unreachable CA then stops the logins of its issuers on a node without a CRL, and each of those logins waits up to 3 seconds. Without `crlRequired` the verifier accepts the credential unchecked. A login that waited without a result fires a `RevocationCheckFailedEvent` with its state. Without `crlRequired`, logins during a cached failure fire none. ISO/IEC 18013-5 requires revocation information for mDL, so enable `crlRequired` for mDL trust domains.
- **Failed fetch:** The verifier logs a warning, fires a `RevocationCheckFailedEvent` and caches the failure for `crlMaxCacheTtlSeconds`, so an outage costs one attempt per cache TTL. With `crlRequired` and no known CRL, the attempts follow the logins, one at a time per CRL.
- **Last known CRL:** It stays in use however old it is, and a certificate listed on it stays rejected.
- **Invalid CRL:** The verifier treats a fetched CRL as failed when its issuer or signature does not match the issuing CA, when its `nextUpdate` has passed, when its `thisUpdate` lies more than 5 minutes ahead, when it is older than the cached CRL, when it has an unknown critical extension, or when it is a delta or scoped CRL. Without a last known CRL, credentials of a CA that publishes only such CRLs stay unchecked, or `crlRequired` rejects them.
- **Download limits:** A download that exceeds 30 seconds or 16 MiB counts as failed. The HTTP client's socket timeout ends a stalled read.
- **Cache size:** Each provider keeps up to 256 CRLs, so one provider cannot evict the CRLs of another.
