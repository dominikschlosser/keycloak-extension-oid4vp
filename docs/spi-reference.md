# SPI Reference

## OID4VP Event SPI

The extension fires events for security relevant decisions. Events hold no credential claims. Listeners run synchronously where the event fires, in the request or in the background CRL task, and a failing listener affects neither other listeners nor the login. A factory whose `create()` throws drops that event for its own listener only.

### Available Events

| Event | When Fired | Key Data |
|-------|------------|----------|
| `PresentationVerifiedEvent` | A wallet presentation passed verification. A repeated verified presentation for the same state fires none | `state`, `flow`, `credentialTypes` |
| `PresentationFailedEvent` | A wallet response ended without a verified presentation | `state`, `flow`, `origin`, `error`, `reason` |
| `PresentationRefusedEvent` | A login or a verified presentation does not meet what the flow requires | `userId`, `state`, `refusal`, `reason` |
| `CompletionRejectedEvent` | Keycloak refused a step towards completing a login | `state`, `rejection`, `reason` |
| `RevocationDetectedEvent` | A status list or CRL marks a credential or an issuer certificate as revoked or suspended | `trustProviderId`, `mechanism`, `reference`, `state` |
| `RevocationCheckFailedEvent` | A revocation status could not be determined | `trustProviderId`, `mechanism`, `reference`, `state`, `staleDataInUse`, `reason` |
| `TrustMaterialFailedEvent` | Trust material is missing or weaker than configured | `trustProviderId`, `failure`, `reference`, `staleDataInUse`, `reason` |

Match on the enum attributes. `reason` is free text and can change.

| Attribute | Value | Meaning |
|-----------|-------|---------|
| `origin` | `VERIFIER` | Verification rejected the presentation |
| | `SERVER` | Verification broke on the server side, a status list or a required CRL was unavailable, or a credential had no issuer trust because a trust list had no usable copy. The presentation received no verdict |
| | `WALLET` | The wallet answered with an error response, which nothing authenticates. A user who declines ends up here |
| | `TRANSPORT` | The post failed before its presentation could be verified, for example an undecryptable or unencrypted response |
| `refusal` | `USER_MISMATCH` | The presentation does not fit the user of the authentication flow |
| | `LEVEL_NOT_OFFERED` | No OID4VP flow offers the requested level of authentication |
| | `CREDENTIAL_IGNORED` | Keycloak left a credential out, because it was issued for another presentation or lacks a reference binding. The login continues without it |
| `rejection` | `RESPONSE_CODE` | The state has no record, or the response code does not match it |
| | `BROWSER_MISMATCH` | The browser is not the one that started the login |
| | `REPEATED_PRESENTATION` | A further verified presentation arrived for a state that already has one. A wallet retry looks the same. The first presentation stays in force |
| `mechanism` | `STATUS_LIST`, `CRL`, `IDENTIFIER_LIST` | How the revocation is published. `IDENTIFIER_LIST` only occurs on `RevocationCheckFailedEvent`, because the extension does not read identifier lists |
| `failure` | `REFRESH_FAILED` | A trust list could not be fetched or verified, or it is closed. Fires at most once per provider and request, and not during the retry pause. Without a stale copy the list adds no certificates |
| | `UNSIGNED` | Keycloak read a trust list without a signature check, once per provider on each node, before it parses the list, or a status list, once per download |
| | `UNAVAILABLE` | None of the configured trust material identity providers resolved, so Keycloak rejects every credential |

| Attribute | Meaning |
|-----------|---------|
| `staleDataInUse` | A last known CRL or a stale trust list still applies |

A `RevocationCheckFailedEvent` does not say whether the login goes on:

- A failed status list check rejects the credential.
- A CRL check without a known CRL rejects the credential with `crlRequired` and accepts it unchecked otherwise. Without `crlRequired` the event fires once per failed download and for each login that waited. Later logins fire none until the cache TTL ends.
- An identifier list stays unchecked, and a credential with both an identifier list and a status list still gets the status list check.

A rejection also fires `PresentationFailedEvent` with the same `state`. An event with a `state` and no such match means the credential continued, unchecked unless `staleDataInUse` is true.

- All events include `realmId` (null outside a realm) and `timestamp`.
- `identityProvider` names the OID4VP identity provider, and `trustProviderId` is the internal id of a trust material identity provider. Status list events, identifier list events and `UNAVAILABLE` have no `trustProviderId`.
- `clientId` and `userId` are set where known. Most events have no user.
- `PresentationRefusedEvent` carries `state` only for `CREDENTIAL_IGNORED`.
- A revocation rejection fires `PresentationFailedEvent` and `RevocationDetectedEvent` with the same `state`.
- A `RevocationCheckFailedEvent` from a background CRL refresh has no `state`.
- Wallets and issuers control parts of `reason`, `reference`, `state` and error values, so treat them as untrusted text. `Oid4vpEvent.details()` reduces each value to one line, cut at 1024 characters. The record fields keep the original text.

### Built-in Listeners

#### Keycloak Event Bridge (`keycloak-event-bridge`)

Forwards the events to Keycloak's event system: the Admin Console, the event store and the `EventListenerProvider`s enabled in the realm. It is disabled by default. Enable it in `keycloak.conf`:

```properties
spi-oid4vp-event-listener--keycloak-event-bridge--enabled=true
```

Or through the environment:

```bash
KC_SPI_OID4VP_EVENT_LISTENER__KEYCLOAK_EVENT_BRIDGE__ENABLED=true
```

`enabled` is a build option: set it for `kc.sh build`, or start without `--optimized`.

| OID4VP Event | Keycloak EventType | Error Code |
|--------------|--------------------|------------|
| `PresentationVerifiedEvent` | `IDENTITY_PROVIDER_RESPONSE` | - |
| `PresentationFailedEvent` | `IDENTITY_PROVIDER_RESPONSE_ERROR` | `oid4vp_presentation_failed` |
| `PresentationRefusedEvent` | `IDENTITY_PROVIDER_LOGIN_ERROR`, or `IDENTITY_PROVIDER_RESPONSE_ERROR` for `CREDENTIAL_IGNORED`, because that login continues | `oid4vp_presentation_refused` |
| `CompletionRejectedEvent` | `IDENTITY_PROVIDER_RESPONSE_ERROR` | `oid4vp_completion_rejected` |
| `RevocationDetectedEvent` | `IDENTITY_PROVIDER_RESPONSE_ERROR` | `oid4vp_revocation_detected` |
| `RevocationCheckFailedEvent` | `IDENTITY_PROVIDER_RESPONSE_ERROR` | `oid4vp_revocation_check_failed` |
| `TrustMaterialFailedEvent` | `IDENTITY_PROVIDER_RESPONSE_ERROR` | `oid4vp_trust_material_failed` |

- `oid4vp_event_type` holds the event type, for example `REVOCATION_CHECK_FAILED`, and tells apart events with the same Keycloak type.
- `Event.getDetails()` holds the key data under `oid4vp_` keys, for example `oid4vp_reason`. `Oid4vpEventDetails` defines them.
- The event store keeps only the types enabled in the realm's event configuration. `EventListenerProvider`s enabled in the realm receive every event. To store bridged events, turn on the realm's save events switch and enable `IDENTITY_PROVIDER_RESPONSE`, `IDENTITY_PROVIDER_RESPONSE_ERROR` and `IDENTITY_PROVIDER_LOGIN_ERROR`.
- The bridge adds no `LOGIN_ERROR`, because it uses identity provider event types, so it does not change brute force counts.
- The bridge drops events without a realm.
- An event from a background CRL refresh has no IP address.
- `CompletionRejectedEvent` and `PresentationFailedEvent` with origin `TRANSPORT` fire on unauthenticated requests, so a client can cause event store writes.

#### Logging Listener (`log`)

Logs `PresentationVerifiedEvent` and wallet errors at INFO, and all other events at WARN. To change the output, configure Keycloak's logging:

```properties
quarkus.log.category."de.arbeitsagentur.keycloak.oid4vp.event".level=WARN
```

### Custom Listeners

Implement `Oid4vpEventListener` and `Oid4vpEventListenerFactory`, and register the factory in `META-INF/services/de.arbeitsagentur.keycloak.oid4vp.event.Oid4vpEventListenerFactory`. All handlers default to empty. `onEvent` runs for every event before the specific handler.

```java
public class SiemEventListener implements Oid4vpEventListener {

    @Override
    public void onRevocationCheckFailed(RevocationCheckFailedEvent event) {
        // Forward the event. Listeners run during the request, so hand it off without blocking.
    }
}
```

## Reference Credential Binding SPI

The credential this Keycloak issues identifies an account on its own, so it needs a link to the PID it was issued with. Without that link, one person's employee credential next to another person's PID would sign in as the first person.

- The issued credential carries a keyed digest of the credential types and claims it was issued alongside.
- The verifier recomputes the digest from the current presentation.
- On a mismatch it treats the credential as not presented, so neither its subject nor its claims reach the login.
- The digest is an HMAC over a realm secret, because a plain hash of names and dates can be recovered from a candidate list. Passive realm keys still verify, so a key rotation keeps issued credentials valid.
- The binding covers claims of the person, so re-issued and batch-issued PIDs keep it. Two people who share every bound claim share a binding.
- Holder binding is separate: it ties a credential to a wallet key.

The `oid4vp-reference-credential-binding` provider selects the claims. The built-in `pid` provider reads its selection from the server configuration, because the login that issues a credential and the login that presents it share no other configuration. These are the defaults:

```properties
--spi-oid4vp-reference-credential-binding--pid--credential-types=urn:eudi:pid:1
--spi-oid4vp-reference-credential-binding--pid--claims=given_name,family_name,birthdate,personal_administrative_number
```

- **Credential types:** the VCT of an SD-JWT credential or the doctype of an mDoc. For the mDoc PID, configure `eu.europa.ec.eudi.pid.1` with the mDoc element names, for example `birth_date`.
- **Claim paths:** the same dot notation as the [IdP mappers](configuration.md#idp-mappers), for example `place_of_birth.locality` and `nationalities[]`. An mDoc path resolves inside the namespace of the credential.
- **Object and array claims:** read with ordered keys, so a different rendering by the wallet produces the same binding.
- **`personal_administrative_number`:** bound only when the PID carries it. If your PIDs omit it, name another claim that is unique to the person.
- **Empty `claims`:** Keycloak refuses this at startup. Binding everything would include issuance metadata, and a re-issued PID would break the binding.

When a bound claim changes, the verifier treats the credential as not presented. The user signs in with a password and Keycloak issues a credential bound to the current PID. Fewer claims make this rarer and the binding weaker. To bind to something other than a PID, write your own provider for this SPI.

A credential without a binding, such as one from another issuer, is accepted in any presentation. The exception is the credential that carries the subject: if it has no binding and sits next to credentials a binding would cover, Keycloak does not use it as the subject and fires `PresentationRefusedEvent` with `CREDENTIAL_IGNORED`.
