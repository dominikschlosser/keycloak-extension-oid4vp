/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.arbeitsagentur.keycloak.oid4vp.event;

import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.keycloak.oid4vp.event.KeycloakEventBridgeListener.KeycloakEvent;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.events.EventType;

class KeycloakEventBridgeListenerTest {

    private static KeycloakEvent bridged(Oid4vpEvent event) {
        List<KeycloakEvent> sent = new ArrayList<>();
        new KeycloakEventBridgeListener(sent::add).onEvent(event);
        assertThat(sent).hasSize(1);
        return sent.get(0);
    }

    @Test
    void verifiedPresentationIsASuccessfulIdentityProviderResponse() {
        KeycloakEvent event = bridged(new PresentationVerifiedEvent(
                "realm", "wallet", "client", "state", "same_device", List.of("urn:pid", "urn:mdl"), Instant.EPOCH));

        assertThat(event.type()).isEqualTo(EventType.IDENTITY_PROVIDER_RESPONSE);
        assertThat(event.error()).isNull();
        assertThat(event.clientId()).isEqualTo("client");
        assertThat(event.details())
                .containsEntry(Oid4vpEventDetails.EVENT_TYPE, "PRESENTATION_VERIFIED")
                .containsEntry(Oid4vpEventDetails.IDENTITY_PROVIDER, "wallet")
                .containsEntry(Oid4vpEventDetails.CREDENTIAL_TYPES, "urn:pid,urn:mdl");
    }

    @Test
    void failureIsAnIdentityProviderResponseErrorAndNoLoginError() {
        KeycloakEvent event = bridged(new PresentationFailedEvent(
                "realm",
                "wallet",
                "client",
                "state",
                "same_device",
                PresentationFailedEvent.Origin.VERIFIER,
                null,
                "bad signature",
                Instant.EPOCH));

        assertThat(event.type()).isEqualTo(EventType.IDENTITY_PROVIDER_RESPONSE_ERROR);
        assertThat(event.error()).isEqualTo("oid4vp_presentation_failed");
        assertThat(event.details())
                .containsEntry(Oid4vpEventDetails.ORIGIN, "VERIFIER")
                .containsEntry(Oid4vpEventDetails.REASON, "bad signature")
                .doesNotContainKey(Oid4vpEventDetails.ERROR);
    }

    @Test
    void refusalCarriesTheUserAndIsALoginError() {
        KeycloakEvent event = bridged(new PresentationRefusedEvent(
                "realm",
                "wallet",
                "client",
                "user",
                null,
                PresentationRefusedEvent.Refusal.USER_MISMATCH,
                "other user",
                Instant.EPOCH));

        assertThat(event.type()).isEqualTo(EventType.IDENTITY_PROVIDER_LOGIN_ERROR);
        assertThat(event.userId()).isEqualTo("user");
        assertThat(event.details()).containsEntry(Oid4vpEventDetails.REFUSAL, "USER_MISMATCH");
    }

    @Test
    void ignoredCredentialIsNoLoginError() {
        KeycloakEvent event = bridged(new PresentationRefusedEvent(
                "realm",
                "wallet",
                null,
                null,
                null,
                PresentationRefusedEvent.Refusal.CREDENTIAL_IGNORED,
                "Credential pid: issued for another presentation",
                Instant.EPOCH));

        assertThat(event.type()).isEqualTo(EventType.IDENTITY_PROVIDER_RESPONSE_ERROR);
    }

    @Test
    void revocationCheckFailureSaysWhetherStaleDataIsInUse() {
        KeycloakEvent event = bridged(new RevocationCheckFailedEvent(
                "realm",
                null,
                RevocationMechanism.CRL,
                "https://ca.example/ca.crl",
                "state",
                false,
                "HTTP 503",
                Instant.EPOCH));

        assertThat(event.details())
                .doesNotContainKey(Oid4vpEventDetails.TRUST_PROVIDER)
                .containsEntry(Oid4vpEventDetails.MECHANISM, "CRL")
                .containsEntry(Oid4vpEventDetails.STATE, "state")
                .containsEntry(Oid4vpEventDetails.STALE_DATA_IN_USE, "false");
    }

    @Test
    void valuesAreBounded() {
        KeycloakEvent event = bridged(new CompletionRejectedEvent(
                "realm",
                "wallet",
                "x".repeat(5000),
                CompletionRejectedEvent.Rejection.RESPONSE_CODE,
                "no record",
                Instant.EPOCH));

        assertThat(event.details().get(Oid4vpEventDetails.STATE)).hasSizeLessThan(1100);
    }

    @Test
    void walletChosenTextStaysOnOneLine() {
        KeycloakEvent event = bridged(new PresentationFailedEvent(
                "realm",
                "wallet",
                "client",
                "state",
                "same_device",
                PresentationFailedEvent.Origin.WALLET,
                "denied\nforged=1",
                null,
                Instant.EPOCH));

        assertThat(event.details()).containsEntry(Oid4vpEventDetails.ERROR, "denied forged=1");
    }

    @Test
    void eventWithoutARealmIsNotBridged() {
        List<KeycloakEvent> sent = new ArrayList<>();
        new KeycloakEventBridgeListener(sent::add)
                .onEvent(new RevocationDetectedEvent(
                        null, null, RevocationMechanism.CRL, "certificate", null, Instant.EPOCH));

        assertThat(sent).isEmpty();
    }
}
