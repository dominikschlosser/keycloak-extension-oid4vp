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

import java.time.Instant;
import java.util.List;

final class Oid4vpEventsFixture {

    static final List<Oid4vpEvent> ALL = List.of(
            new PresentationVerifiedEvent("value", "value", "value", "value", "value", List.of("value"), Instant.EPOCH),
            new PresentationFailedEvent(
                    "value",
                    "value",
                    "value",
                    "value",
                    "value",
                    PresentationFailedEvent.Origin.VERIFIER,
                    "value",
                    "value",
                    Instant.EPOCH),
            new PresentationRefusedEvent(
                    "value",
                    "value",
                    "value",
                    "value",
                    "value",
                    PresentationRefusedEvent.Refusal.USER_MISMATCH,
                    "value",
                    Instant.EPOCH),
            new CompletionRejectedEvent(
                    "value", "value", "value", CompletionRejectedEvent.Rejection.RESPONSE_CODE, "value", Instant.EPOCH),
            new RevocationDetectedEvent("value", "value", RevocationMechanism.CRL, "value", "value", Instant.EPOCH),
            new RevocationCheckFailedEvent(
                    "value", "value", RevocationMechanism.CRL, "value", "value", true, "value", Instant.EPOCH),
            new TrustMaterialFailedEvent(
                    "value",
                    "value",
                    TrustMaterialFailedEvent.Failure.REFRESH_FAILED,
                    "value",
                    true,
                    "value",
                    Instant.EPOCH));

    private Oid4vpEventsFixture() {}

    record RecordingListener(List<Oid4vpEvent> received) implements Oid4vpEventListener {

        @Override
        public void onPresentationVerified(PresentationVerifiedEvent event) {
            received.add(event);
        }

        @Override
        public void onPresentationFailed(PresentationFailedEvent event) {
            received.add(event);
        }

        @Override
        public void onPresentationRefused(PresentationRefusedEvent event) {
            received.add(event);
        }

        @Override
        public void onCompletionRejected(CompletionRejectedEvent event) {
            received.add(event);
        }

        @Override
        public void onRevocationDetected(RevocationDetectedEvent event) {
            received.add(event);
        }

        @Override
        public void onRevocationCheckFailed(RevocationCheckFailedEvent event) {
            received.add(event);
        }

        @Override
        public void onTrustMaterialFailed(TrustMaterialFailedEvent event) {
            received.add(event);
        }
    }
}
