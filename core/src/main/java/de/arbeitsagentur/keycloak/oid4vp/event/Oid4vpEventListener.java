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

import org.keycloak.provider.Provider;

/**
 * Reacts to the security events of the extension. Events fire synchronously in the request or the
 * background CRL task, so an implementation must not block. Handlers default to empty, so a listener overrides only the
 * events it cares about. {@link #onEvent} runs for every event before the specific handler.
 */
public interface Oid4vpEventListener extends Provider {

    default void onEvent(Oid4vpEvent event) {}

    default void onPresentationVerified(PresentationVerifiedEvent event) {}

    default void onPresentationFailed(PresentationFailedEvent event) {}

    default void onPresentationRefused(PresentationRefusedEvent event) {}

    default void onCompletionRejected(CompletionRejectedEvent event) {}

    default void onRevocationDetected(RevocationDetectedEvent event) {}

    default void onRevocationCheckFailed(RevocationCheckFailedEvent event) {}

    default void onTrustMaterialFailed(TrustMaterialFailedEvent event) {}

    @Override
    default void close() {}
}
