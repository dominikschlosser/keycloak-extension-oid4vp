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

import java.util.Map;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;

// Logs every event, at WARN unless it reports a verified presentation or a wallet error.
final class LoggingOid4vpEventListener implements Oid4vpEventListener {

    private static final Logger LOG = Logger.getLogger(LoggingOid4vpEventListener.class);

    @Override
    public void onEvent(Oid4vpEvent event) {
        LOG.logf(
                isRoutine(event) ? Logger.Level.INFO : Logger.Level.WARN,
                "OID4VP event: type=%s, realm=%s, client=%s, user=%s, details=%s",
                event.eventType(),
                event.realmId(),
                event.clientId(),
                event.userId(),
                quoted(event.details()));
    }

    // Quotes the values, so that text a wallet chose cannot pass as another field.
    private static String quoted(Map<String, String> details) {
        return details.entrySet().stream()
                .map(detail -> detail.getKey() + "=\"" + detail.getValue().replace("\"", "'") + "\"")
                .collect(Collectors.joining(", "));
    }

    // Treats a wallet error as routine, because a user who declines ends up there.
    private static boolean isRoutine(Oid4vpEvent event) {
        return event instanceof PresentationVerifiedEvent
                || event instanceof PresentationFailedEvent failed
                        && failed.origin() == PresentationFailedEvent.Origin.WALLET;
    }
}
