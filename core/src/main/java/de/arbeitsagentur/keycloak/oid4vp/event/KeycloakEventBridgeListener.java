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

import de.arbeitsagentur.keycloak.oid4vp.event.PresentationRefusedEvent.Refusal;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Bridges the events to Keycloak's event system. Every standard EventListenerProvider receives them,
 * and the event store keeps the types enabled in the realm's event configuration.
 *
 * <p>Uses identity provider event types, because the login flow reports the failed login as
 * {@code LOGIN_ERROR} itself.
 */
class KeycloakEventBridgeListener implements Oid4vpEventListener {

    private static final String ERROR_PREFIX = "oid4vp_";

    private final Consumer<KeycloakEvent> eventSender;

    KeycloakEventBridgeListener(KeycloakSession session) {
        this(event -> send(session, event));
    }

    KeycloakEventBridgeListener(Consumer<KeycloakEvent> eventSender) {
        this.eventSender = eventSender;
    }

    @Override
    public void onEvent(Oid4vpEvent event) {
        if (event.realmId() == null) {
            return;
        }
        eventSender.accept(new KeycloakEvent(
                event.realmId(), event.userId(), event.clientId(), typeOf(event), errorOf(event), detailsOf(event)));
    }

    private static EventType typeOf(Oid4vpEvent event) {
        return switch (event) {
            case PresentationVerifiedEvent e -> EventType.IDENTITY_PROVIDER_RESPONSE;
            case PresentationRefusedEvent e
            when e.refusal() != Refusal.CREDENTIAL_IGNORED -> EventType.IDENTITY_PROVIDER_LOGIN_ERROR;
            default -> EventType.IDENTITY_PROVIDER_RESPONSE_ERROR;
        };
    }

    private static String errorOf(Oid4vpEvent event) {
        return event instanceof PresentationVerifiedEvent
                ? null
                : ERROR_PREFIX + event.eventType().toLowerCase(Locale.ROOT);
    }

    private static Map<String, String> detailsOf(Oid4vpEvent event) {
        Map<String, String> details = new LinkedHashMap<>(event.details());
        details.put(Oid4vpEventDetails.EVENT_TYPE, event.eventType());
        return details;
    }

    private static void send(KeycloakSession session, KeycloakEvent event) {
        RealmModel realm = session.realms().getRealm(event.realmId());
        if (realm == null) {
            return;
        }
        EventBuilder builder =
                new EventBuilder(realm, session, session.getContext().getConnection());
        builder.event(event.type());
        event.details().forEach(builder::detail);
        if (event.clientId() != null) {
            builder.client(event.clientId());
        }
        if (event.userId() != null) {
            builder.user(event.userId());
        }
        if (event.error() != null) {
            builder.error(event.error());
        } else {
            builder.success();
        }
    }

    record KeycloakEvent(
            String realmId,
            String userId,
            String clientId,
            EventType type,
            String error,
            Map<String, String> details) {}
}
