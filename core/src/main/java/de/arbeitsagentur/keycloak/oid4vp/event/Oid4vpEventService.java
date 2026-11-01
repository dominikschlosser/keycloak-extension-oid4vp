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

import java.util.Collection;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Dispatches events to every {@link Oid4vpEventListener}. A failing listener affects neither the
 * other listeners nor the login that fired the event.
 */
public final class Oid4vpEventService {

    private static final Logger LOG = Logger.getLogger(Oid4vpEventService.class);
    private static final String STATE_ATTRIBUTE = "oid4vp.event.state";

    private Oid4vpEventService() {}

    public static void fire(KeycloakSession session, Oid4vpEvent event) {
        if (session == null) {
            return;
        }
        for (String id : session.listProviderIds(Oid4vpEventListener.class)) {
            try {
                dispatch(List.of(session.getProvider(Oid4vpEventListener.class, id)), event);
            } catch (RuntimeException | LinkageError e) {
                LOG.warnf(e, "Event listener %s could not be created for %s", id, event.eventType());
            }
        }
    }

    // Fires the event once per session and key, for a check that runs several times per request.
    public static void fireOnce(KeycloakSession session, String key, Oid4vpEvent event) {
        if (session == null || session.getAttribute(key) != null) {
            return;
        }
        session.setAttribute(key, Boolean.TRUE);
        fire(session, event);
    }

    static void dispatch(Collection<Oid4vpEventListener> listeners, Oid4vpEvent event) {
        for (Oid4vpEventListener listener : listeners) {
            try {
                listener.onEvent(event);
                dispatchToSpecificHandler(listener, event);
            } catch (RuntimeException | LinkageError e) {
                LOG.warnf(
                        e, "Event listener %s failed on %s", listener.getClass().getName(), event.eventType());
            }
        }
    }

    // Marks the session as answering this login, so that the events it fires can name the state.
    public static void bindState(KeycloakSession session, String state) {
        session.setAttribute(STATE_ATTRIBUTE, state);
    }

    public static String state(KeycloakSession session) {
        return session != null ? session.getAttribute(STATE_ATTRIBUTE, String.class) : null;
    }

    public static String realmId(KeycloakSession session) {
        RealmModel realm = session != null ? session.getContext().getRealm() : null;
        return realm != null ? realm.getId() : null;
    }

    private static void dispatchToSpecificHandler(Oid4vpEventListener listener, Oid4vpEvent event) {
        switch (event) {
            case PresentationVerifiedEvent e -> listener.onPresentationVerified(e);
            case PresentationFailedEvent e -> listener.onPresentationFailed(e);
            case PresentationRefusedEvent e -> listener.onPresentationRefused(e);
            case CompletionRejectedEvent e -> listener.onCompletionRejected(e);
            case RevocationDetectedEvent e -> listener.onRevocationDetected(e);
            case RevocationCheckFailedEvent e -> listener.onRevocationCheckFailed(e);
            case TrustMaterialFailedEvent e -> listener.onTrustMaterialFailed(e);
        }
    }
}
