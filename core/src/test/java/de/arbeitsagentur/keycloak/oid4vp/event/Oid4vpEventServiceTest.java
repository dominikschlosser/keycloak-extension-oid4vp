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
import static org.assertj.core.api.Assertions.assertThatCode;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class Oid4vpEventServiceTest {

    private static final RevocationDetectedEvent EVENT = new RevocationDetectedEvent(
            "realm",
            null,
            RevocationMechanism.STATUS_LIST,
            "https://status.example/1 status 1",
            "state",
            Instant.EPOCH);

    @Test
    void callsTheGenericHandlerBeforeTheSpecificOne() {
        List<String> calls = new ArrayList<>();
        Oid4vpEventListener listener = new Oid4vpEventListener() {
            @Override
            public void onEvent(Oid4vpEvent event) {
                calls.add("generic");
            }

            @Override
            public void onRevocationDetected(RevocationDetectedEvent event) {
                calls.add("specific");
            }
        };

        Oid4vpEventService.dispatch(List.of(listener), EVENT);

        assertThat(calls).containsExactly("generic", "specific");
    }

    @Test
    void failingListenerDoesNotStopTheOthers() {
        List<Oid4vpEvent> received = new ArrayList<>();
        Oid4vpEventListener failing = new Oid4vpEventListener() {
            @Override
            public void onEvent(Oid4vpEvent event) {
                throw new IllegalStateException("listener failed");
            }
        };
        Oid4vpEventListener recording = new Oid4vpEventListener() {
            @Override
            public void onEvent(Oid4vpEvent event) {
                received.add(event);
            }
        };

        assertThatCode(() -> Oid4vpEventService.dispatch(List.of(failing, recording), EVENT))
                .doesNotThrowAnyException();

        assertThat(received).containsExactly(EVENT);
    }

    @Test
    void listenerThatFailsToLinkDoesNotEscape() {
        Oid4vpEventListener failing = new Oid4vpEventListener() {
            @Override
            public void onEvent(Oid4vpEvent event) {
                throw new NoClassDefFoundError("missing dependency");
            }
        };

        assertThatCode(() -> Oid4vpEventService.dispatch(List.of(failing), EVENT))
                .doesNotThrowAnyException();
    }

    @Test
    void everyEventReachesItsHandlerAndNamesItsType() {
        List<Oid4vpEvent> events = Oid4vpEventsFixture.ALL;
        List<Oid4vpEvent> received = new ArrayList<>();
        Oid4vpEventListener listener = new Oid4vpEventsFixture.RecordingListener(received);

        events.forEach(event -> Oid4vpEventService.dispatch(List.of(listener), event));

        assertThat(received).containsExactlyElementsOf(events);
        assertThat(events)
                .extracting(Oid4vpEvent::eventType)
                .doesNotContainNull()
                .doesNotHaveDuplicates();
        assertThat(events).extracting(Oid4vpEvent::details).doesNotContainNull();
    }

    @Test
    void firingWithoutASessionDoesNothing() {
        assertThatCode(() -> Oid4vpEventService.fire(null, EVENT)).doesNotThrowAnyException();
        assertThat(Oid4vpEventService.realmId(null)).isNull();
        assertThat(Oid4vpEventService.state(null)).isNull();
    }
}
