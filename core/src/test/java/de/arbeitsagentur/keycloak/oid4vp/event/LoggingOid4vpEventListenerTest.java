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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class LoggingOid4vpEventListenerTest {

    private static PresentationFailedEvent failure(PresentationFailedEvent.Origin origin, String reason) {
        return new PresentationFailedEvent(
                "realm", "idp", "client", "state", "flow", origin, "error", reason, Instant.EPOCH);
    }

    private static ILoggingEvent logged(Oid4vpEvent event) {
        Logger logger = (Logger) LoggerFactory.getLogger(LoggingOid4vpEventListener.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            new LoggingOid4vpEventListener().onEvent(event);
        } finally {
            logger.detachAppender(appender);
        }
        assertThat(appender.list).hasSize(1);
        return appender.list.get(0);
    }

    @Test
    void walletErrorIsRoutine() {
        assertThat(logged(failure(PresentationFailedEvent.Origin.WALLET, "declined"))
                        .getLevel())
                .isEqualTo(Level.INFO);
    }

    @Test
    void verifierFailureIsAWarning() {
        assertThat(logged(failure(PresentationFailedEvent.Origin.VERIFIER, "invalid"))
                        .getLevel())
                .isEqualTo(Level.WARN);
    }

    @Test
    void textOfAWalletCannotPassAsAnotherField() {
        assertThat(logged(failure(PresentationFailedEvent.Origin.WALLET, "x\", oid4vp_state=\"forged"))
                        .getFormattedMessage())
                .contains("oid4vp_reason=\"x', oid4vp_state='forged\"");
    }
}
