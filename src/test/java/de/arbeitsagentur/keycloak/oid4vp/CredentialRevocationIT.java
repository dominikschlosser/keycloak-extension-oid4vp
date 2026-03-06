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
package de.arbeitsagentur.keycloak.oid4vp;

import static de.arbeitsagentur.keycloak.oid4vp.Oid4vpE2eInfrastructure.*;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.dominikschlosser.oid4vc.CredentialFormat;
import io.github.dominikschlosser.oid4vc.PresentationResponse;
import org.junit.jupiter.api.Test;

/**
 * E2E tests for credential revocation (status list) verification.
 *
 * <p>These tests depend on the wallet container's status list endpoint being "warm" — the
 * asynchronous status list JWT regeneration needs at least one full cycle before revocation
 * updates are reflected reliably. This is why the failsafe plugin is configured with
 * {@code reversealphabetical} run order, ensuring this class runs after the other IT classes.
 */
class CredentialRevocationIT extends AbstractOid4vpE2eIT {

    @Test
    void revokedSdJwtCredentialIsRejected() throws Exception {
        assertRevokedCredentialIsRejected("SD-JWT", null);
    }

    @Test
    void revokedMdocCredentialIsRejected() throws Exception {
        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] }
                      ]
                    }
                  ]
                }
                """;
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, REALM, mdocDcqlQuery);
        wallet.client().setPreferredFormat(CredentialFormat.MSO_MDOC);
        try {
            assertRevokedCredentialIsRejected("mDoc", "eu.europa.ec.eudi.pid.1");
        } finally {
            wallet.client().clearPreferredFormat();
            Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, REALM, buildDefaultDcqlQuery());
        }
    }

    private void assertRevokedCredentialIsRejected(String formatLabel, String credentialType) throws Exception {
        deleteAllOid4vpUsers();

        String credentialId;
        if (credentialType != null) {
            var typedCredentials = wallet.client().getCredentialsByType(credentialType);
            assertThat(typedCredentials)
                    .as("Wallet should have a credential of type %s", credentialType)
                    .isNotEmpty();
            credentialId = typedCredentials.get(0).id();
        } else {
            var credentials = wallet.client().getCredentials();
            assertThat(credentials)
                    .as("Wallet should have at least one credential")
                    .isNotEmpty();
            credentialId = credentials.get(0).id();
        }
        wallet.client().revokeCredential(credentialId);

        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getSameDeviceWalletUrl();
            PresentationResponse walletResponse = flow.submitToWallet(walletUrl);

            String redirectUri = walletResponse.redirectUri();
            if (redirectUri != null) {
                page.navigate(redirectUri);
                page.waitForLoadState();
            }

            Thread.sleep(2000);
            String bodyText = page.locator("body").textContent().toLowerCase();
            boolean hasError = bodyText.contains("error")
                    || bodyText.contains("revoked")
                    || bodyText.contains("failed")
                    || bodyText.contains("denied");

            assertThat(hasError)
                    .as(
                            "Revoked %s credential should be rejected. URL: %s, Body: %s",
                            formatLabel, page.url(), bodyText.substring(0, Math.min(500, bodyText.length())))
                    .isTrue();
        } finally {
            wallet.client().unrevokeCredential(credentialId);
        }
    }
}
