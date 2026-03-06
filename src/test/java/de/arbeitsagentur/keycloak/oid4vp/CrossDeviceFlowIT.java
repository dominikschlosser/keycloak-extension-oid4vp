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

import com.microsoft.playwright.Page;
import io.github.dominikschlosser.oid4vc.PresentationResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * E2E tests for the cross-device OID4VP login flow (QR code + SSE polling).
 */
class CrossDeviceFlowIT extends AbstractOid4vpE2eIT {

    @BeforeEach
    void enableCrossDevice() throws Exception {
        Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, REALM, true);
    }

    @AfterEach
    void disableCrossDevice() throws Exception {
        Oid4vpTestKeycloakSetup.configureCrossDeviceFlow(adminClient, REALM, false);
    }

    @Test
    void crossDeviceFirstLogin() throws Exception {
        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        flow.waitForSseConnection();

        PresentationResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri())
                .as("Cross-device direct_post response must not contain redirect_uri")
                .isNull();

        waitForCrossDeviceNavigation();
        flow.completeFirstBrokerLoginIfNeeded("cross-device-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void crossDeviceSecondLogin() throws Exception {
        // First login to create user
        deleteAllOid4vpUsers();
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getCrossDeviceWalletUrl();
        flow.waitForSseConnection();
        PresentationResponse firstResponse = flow.submitToWallet(walletUrl);
        waitForCrossDeviceNavigation();
        flow.completeFirstBrokerLoginIfNeeded("cross-device-returning");
        flow.assertLoginSucceeded();

        // Second login with existing user
        tearDownBrowser();
        setUpBrowser();
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        walletUrl = flow.getCrossDeviceWalletUrl();
        flow.waitForSseConnection();

        PresentationResponse walletResponse = flow.submitToWallet(walletUrl);
        assertThat(walletResponse.redirectUri()).isNull();

        try {
            page.waitForURL(
                    url -> url.contains("code=") || flow.isCallbackUrl(url),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            throw new AssertionError(
                    "Cross-device second login: SSE did not navigate to callback. URL: " + page.url(), e);
        }
        flow.assertLoginSucceeded();
    }

    @Test
    void crossDeviceMdocPresentation() throws Exception {
        deleteAllOid4vpUsers();

        String mdocDcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "mso_mdoc",
                      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                      "claims": [
                        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
                      ]
                    }
                  ]
                }
                """;
        Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, REALM, mdocDcqlQuery);

        try {
            flow.navigateToLoginPage();
            flow.clickOid4vpIdpButton();
            String walletUrl = flow.getCrossDeviceWalletUrl();
            flow.waitForSseConnection();

            PresentationResponse walletResponse = flow.submitToWallet(walletUrl);
            assertThat(walletResponse.redirectUri()).isNull();

            waitForCrossDeviceNavigation();
            flow.completeFirstBrokerLoginIfNeeded("cross-device-mdoc-user");
            flow.assertLoginSucceeded();
        } finally {
            Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, REALM, buildDefaultDcqlQuery());
        }
    }
}
