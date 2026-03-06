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

import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Page;
import io.github.dominikschlosser.oid4vc.PresentationResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for OID4VP E2E integration tests.
 *
 * <p>Manages the shared infrastructure lifecycle (containers, browser) and provides per-test
 * isolation via a fresh {@link BrowserContext} and {@link Page}. Each test class gets its own
 * browser context (isolated cookies/storage), while the expensive Keycloak and wallet containers
 * are shared across all test classes.
 *
 * <p>When this extension is upstreamed into Keycloak, this base class would be replaced by
 * {@code @KeycloakIntegrationTest} with custom suppliers for the wallet container and Playwright
 * browser, using the Keycloak test framework's dependency injection.
 */
abstract class AbstractOid4vpE2eIT {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    @RegisterExtension
    IdpConfigScope idpConfig = new IdpConfigScope(() -> adminClient, REALM);

    protected BrowserContext context;
    protected Page page;
    protected Oid4vpLoginFlowHelper flow;

    @BeforeAll
    static void startInfrastructure() {
        ensureStarted();
    }

    @BeforeEach
    void setUpBrowser() {
        callback.reset();
        context = browser.newContext();
        context.addInitScript("""
                const OrigES = window.EventSource;
                window.EventSource = function(url) {
                    const es = new OrigES(url);
                    es.addEventListener('ping', () => { window.__oid4vpSseReady = true; });
                    return es;
                };
                window.EventSource.prototype = OrigES.prototype;
                window.__oid4vpSseReady = false;
                """);
        page = context.newPage();
        flow = new Oid4vpLoginFlowHelper(page, context, wallet, kcHostUrl, callback.localCallbackUrl(), REALM);
    }

    @AfterEach
    void tearDownBrowser() {
        if (page != null) page.close();
        if (context != null) context.close();
    }

    /** Performs a full same-device login flow: navigate → click IdP → get wallet URL → submit → complete. */
    protected void performSameDeviceLogin(String usernamePrefix) throws Exception {
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        PresentationResponse response = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(response);
        flow.completeFirstBrokerLoginIfNeeded(usernamePrefix);
    }

    /** Waits for SSE-driven cross-device navigation to complete-auth or first-broker-login. */
    protected void waitForCrossDeviceNavigation() {
        try {
            page.waitForURL(
                    url -> url.contains("/complete-auth")
                            || url.contains("/first-broker-login")
                            || url.contains("/login-actions/")
                            || page.locator("input[name='username']").count() > 0
                            || flow.isCallbackUrl(url),
                    new Page.WaitForURLOptions().setTimeout(30000));
        } catch (Exception e) {
            throw new AssertionError("Cross-device: SSE did not navigate browser. URL: " + page.url(), e);
        }
        page.waitForLoadState();
    }

    /** Deletes all OID4VP-federated users from the test realm. */
    protected void deleteAllOid4vpUsers() throws Exception {
        Oid4vpTestKeycloakSetup.deleteAllOid4vpUsers(adminClient, REALM);
    }
}
