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

import io.github.dominikschlosser.oid4vc.Oid4vcContainer;
import io.github.dominikschlosser.oid4vc.PresentationResponse;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

/**
 * E2E tests for request object handling: multi-fetch, encryption, certificate chains,
 * and the request_uri endpoint (analogous to PAR's request_uri resolution).
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101 — JWT-Secured Authorization Request (JAR)</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126 — Pushed Authorization Request (PAR)</a>
 */
class RequestObjectIT extends AbstractOid4vpE2eIT {

    @Test
    void requestObjectCanBeFetchedMultipleTimes() throws Exception {
        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);

        HttpClient httpClient = HttpClient.newHttpClient();

        HttpResponse<String> response1 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        HttpResponse<String> response2 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        HttpResponse<String> response3 = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response1.statusCode()).as("First fetch should succeed").isEqualTo(200);
        assertThat(response2.statusCode()).as("Second fetch should succeed").isEqualTo(200);
        assertThat(response3.statusCode()).as("Third fetch should succeed").isEqualTo(200);

        String kid1 = Oid4vpLoginFlowHelper.extractEncryptionKid(response1.body());
        String kid2 = Oid4vpLoginFlowHelper.extractEncryptionKid(response2.body());
        String kid3 = Oid4vpLoginFlowHelper.extractEncryptionKid(response3.body());

        assertThat(kid1)
                .as("First request object should contain an encryption key")
                .isNotNull();
        assertThat(kid2).isNotNull();
        assertThat(kid3).isNotNull();
        assertThat(kid1)
                .as("Each fetch should generate a different encryption key")
                .isNotEqualTo(kid2);
        assertThat(kid2).isNotEqualTo(kid3);
    }

    @Test
    void loginSucceedsAfterMultipleRequestObjectFetches() throws Exception {
        deleteAllOid4vpUsers();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);

        // Pre-fetch the request object twice (simulating non-wallet fetches)
        HttpClient httpClient = HttpClient.newHttpClient();
        httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        PresentationResponse response = flow.submitToWallet(walletUrl);
        flow.waitForLoginCompletion(response);
        flow.completeFirstBrokerLoginIfNeeded("multi-fetch-user");
        flow.assertLoginSucceeded();
    }

    @Test
    void loginWithX509CertChainPem() throws Exception {
        KeyPair caKeyPair = generateEcKeyPair();
        KeyPair leafKeyPair = generateEcKeyPair();
        X509Certificate caCert = generateCaCert(caKeyPair);
        X509Certificate leafCert = generateLeafCertWithSan(leafKeyPair, caKeyPair, "test.example.com");

        String combinedPem = toPem("CERTIFICATE", leafCert.getEncoded())
                + "\n"
                + toPem("CERTIFICATE", caCert.getEncoded())
                + "\n"
                + toPem("PRIVATE KEY", leafKeyPair.getPrivate().getEncoded());

        idpConfig
                .set(Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM, combinedPem)
                .set(Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, "x509_san_dns")
                .set(Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false")
                .set(Oid4vpIdentityProviderConfig.X509_SIGNING_KEY_JWK, "")
                .apply();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        assertThat(walletUrl).contains("request_uri=");

        String requestUri = Oid4vpLoginFlowHelper.extractRequestUri(walletUrl);
        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder().uri(URI.create(requestUri)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);

        com.nimbusds.jwt.SignedJWT requestJwt = com.nimbusds.jwt.SignedJWT.parse(response.body());
        assertThat(requestJwt.getHeader().getAlgorithm().getName())
                .as("Request object must be signed with ES256 from the x509 key")
                .isEqualTo("ES256");
        assertThat(requestJwt.getHeader().getX509CertChain())
                .as("Request object must include x5c certificate chain")
                .hasSize(2);
    }

    @Test
    void loginWithCertOnlyPemAndRealmKey() throws Exception {
        KeyPair leafKeyPair = generateEcKeyPair();
        X509Certificate leafCert = generateLeafCertWithSan(leafKeyPair, leafKeyPair, "test.example.com");
        String certOnlyPem = toPem("CERTIFICATE", leafCert.getEncoded());

        idpConfig
                .set(Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM, certOnlyPem)
                .set(Oid4vpIdentityProviderConfig.CLIENT_ID_SCHEME, "x509_san_dns")
                .set(Oid4vpIdentityProviderConfig.ENFORCE_HAIP, "false")
                .set(Oid4vpIdentityProviderConfig.X509_SIGNING_KEY_JWK, "")
                .apply();

        flow.navigateToLoginPage();
        flow.clickOid4vpIdpButton();
        String walletUrl = flow.getSameDeviceWalletUrl();
        assertThat(walletUrl).contains("request_uri=");
    }

    @Test
    void loginWithEncryptedRequestObject() throws Exception {
        deleteAllOid4vpUsers();

        Oid4vcContainer encWallet = new Oid4vcContainer()
                .withHostAccess()
                .withNetwork(network)
                .withNetworkAliases("oid4vc-enc")
                .withRequireEncryptedRequest()
                .withStatusList()
                .withStatusListBaseUrl("http://oid4vc-enc:8085")
                .withLogConsumer(frame ->
                        log.info("[OID4VC-ENC] {}", frame.getUtf8String().stripTrailing()));
        encWallet.start();

        String encTrustListUrl = "http://oid4vc-enc:8085/api/trustlist";
        Oid4vpTestKeycloakSetup.setIdpConfig(
                adminClient, REALM, Oid4vpIdentityProviderConfig.TRUST_LIST_URL, encTrustListUrl);

        try {
            Oid4vpLoginFlowHelper encFlow =
                    new Oid4vpLoginFlowHelper(page, context, encWallet, kcHostUrl, callback.localCallbackUrl(), REALM);
            encFlow.navigateToLoginPage();
            encFlow.clickOid4vpIdpButton();
            String walletUrl = encFlow.getSameDeviceWalletUrl();
            PresentationResponse response = encFlow.submitToWallet(walletUrl);
            encFlow.waitForLoginCompletion(response);
            encFlow.completeFirstBrokerLoginIfNeeded("enc-request-user");
            encFlow.assertLoginSucceeded();
        } finally {
            Oid4vpTestKeycloakSetup.setIdpConfig(
                    adminClient,
                    REALM,
                    Oid4vpIdentityProviderConfig.TRUST_LIST_URL,
                    "http://oid4vc-dev:8085/api/trustlist");
            encWallet.stop();
        }
    }

    @Test
    void mdocWithIsoSessionTranscript() throws Exception {
        deleteAllOid4vpUsers();

        Oid4vcContainer isoWallet = new Oid4vcContainer()
                .withHostAccess()
                .withNetwork(network)
                .withNetworkAliases("oid4vc-iso")
                .withSessionTranscript("iso")
                .withStatusList()
                .withStatusListBaseUrl("http://oid4vc-iso:8085")
                .withLogConsumer(frame ->
                        log.info("[OID4VC-ISO] {}", frame.getUtf8String().stripTrailing()));
        isoWallet.start();

        String isoTrustListUrl = "http://oid4vc-iso:8085/api/trustlist";
        Oid4vpTestKeycloakSetup.setIdpConfig(
                adminClient, REALM, Oid4vpIdentityProviderConfig.TRUST_LIST_URL, isoTrustListUrl);

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
            Oid4vpLoginFlowHelper isoFlow =
                    new Oid4vpLoginFlowHelper(page, context, isoWallet, kcHostUrl, callback.localCallbackUrl(), REALM);
            isoFlow.navigateToLoginPage();
            isoFlow.clickOid4vpIdpButton();
            String walletUrl = isoFlow.getSameDeviceWalletUrl();
            PresentationResponse response = isoFlow.submitToWallet(walletUrl);
            isoFlow.waitForLoginCompletion(response);
            isoFlow.completeFirstBrokerLoginIfNeeded("iso-transcript-user");
            isoFlow.assertLoginSucceeded();
        } finally {
            Oid4vpTestKeycloakSetup.setIdpConfig(
                    adminClient,
                    REALM,
                    Oid4vpIdentityProviderConfig.TRUST_LIST_URL,
                    "http://oid4vc-dev:8085/api/trustlist");
            Oid4vpTestKeycloakSetup.configureDcqlQuery(adminClient, REALM, buildDefaultDcqlQuery());
            isoWallet.stop();
        }
    }
}
