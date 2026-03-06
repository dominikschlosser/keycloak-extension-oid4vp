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

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Playwright;
import io.github.dominikschlosser.oid4vc.Oid4vcContainer;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

/**
 * Shared E2E test infrastructure managing expensive resources (containers, browser).
 *
 * <p>Resources are lazily initialized on first use and shared across all E2E test classes.
 * This follows the Keycloak test framework's {@code LifeCycle.GLOBAL} pattern where the server
 * persists across test classes. When this extension is upstreamed, this class would be replaced by
 * a {@code TestFrameworkExtension} with custom {@code Supplier} implementations for the Keycloak
 * container, wallet container, and Playwright browser.
 *
 * <p>A JVM shutdown hook ensures cleanup even if tests are interrupted.
 */
final class Oid4vpE2eInfrastructure {

    private static final Logger LOG = LoggerFactory.getLogger(Oid4vpE2eInfrastructure.class);
    static final String REALM = "wallet-demo";

    static Network network;
    static GenericContainer<?> keycloak;
    static Oid4vcContainer wallet;
    static Oid4vpTestCallbackServer callback;
    static Keycloak adminClient;
    static String kcHostUrl;

    static Playwright playwright;
    static Browser browser;

    private static volatile boolean initialized = false;

    static synchronized void ensureStarted() {
        if (initialized) return;
        try {
            doStart();
            initialized = true;
            Runtime.getRuntime().addShutdownHook(new Thread(Oid4vpE2eInfrastructure::shutdown));
        } catch (Exception e) {
            throw new RuntimeException("Failed to start E2E infrastructure", e);
        }
    }

    private static void doStart() throws Exception {
        callback = new Oid4vpTestCallbackServer();
        network = Network.newNetwork();

        keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:26.5.4")
                .withNetwork(network)
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withEnv("KC_PROXY_HEADERS", "xforwarded")
                .withExposedPorts(8080)
                .withCommand("start-dev", "--import-realm")
                .withLogConsumer(
                        frame -> LOG.info("[KC] {}", frame.getUtf8String().stripTrailing()))
                .waitingFor(Wait.forHttp("/realms/" + REALM).forPort(8080).withStartupTimeout(Duration.ofSeconds(180)));

        copyRealmImport();
        copyProviderJars();
        keycloak.start();

        kcHostUrl = "http://localhost:" + keycloak.getMappedPort(8080);

        wallet = new Oid4vcContainer()
                .withHostAccess()
                .withNetwork(network)
                .withNetworkAliases("oid4vc-dev")
                .withStatusList()
                .withStatusListBaseUrl("http://oid4vc-dev:8085")
                .withLogConsumer(
                        frame -> LOG.info("[OID4VC] {}", frame.getUtf8String().stripTrailing()));
        wallet.start();

        playwright = Playwright.create();
        browser = playwright.chromium().launch(new BrowserType.LaunchOptions().setHeadless(true));

        adminClient = KeycloakBuilder.builder()
                .serverUrl(kcHostUrl)
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build();

        String trustListUrl = "http://oid4vc-dev:8085/api/trustlist";
        KeyPair haipKeyPair = generateEcKeyPair();
        X509Certificate haipCert = generateCaCert(haipKeyPair);
        String haipCertPem = toPem("CERTIFICATE", haipCert.getEncoded())
                + "\n"
                + toPem("PRIVATE KEY", haipKeyPair.getPrivate().getEncoded());
        Oid4vpTestKeycloakSetup.configureOid4vpIdentityProvider(adminClient, REALM, trustListUrl, haipCertPem);
        Oid4vpTestKeycloakSetup.configureSameDeviceFlow(adminClient, REALM, true);
        Oid4vpTestKeycloakSetup.addRedirectUriToClient(adminClient, REALM, "wallet-mock", callback.localCallbackUrl());

        LOG.info("E2E infrastructure started. KC: {}, Wallet: {}", kcHostUrl, wallet.getBaseUrl());
    }

    static synchronized void shutdown() {
        if (!initialized) return;
        if (browser != null) browser.close();
        if (playwright != null) playwright.close();
        if (adminClient != null) adminClient.close();
        if (keycloak != null) keycloak.stop();
        if (wallet != null) wallet.stop();
        if (network != null) network.close();
        if (callback != null) callback.close();
        initialized = false;
    }

    // Certificate utilities shared across test classes

    static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    static X509Certificate generateCaCert(KeyPair caKeyPair) throws Exception {
        X500Principal subject = new X500Principal("CN=Test CA");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(1),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                caKeyPair.getPublic());
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate())));
    }

    static X509Certificate generateLeafCertWithSan(KeyPair leafKeyPair, KeyPair caKeyPair, String dnsName)
            throws Exception {
        X500Principal issuer = new X500Principal("CN=Test CA");
        X500Principal subject = new X500Principal("CN=" + dnsName);
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(2),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                leafKeyPair.getPublic());
        builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate())));
    }

    static String toPem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----";
    }

    static String buildDefaultDcqlQuery() {
        return """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["urn:eudi:pid:de:1"] },
                      "claims": [
                        { "path": ["family_name"] },
                        { "path": ["given_name"] }
                      ]
                    }
                  ]
                }
                """;
    }

    private static void copyRealmImport() {
        Path realmExport = Path.of("src/test/resources/realm-export.json").toAbsolutePath();
        keycloak.withCopyFileToContainer(
                MountableFile.forHostPath(realmExport), "/opt/keycloak/data/import/realm-export.json");
    }

    private static void copyProviderJars() throws IOException {
        Path providerJar = findProviderJar();
        keycloak.withCopyFileToContainer(
                MountableFile.forHostPath(providerJar), "/opt/keycloak/providers/" + providerJar.getFileName());

        Path deps = Path.of("target/providers").toAbsolutePath();
        if (!Files.isDirectory(deps)) return;
        try (Stream<Path> stream = Files.list(deps)) {
            for (Path jar : stream.filter(p -> p.getFileName().toString().endsWith(".jar"))
                    .toList()) {
                keycloak.withCopyFileToContainer(
                        MountableFile.forHostPath(jar), "/opt/keycloak/providers/" + jar.getFileName());
            }
        }
    }

    private static Path findProviderJar() throws IOException {
        Path target = Path.of("target").toAbsolutePath();
        try (Stream<Path> stream = Files.list(target)) {
            return stream.filter(path -> path.getFileName().toString().startsWith("keycloak-extension-oid4vp-"))
                    .filter(path -> path.getFileName().toString().endsWith(".jar"))
                    .filter(path -> !path.getFileName().toString().endsWith("-sources.jar"))
                    .filter(path -> !path.getFileName().toString().endsWith("-javadoc.jar"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Provider jar not found in target/"));
        }
    }

    private Oid4vpE2eInfrastructure() {}
}
