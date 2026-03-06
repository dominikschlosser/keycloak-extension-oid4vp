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
package de.arbeitsagentur.keycloak.oid4vp.domain;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import org.keycloak.common.util.PemUtils;
import org.keycloak.utils.StringUtil;

/**
 * OID4VP Client Identifier Scheme determining how the verifier identifies itself to the wallet.
 *
 * <p>Each scheme defines how the {@code client_id} is computed and whether the request object's
 * JWS header must include an {@code x5c} certificate chain for wallet-side verification.
 *
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.2">OID4VP 1.0 §5.2 — Client Identifier Schemes</a>
 * @see <a href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html#section-5.3">HAIP §5.3 — Client Identification</a>
 */
public sealed interface ClientIdScheme {

    /** Returns the scheme identifier as used in the OID4VP protocol (e.g., {@code "x509_san_dns"}). */
    String identifier();

    /**
     * Computes the effective client ID for this scheme.
     *
     * @param baseClientId the realm-based client ID (fallback for pre-registered scheme)
     * @param x509CertPem the X.509 certificate PEM (may be {@code null} or blank)
     * @return the effective client ID for use in the authorization request
     */
    String resolveClientId(String baseClientId, String x509CertPem);

    /** Whether the signed request object must include the X.509 certificate chain in the JWS {@code x5c} header. */
    boolean requiresX5cHeader();

    /**
     * Derives the client ID from the first DNS Subject Alternative Name in the certificate.
     * Format: {@code x509_san_dns:<dns-name>}.
     *
     * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.2.1">OID4VP 1.0 §5.2.1 — x509_san_dns</a>
     */
    record X509SanDns() implements ClientIdScheme {
        @Override
        public String identifier() {
            return Oid4vpConstants.CLIENT_ID_SCHEME_X509_SAN_DNS;
        }

        @Override
        public String resolveClientId(String baseClientId, String x509CertPem) {
            if (StringUtil.isBlank(x509CertPem)) {
                return baseClientId;
            }
            try {
                X509Certificate cert = decodeFirstCertificate(x509CertPem);
                Collection<List<?>> sans = cert.getSubjectAlternativeNames();
                if (sans != null) {
                    for (List<?> san : sans) {
                        if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0))) {
                            return Oid4vpConstants.CLIENT_ID_SCHEME_X509_SAN_DNS + ":" + san.get(1);
                        }
                    }
                }
                throw new IllegalStateException("No DNS SAN found in certificate");
            } catch (IllegalStateException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException("Failed to extract DNS SAN from certificate", e);
            }
        }

        @Override
        public boolean requiresX5cHeader() {
            return true;
        }
    }

    /**
     * Derives the client ID from the SHA-256 hash of the certificate's DER encoding.
     * Format: {@code x509_hash:<base64url-sha256>}.
     *
     * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.2.2">OID4VP 1.0 §5.2.2 — x509_hash</a>
     */
    record X509Hash() implements ClientIdScheme {
        @Override
        public String identifier() {
            return Oid4vpConstants.CLIENT_ID_SCHEME_X509_HASH;
        }

        @Override
        public String resolveClientId(String baseClientId, String x509CertPem) {
            if (StringUtil.isBlank(x509CertPem)) {
                return baseClientId;
            }
            try {
                X509Certificate cert = decodeFirstCertificate(x509CertPem);
                byte[] encoded = cert.getEncoded();
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(encoded);
                String hashBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
                return Oid4vpConstants.CLIENT_ID_SCHEME_X509_HASH + ":" + hashBase64;
            } catch (Exception e) {
                throw new IllegalStateException("Failed to compute certificate hash", e);
            }
        }

        @Override
        public boolean requiresX5cHeader() {
            return true;
        }
    }

    /**
     * Pre-registered client ID scheme where the client ID is the realm base URL.
     * No certificate-based identification.
     */
    record PreRegistered() implements ClientIdScheme {
        @Override
        public String identifier() {
            return Oid4vpConstants.CLIENT_ID_SCHEME_PLAIN;
        }

        @Override
        public String resolveClientId(String baseClientId, String x509CertPem) {
            return baseClientId;
        }

        @Override
        public boolean requiresX5cHeader() {
            return false;
        }
    }

    /**
     * Resolves a {@link ClientIdScheme} from its protocol identifier string.
     *
     * @param identifier the scheme identifier (e.g., {@code "x509_san_dns"}, {@code "x509_hash"}, {@code "plain"})
     * @return the corresponding {@link ClientIdScheme} implementation
     */
    static ClientIdScheme of(String identifier) {
        if (identifier == null) {
            return new X509SanDns();
        }
        return switch (identifier) {
            case Oid4vpConstants.CLIENT_ID_SCHEME_X509_SAN_DNS -> new X509SanDns();
            case Oid4vpConstants.CLIENT_ID_SCHEME_X509_HASH -> new X509Hash();
            default -> new PreRegistered();
        };
    }

    private static X509Certificate decodeFirstCertificate(String pem) {
        X509Certificate[] certs = PemUtils.decodeCertificates(pem);
        if (certs == null || certs.length == 0) {
            throw new IllegalStateException("No certificates found in PEM");
        }
        return certs[0];
    }
}
