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

import de.arbeitsagentur.keycloak.oid4vp.domain.Oid4vpConstants;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

final class Oid4vpTestKeycloakSetup {

    static final String DEFAULT_DCQL_QUERY = """
            {
              "credentials": [
                {
                  "id": "pid_sd_jwt",
                  "format": "dc+sd-jwt",
                  "meta": { "vct_values": ["urn:eudi:pid:1"] },
                  "claims": [
                    { "path": ["family_name"] },
                    { "path": ["given_name"] },
                    { "path": ["birthdate"] }
                  ]
                },
                {
                  "id": "pid_mdoc",
                  "format": "mso_mdoc",
                  "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
                  "claims": [
                    { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
                    { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] },
                    { "path": ["eu.europa.ec.eudi.pid.1", "birth_date"] }
                  ]
                }
              ],
              "credential_sets": [
                {
                  "options": [["pid_sd_jwt"], ["pid_mdoc"]],
                  "required": true
                }
              ]
            }
            """;

    static void addRedirectUriToClient(Keycloak admin, String realm, String clientId, String redirectUri) {
        RealmResource realmResource = admin.realm(realm);
        List<ClientRepresentation> clients = realmResource.clients().findByClientId(clientId);
        if (clients.isEmpty()) {
            throw new IllegalStateException("Client not found: " + clientId);
        }

        ClientRepresentation client =
                realmResource.clients().get(clients.get(0).getId()).toRepresentation();
        List<String> redirectUris =
                client.getRedirectUris() != null ? new ArrayList<>(client.getRedirectUris()) : new ArrayList<>();
        if (!redirectUris.contains(redirectUri)) {
            redirectUris.add(redirectUri);
        }
        client.setRedirectUris(redirectUris);
        realmResource.clients().get(client.getId()).update(client);
    }

    static void configureOid4vpIdentityProvider(Keycloak admin, String realm, String trustListUrl, String x509CertPem) {
        RealmResource realmResource = admin.realm(realm);

        // Remove existing IdP if present
        try {
            realmResource.identityProviders().get("oid4vp").remove();
        } catch (jakarta.ws.rs.NotFoundException ignored) {
        }

        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
        idp.setAlias("oid4vp");
        idp.setDisplayName("Sign in with Wallet");
        idp.setProviderId(Oid4vpConstants.PROVIDER_ID);
        idp.setEnabled(true);
        idp.setTrustEmail(false);
        idp.setStoreToken(false);
        idp.setAddReadTokenRoleOnCreate(false);
        idp.setAuthenticateByDefault(false);
        idp.setLinkOnly(false);
        idp.setFirstBrokerLoginFlowAlias("first broker login");

        Map<String, String> config = new HashMap<>();
        config.put("clientId", "not-used");
        config.put("clientSecret", "not-used");
        config.put(Oid4vpIdentityProviderConfig.DCQL_QUERY, DEFAULT_DCQL_QUERY);
        config.put(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM, "family_name");
        config.put(Oid4vpIdentityProviderConfig.USER_MAPPING_CLAIM_MDOC, "eu.europa.ec.eudi.pid.1/family_name");
        config.put(Oid4vpIdentityProviderConfig.TRUST_LIST_URL, trustListUrl);
        config.put(Oid4vpIdentityProviderConfig.STATUS_LIST_MAX_CACHE_TTL_SECONDS, "0");
        config.put(Oid4vpIdentityProviderConfig.X509_CERTIFICATE_PEM, x509CertPem);
        idp.setConfig(config);

        realmResource.identityProviders().create(idp).close();
    }

    static void configureDcqlQuery(Keycloak admin, String realm, String dcqlQuery) {
        IdentityProviderResource idpResource =
                admin.realm(realm).identityProviders().get("oid4vp");
        IdentityProviderRepresentation rep = idpResource.toRepresentation();
        rep.getConfig().put(Oid4vpIdentityProviderConfig.DCQL_QUERY, dcqlQuery);
        idpResource.update(rep);
    }

    static void configureSameDeviceFlow(Keycloak admin, String realm, boolean enabled) {
        IdentityProviderResource idpResource =
                admin.realm(realm).identityProviders().get("oid4vp");
        IdentityProviderRepresentation rep = idpResource.toRepresentation();
        rep.getConfig().put(Oid4vpIdentityProviderConfig.SAME_DEVICE_ENABLED, String.valueOf(enabled));
        idpResource.update(rep);
    }

    static void configureCrossDeviceFlow(Keycloak admin, String realm, boolean enabled) {
        IdentityProviderResource idpResource =
                admin.realm(realm).identityProviders().get("oid4vp");
        IdentityProviderRepresentation rep = idpResource.toRepresentation();
        rep.getConfig().put(Oid4vpIdentityProviderConfig.CROSS_DEVICE_ENABLED, String.valueOf(enabled));
        idpResource.update(rep);
    }

    static void deleteAllOid4vpUsers(Keycloak admin, String realm) {
        RealmResource realmResource = admin.realm(realm);
        List<UserRepresentation> users = realmResource.users().list(0, 100);
        for (UserRepresentation user : users) {
            String username = user.getUsername();
            if ("admin".equals(username) || "test".equals(username)) continue;
            try {
                List<FederatedIdentityRepresentation> identities =
                        realmResource.users().get(user.getId()).getFederatedIdentity();
                boolean hasOid4vp = identities.stream().anyMatch(id -> "oid4vp".equals(id.getIdentityProvider()));
                if (hasOid4vp) {
                    realmResource.users().get(user.getId()).remove();
                }
            } catch (Exception ignored) {
            }
        }
    }

    static void setIdpConfig(Keycloak admin, String realm, String key, String value) {
        setIdpConfigs(admin, realm, Map.of(key, value));
    }

    static void setIdpConfigs(Keycloak admin, String realm, Map<String, String> entries) {
        IdentityProviderResource idpResource =
                admin.realm(realm).identityProviders().get("oid4vp");
        IdentityProviderRepresentation rep = idpResource.toRepresentation();
        rep.getConfig().putAll(entries);
        idpResource.update(rep);
    }

    private Oid4vpTestKeycloakSetup() {}
}
