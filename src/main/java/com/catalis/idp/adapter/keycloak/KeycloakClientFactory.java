package com.catalis.idp.adapter.keycloak;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.stereotype.Component;

/**
 * Factory bean to centralize creation of Keycloak admin client instances.
 * This avoids duplicating builder configuration across service methods.
 */
@Component
public class KeycloakClientFactory {

    // Minimal configuration based on earlier requirements
    private static final String SERVER_URL = "http://localhost:8080/";
    private static final String REALM = "testrealm";
    private static final String CLIENT_ID = "myapp-client";

    /**
     * Creates a base Keycloak client with serverUrl/realm/clientId.
     */
    public Keycloak baseClient() {
        return KeycloakBuilder.builder()
                .serverUrl(SERVER_URL)
                .realm(REALM)
                .clientId(CLIENT_ID)
                .build();
    }

    /**
     * Creates a Keycloak client configured for the Resource Owner Password Credentials (password) flow.
     */
    public Keycloak passwordClient(String username, String password) {
        return KeycloakBuilder.builder()
                .serverUrl(SERVER_URL)
                .realm(REALM)
                .clientId(CLIENT_ID)
                .grantType(OAuth2Constants.PASSWORD)
                .username(username)
                .password(password)
                .build();
    }

    public Keycloak refreshToken() {
        return KeycloakBuilder.builder()
                .serverUrl(SERVER_URL)
                .realm(REALM)
                .clientId(CLIENT_ID)
                .grantType(OAuth2Constants.REFRESH_TOKEN)
                .build();
    }

    public String getRealm() {
        return REALM;
    }
}
