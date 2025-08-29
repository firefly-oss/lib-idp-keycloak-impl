package com.firefly.idp.adapter.keycloak;

import com.firefly.idp.dtos.LoginRequest;
import com.firefly.idp.properties.KeycloakProperties;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.stereotype.Component;
import org.springframework.http.client.reactive.ClientHttpRequest;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Factory bean to centralize creation of Keycloak admin client instances.
 * This avoids duplicating builder configuration across service methods.
 */
@Component
@Slf4j
public class KeycloakClientFactory {

    private final KeycloakProperties properties;

    public KeycloakClientFactory(KeycloakProperties properties) {
        this.properties = properties;
    }

    /**
     * Creates a base Keycloak client with common configuration.
     */
    private KeycloakBuilder baseBuilder() {
        return KeycloakBuilder.builder()
                .serverUrl(properties.serverUrl())
                .realm(properties.realm())
                .clientId(properties.clientId())
                .clientSecret(properties.clientSecret());
    }

    /**
     * Creates a Keycloak client for Resource Owner Password Credentials flow.
     */
    public Keycloak createPasswordClient(String username, String password) {
        log.debug("Creating Keycloak PASSWORD client - realm={}, clientId={}, username={}", properties.realm(), properties.clientId(), username);
        var builder = baseBuilder()
                .grantType(OAuth2Constants.PASSWORD)
                .username(username)
                .password(password);

        return builder.build();
    }

    /**
     * Creates a Keycloak client for client credentials flow.
     */
    public Keycloak createClientCredentialsClient() {
        log.debug("Creating Keycloak CLIENT_CREDENTIALS client - realm={}, clientId={}", properties.realm(), properties.clientId());
        if (properties.clientSecret() == null) {
            throw new IllegalStateException("Client secret is required for client credentials flow");
        }

        return baseBuilder()
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .clientId(properties.clientId())
                .clientSecret(properties.clientSecret())
                .build();
    }

    public String getRealm() {
        return properties.realm();
    }

}
