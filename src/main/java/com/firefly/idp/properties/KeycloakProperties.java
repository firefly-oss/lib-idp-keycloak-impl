package com.firefly.idp.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "keycloak")
public record KeycloakProperties(
        @NotBlank String serverUrl,
        @NotBlank String realm,
        @NotBlank String clientId,
        String clientSecret,
        @NotNull @Positive Integer connectionPoolSize,
        @NotNull @Positive Integer connectionTimeout,
        @NotNull @Positive Integer requestTimeout
) {

    public KeycloakProperties {
        // Normalize server URL
        if (serverUrl != null && !serverUrl.endsWith("/")) {
            serverUrl = serverUrl + "/";
        }

        // Default values
        if (connectionPoolSize == null) connectionPoolSize = 10;
        if (connectionTimeout == null) connectionTimeout = 30000;
        if (requestTimeout == null) requestTimeout = 60000;
    }
}
