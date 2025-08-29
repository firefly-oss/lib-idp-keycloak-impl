package com.firefly.idp;

import com.firefly.idp.properties.KeycloakProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(KeycloakProperties.class)
@Slf4j
public class LibIdpKeycloakImplApplication {

    public static void main(String[] args) {
        log.info("Starting lib-idp-keycloak-impl application");
        SpringApplication.run(LibIdpKeycloakImplApplication.class, args);
    }
}
