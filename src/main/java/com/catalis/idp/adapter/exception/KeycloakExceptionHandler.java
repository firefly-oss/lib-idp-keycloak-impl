package com.catalis.idp.adapter.exception;

import jakarta.ws.rs.WebApplicationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * Utility class for handling Keycloak exceptions in a consistent way.
 */
@Slf4j
public final class KeycloakExceptionHandler {

    private KeycloakExceptionHandler() {
        // Utility class
    }

    /**
     * Maps Keycloak exceptions to appropriate HTTP responses.
     */
    public static <T> ResponseEntity<T> handleException(Throwable throwable) {
        if (throwable instanceof WebApplicationException wae) {
            return handleWebApplicationException(wae);
        }

        log.error("Unexpected error in Keycloak operation", throwable);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }

    private static <T> ResponseEntity<T> handleWebApplicationException(WebApplicationException wae) {
        int status = wae.getResponse().getStatus();

        return switch (status) {
            case 401 -> {
                log.warn("Unauthorized Keycloak request: {}", wae.getMessage());
                yield ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
            case 403 -> {
                log.warn("Forbidden Keycloak request: {}", wae.getMessage());
                yield ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
            case 404 -> {
                log.warn("Keycloak resource not found: {}", wae.getMessage());
                yield ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }
            case 409 -> {
                log.warn("Keycloak resource conflict: {}", wae.getMessage());
                yield ResponseEntity.status(HttpStatus.CONFLICT).build();
            }
            default -> {
                log.error("Keycloak error with status {}: {}", status, wae.getMessage(), wae);
                yield ResponseEntity.status(HttpStatus.valueOf(status)).build();
            }
        };
    }
}