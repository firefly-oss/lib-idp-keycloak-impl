package com.catalis.idp.adapter.service.impl;

import com.catalis.idp.adapter.keycloak.KeycloakClientFactory;
import com.catalis.idp.adapter.service.IdpAdminService;
import com.catalis.idp.dtos.*;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.*;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class IdpAdminServiceImpl implements IdpAdminService {

    private final KeycloakClientFactory keycloakFactory;

    public IdpAdminServiceImpl(KeycloakClientFactory keycloakFactory) {
        this.keycloakFactory = keycloakFactory;
    }

    @Override
    public Mono<ResponseEntity<CreateUserResponse>> createUser(CreateUserRequest request) {
        return Mono.fromCallable(() -> {
            String userId;
            try (Keycloak keycloak = keycloakFactory.baseClient()) {
                UserRepresentation user = new UserRepresentation();
                user.setUsername(request.getUsername());
                user.setEmail(request.getEmail());
                user.setEnabled(true);

                Response response = keycloak.realm(keycloakFactory.getRealm()).users().create(user);

                if (response.getStatus() != 201) {
                    return ResponseEntity
                            .status(response.getStatus())
                            .body(null);
                }

                userId = CreatedResponseUtil.getCreatedId(response);

                CredentialRepresentation credential = new CredentialRepresentation();
                credential.setType(CredentialRepresentation.PASSWORD);
                credential.setValue(request.getPassword());
                credential.setTemporary(false);

                keycloak.realm(keycloakFactory.getRealm())
                        .users()
                        .get(userId)
                        .resetPassword(credential);
            }

            CreateUserResponse created = new CreateUserResponse(
                    userId,
                    request.getUsername(),
                    request.getEmail(),
                    Instant.now()
            );
            return ResponseEntity.ok(created);
        });
    }

    @Override
    public Mono<Void> changePassword(ChangePasswordRequest request) {
        return Mono.fromRunnable(() -> {
            try {
                try (Keycloak keycloak = keycloakFactory.passwordClient(getUsernameById(request.getUserId()), request.getOldPassword())) {
                    AccessTokenResponse tokenResponse = keycloak.tokenManager().getAccessToken();
                    if (tokenResponse == null || tokenResponse.getToken() == null) {
                        throw new IllegalArgumentException("Old password is incorrect");
                    }

                    CredentialRepresentation newCred = new CredentialRepresentation();
                    newCred.setType(CredentialRepresentation.PASSWORD);
                    newCred.setValue(request.getNewPassword());
                    newCred.setTemporary(false);

                    keycloak.realm(keycloakFactory.getRealm())
                            .users()
                            .get(request.getUserId())
                            .resetPassword(newCred);
                }

            } catch (Exception ex) {
                throw new RuntimeException("Error changing password: " + ex.getMessage(), ex);
            }
        });
    }

    private String getUsernameById(String userId) {
        try (Keycloak keycloak = keycloakFactory.baseClient()) {
            return keycloak.realm(keycloakFactory.getRealm()).users().get(userId).toRepresentation().getUsername();
        }
    }

    @Override
    public Mono<Void> resetPassword(String username) {
        return Mono.error(new UnsupportedOperationException("resetPassword not implemented"));
    }

    @Override
    public Mono<ResponseEntity<MfaChallengeResponse>> mfaChallenge(String username) {
        return Mono.error(new UnsupportedOperationException("mfaChallenge not implemented"));
    }

    @Override
    public Mono<Void> mfaVerify(MfaVerifyRequest request) {
        return Mono.error(new UnsupportedOperationException("mfaVerify not implemented"));
    }

    @Override
    public Mono<ResponseEntity<List<SessionInfo>>> listSessions(String userId) {
        return Mono.fromCallable(() -> {
            try (Keycloak keycloak = keycloakFactory.baseClient()) {
                RealmResource realmResource = keycloak.realm(keycloakFactory.getRealm());

                List<UserSessionRepresentation> userSessions =
                        realmResource.users().get(userId).getUserSessions();

                List<SessionInfo> sessions = userSessions.stream()
                        .map(session -> {
                            SessionInfo info = new SessionInfo();
                            info.setSessionId(session.getId());
                            info.setUserId(userId);
                            info.setCreatedAt(Instant.ofEpochMilli(session.getStart()));
                            info.setLastAccessAt(Instant.ofEpochMilli(session.getLastAccess()));
                            info.setIpAddress(session.getIpAddress());
                            return info;
                        })
                        .collect(Collectors.toList());

                return ResponseEntity.ok(sessions);
            } catch (Exception ex) {
                throw new RuntimeException("Error listing sessions", ex);
            }
        });
    }

    @Override
    public Mono<Void> revokeSession(String sessionId) {
        return Mono.fromRunnable(() -> {
            try (Keycloak keycloak = keycloakFactory.baseClient()) {
                RealmResource realmResource = keycloak.realm(keycloakFactory.getRealm());

                if (sessionId == null || sessionId.isBlank()) {
                    throw new WebApplicationException("SessionId no puede ser nulo o vacío");
                }
                realmResource.deleteSession(sessionId, false);

            } catch (WebApplicationException wae) {
                throw wae;
            } catch (Throwable ex) {
                throw new WebApplicationException("Error revocando la sesión", ex);
            }
        });    }

    @Override
    public Mono<ResponseEntity<List<String>>> getRoles(String userId) {
        return Mono.fromCallable(() -> {
                    UserResource userResource;
                    try (Keycloak keycloak = keycloakFactory.baseClient()) {
                        userResource = keycloak.realm(keycloakFactory.getRealm()).users().get(userId);
                    }
                    MappingsRepresentation mappings = userResource.roles().getAll();

                    Stream<String> realmRoleNames = Stream.ofNullable(mappings.getRealmMappings())
                            .flatMap(List::stream)
                            .filter(Objects::nonNull)
                            .map(RoleRepresentation::getName)
                            .filter(Objects::nonNull);

                    Stream<String> clientRoleNames = Stream.ofNullable(mappings.getClientMappings())
                            .map(Map::values)
                            .flatMap(Collection::stream)
                            .filter(Objects::nonNull)
                            .map(ClientMappingsRepresentation::getMappings)
                            .filter(Objects::nonNull)
                            .flatMap(List::stream)
                            .filter(Objects::nonNull)
                            .map(RoleRepresentation::getName)
                            .filter(Objects::nonNull);

                    return Stream.concat(realmRoleNames, clientRoleNames)
                            .collect(Collectors.collectingAndThen(
                                    Collectors.toCollection(LinkedHashSet::new),
                                    List::copyOf));
                })
                .map(ResponseEntity::ok)
                .onErrorResume(throwable -> {
                    if (throwable instanceof WebApplicationException wae && wae.getResponse() != null) {
                        int status = wae.getResponse().getStatus();
                        return Mono.just(ResponseEntity.status(status).build());
                    }
                    return Mono.just(ResponseEntity.internalServerError().build());
                });
    }

    @Override
    public Mono<Void> deleteUser(String userId) {
        return Mono.fromRunnable(() -> {
            if (userId == null || userId.isBlank()) {
                throw new WebApplicationException("userId cannot be null or empty");
            }

            try (Keycloak keycloak = keycloakFactory.baseClient()) {
                RealmResource realmResource = keycloak.realm(keycloakFactory.getRealm());

                realmResource.users().get(userId).remove();

            } catch (WebApplicationException wae) {
                throw wae;
            } catch (Throwable ex) {
                throw new WebApplicationException("Error deleting user with id: " + userId, ex);
            }
        });
    }

    @Override
    public Mono<ResponseEntity<UpdateUserResponse>> updateUser(UpdateUserRequest request) {
        return Mono.fromCallable(() -> {
            if (request.getUserId() == null || request.getUserId().isBlank()) {
                throw new WebApplicationException("userId cannot be null or empty");
            }

            try (Keycloak keycloak = keycloakFactory.baseClient()) {
                RealmResource realmResource = keycloak.realm(keycloakFactory.getRealm());

                // Retrieve existing user
                UserRepresentation user = realmResource.users().get(request.getUserId()).toRepresentation();
                if (user == null) {
                    return ResponseEntity.notFound().build();
                }

                // Update fields if they are not null
                if (request.getEmail() != null) user.setEmail(request.getEmail());
                if (request.getGivenName() != null) user.setFirstName(request.getGivenName());
                if (request.getFamilyName() != null) user.setLastName(request.getFamilyName());
                if (request.getEnabled() != null) user.setEnabled(request.getEnabled());
                if (request.getAttributes() != null) {
                    Map<String, List<String>> existingAttributes = user.getAttributes();
                    if (existingAttributes != null) {
                        existingAttributes.putAll(request.getAttributes());
                    } else {
                        user.setAttributes(request.getAttributes());
                    }
                }

                // Perform the update
                realmResource.users().get(request.getUserId()).update(user);

                // Build response
                UpdateUserResponse response = new UpdateUserResponse();
                response.setId(user.getId());
                response.setUsername(user.getUsername());
                response.setEmail(user.getEmail());
                response.setUpdatedAt(Instant.now());

                return ResponseEntity.ok(response);

            } catch (WebApplicationException wae) {
                throw wae;
            } catch (Throwable ex) {
                throw new WebApplicationException("Error updating user with id: " + request.getUserId(), ex);
            }
        });
    }

    @Override
    public Mono<ResponseEntity<CreateRolesResponse>> createRoles(CreateRolesRequest request) {
        return Mono.fromCallable(() -> {
            if (request.getRoleNames() == null || request.getRoleNames().isEmpty()) {
                throw new WebApplicationException("roleNames cannot be null or empty");
            }

            List<String> createdRoles = new ArrayList<>();

            try (Keycloak keycloak = keycloakFactory.baseClient()) {
                RealmResource realmResource = keycloak.realm(keycloakFactory.getRealm());

                if (request.getContext() != null && !request.getContext().isBlank()) {
                    // Create roles in a specific client context
                    ClientResource clientResource = realmResource.clients()
                            .findByClientId(request.getContext())
                            .stream()
                            .findFirst()
                            .map(clientRep -> realmResource.clients().get(clientRep.getId()))
                            .orElseThrow(() -> new WebApplicationException("Client not found: " + request.getContext()));

                    for (String roleName : request.getRoleNames()) {
                        RoleRepresentation role = new RoleRepresentation();
                        role.setName(roleName);
                        role.setDescription(request.getDescription());
                        clientResource.roles().create(role);
                        createdRoles.add(roleName);
                    }
                } else {
                    // Create roles in the realm
                    for (String roleName : request.getRoleNames()) {
                        RoleRepresentation role = new RoleRepresentation();
                        role.setName(roleName);
                        role.setDescription(request.getDescription());
                        realmResource.roles().create(role);
                        createdRoles.add(roleName);
                    }
                }

                CreateRolesResponse response = new CreateRolesResponse();
                response.setCreatedRoleNames(createdRoles);
                return ResponseEntity.ok(response);

            } catch (WebApplicationException wae) {
                throw wae;
            } catch (Throwable ex) {
                throw new WebApplicationException("Error creating roles: " + request.getRoleNames(), ex);
            }
        });
    }

    @Override
    public Mono<ResponseEntity<CreateScopeResponse>> createScope(CreateScopeRequest request) {
        return Mono.fromCallable(() -> {
            if (request.getName() == null || request.getName().isBlank()) {
                throw new WebApplicationException("Scope name cannot be null or empty");
            }

            try (Keycloak keycloak = keycloakFactory.baseClient()) {
                RealmResource realmResource = keycloak.realm(keycloakFactory.getRealm());

                RoleRepresentation scopeRole = new RoleRepresentation();
                scopeRole.setName(request.getName());
                scopeRole.setDescription(request.getDescription());

                String scopeId;

                if (request.getContext() != null && !request.getContext().isBlank()) {
                    // Create scope as a client role
                    ClientResource clientResource = realmResource.clients()
                            .findByClientId(request.getContext())
                            .stream()
                            .findFirst()
                            .map(clientRep -> realmResource.clients().get(clientRep.getId()))
                            .orElseThrow(() -> new WebApplicationException("Client not found: " + request.getContext()));

                    clientResource.roles().create(scopeRole);
                    scopeId = clientResource.roles().get(request.getName()).toRepresentation().getId();
                } else {
                    // Create scope as a realm role
                    realmResource.roles().create(scopeRole);
                    scopeId = realmResource.roles().get(request.getName()).toRepresentation().getId();
                }

                CreateScopeResponse response = new CreateScopeResponse();
                response.setId(scopeId);
                response.setName(request.getName());
                response.setCreatedAt(Instant.now());

                return ResponseEntity.ok(response);

            } catch (WebApplicationException wae) {
                throw wae;
            } catch (Throwable ex) {
                throw new WebApplicationException("Error creating scope: " + request.getName(), ex);
            }
        });
    }

    @Override
    public Mono<Void> assignRolesToUser(AssignRolesRequest request) {
        return Mono.fromRunnable(() -> {
            if (request.getUserId() == null || request.getUserId().isBlank()) {
                throw new WebApplicationException("userId cannot be null or empty");
            }

            if (request.getRoleNames() == null || request.getRoleNames().isEmpty()) {
                throw new WebApplicationException("roleNames cannot be null or empty");
            }

            try (Keycloak keycloak = keycloakFactory.baseClient()) {
                RealmResource realmResource = keycloak.realm(keycloakFactory.getRealm());

                UserResource userResource = realmResource.users().get(request.getUserId());

                List<RoleRepresentation> rolesToAssign = new ArrayList<>();
                for (String roleName : request.getRoleNames()) {
                    RoleRepresentation role = realmResource.roles().get(roleName).toRepresentation();
                    if (role != null) {
                        rolesToAssign.add(role);
                    } else {
                        throw new WebApplicationException("Role not found: " + roleName);
                    }
                }

                userResource.roles().realmLevel().add(rolesToAssign);

            } catch (WebApplicationException wae) {
                throw wae;
            } catch (Throwable ex) {
                throw new WebApplicationException("Error assigning roles to user: " + request.getUserId(), ex);
            }
        });
    }

    @Override
    public Mono<Void> removeRolesFromUser(AssignRolesRequest request) {
        return Mono.fromRunnable(() -> {
            if (request.getUserId() == null || request.getUserId().isBlank()) {
                throw new WebApplicationException("userId cannot be null or empty");
            }

            if (request.getRoleNames() == null || request.getRoleNames().isEmpty()) {
                throw new WebApplicationException("roleNames cannot be null or empty");
            }

            try (Keycloak keycloak = keycloakFactory.baseClient()) {
                RealmResource realmResource = keycloak.realm(keycloakFactory.getRealm());
                UserResource userResource = realmResource.users().get(request.getUserId());

                List<RoleRepresentation> rolesToRemove = new ArrayList<>();
                for (String roleName : request.getRoleNames()) {
                    RoleRepresentation role = realmResource.roles().get(roleName).toRepresentation();
                    if (role != null) {
                        rolesToRemove.add(role);
                    } else {
                        throw new WebApplicationException("Role not found: " + roleName);
                    }
                }

                userResource.roles().realmLevel().remove(rolesToRemove);

            } catch (WebApplicationException wae) {
                throw wae;
            } catch (Throwable ex) {
                throw new WebApplicationException(
                        "Error removing roles from user: " + request.getUserId(), ex);
            }
        });
    }
}
