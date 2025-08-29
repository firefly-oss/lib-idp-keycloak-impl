package com.firefly.idp.adapter.service;

import com.firefly.idp.dtos.*;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

import java.util.List;

public interface IdpAdminService {

    Mono<ResponseEntity<CreateUserResponse>> createUser(CreateUserRequest request);

    Mono<Void> changePassword(ChangePasswordRequest request);

    Mono<Void> resetPassword(String username);

    Mono<ResponseEntity<MfaChallengeResponse>> mfaChallenge(String username);

    Mono<Void> mfaVerify(MfaVerifyRequest request);

    Mono<ResponseEntity<List<SessionInfo>>> listSessions(String userId);

    Mono<Void> revokeSession(String sessionId);

    Mono<ResponseEntity<List<String>>> getRoles(String userId);

    // New methods (stubs for now)
    Mono<Void> deleteUser(String userId);

    Mono<ResponseEntity<UpdateUserResponse>> updateUser(UpdateUserRequest request);

    Mono<ResponseEntity<CreateRolesResponse>> createRoles(CreateRolesRequest request);

    Mono<ResponseEntity<CreateScopeResponse>> createScope(CreateScopeRequest request);

    Mono<Void> assignRolesToUser(AssignRolesRequest request);

    Mono<Void> removeRolesFromUser(AssignRolesRequest request);
}
