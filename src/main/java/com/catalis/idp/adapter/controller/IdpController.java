package com.catalis.idp.adapter.controller;

import com.catalis.idp.adapter.IdpAdapter;
import com.catalis.idp.dtos.LoginRequest;
import com.catalis.idp.dtos.TokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/idp")
public class IdpController {

    private final IdpAdapter idpAdapter;

    @Autowired
    public IdpController(IdpAdapter idpAdapter) {
        this.idpAdapter = idpAdapter;
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<TokenResponse>> login(@RequestBody LoginRequest request) {
        return idpAdapter.login(request);
    }
}
