package com.catalis.idp.adapter.dtos;

import com.catalis.idp.dtos.TokenResponse;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * Extends the external TokenResponse to include a list of user roles.
 * Returning this subclass where a TokenResponse is expected allows
 * controllers to serialize the extra field without changing the API signature.
 */

@Getter
@Setter
public class ExtendedTokenResponse extends TokenResponse {

    private List<String> roles;

    public ExtendedTokenResponse() {
        super();
    }

}
