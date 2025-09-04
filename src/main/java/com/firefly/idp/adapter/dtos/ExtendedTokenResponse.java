/*
 * Copyright 2025 Firefly Software Solutions Inc
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


package com.firefly.idp.adapter.dtos;

import com.firefly.idp.dtos.TokenResponse;
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
