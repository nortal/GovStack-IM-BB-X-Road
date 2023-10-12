/**
 * The MIT License
 * Copyright (c) 2019- Nordic Institute for Interoperability Solutions (NIIS)
 * Copyright (c) 2018 Estonian Information System Authority (RIA),
 * Nordic Institute for Interoperability Solutions (NIIS), Population Register Centre (VRK)
 * Copyright (c) 2015-2017 Estonian Information System Authority (RIA), Population Register Centre (VRK)
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.niis.xroad.restapi.auth;

import lombok.extern.slf4j.Slf4j;
import org.niis.xroad.restapi.domain.Role;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class OauthLoginGrantedAuthoritiesMapper implements GrantedAuthoritiesMapper {
    private final GrantedAuthorityMapper grantedAuthorityMapper;

    /**
     * users with these groups are allowed access
     */
    private static final Set<String> ALLOWED_ROLE_NAMES = Collections.unmodifiableSet(
            Arrays.stream(Role.values())
                    .map(Role::getLinuxGroupName)
                    .collect(Collectors.toSet()));

    public OauthLoginGrantedAuthoritiesMapper(GrantedAuthorityMapper grantedAuthorityMapper) {
        this.grantedAuthorityMapper = grantedAuthorityMapper;
    }

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

        for (GrantedAuthority authority : authorities) {
            if (authority instanceof OidcUserAuthority) {
                OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
                Map<String, Object> idTokenClaims = oidcUserAuthority.getIdToken().getClaims();
                mappedAuthorities.addAll(mapRolesToGrantedAuthorities(idTokenClaims));
            }
        }

        return mappedAuthorities;
    }

    private Collection<GrantedAuthority> mapRolesToGrantedAuthorities(Map<String, Object> claims) {
        Object rolesClaim = claims.get("roles");
        if (rolesClaim instanceof Collection) {
            Collection<String> roles = (Collection<String>) rolesClaim;

            Set<String> matchingRoles = roles.stream()
                    .filter(ALLOWED_ROLE_NAMES::contains)
                    .collect(Collectors.toSet());
            if (matchingRoles.isEmpty()) {
                throw new AuthenticationServiceException("user hasn't got any required roles");
            }
            Collection<Role> xroadRoles = matchingRoles.stream()
                    .map(roleName -> Role.getForGroupName(roleName).get())
                    .collect(Collectors.toSet());
            return grantedAuthorityMapper.getAuthorities(xroadRoles);
        }
        throw new AuthenticationServiceException("unknown roles claim type, expected roles claim to contain a list");
    }
}
