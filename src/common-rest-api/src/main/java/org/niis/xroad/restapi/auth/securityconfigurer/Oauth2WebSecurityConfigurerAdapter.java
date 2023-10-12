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
package org.niis.xroad.restapi.auth.securityconfigurer;

import lombok.extern.slf4j.Slf4j;
import org.niis.xroad.restapi.auth.GrantedAuthorityMapper;
import org.niis.xroad.restapi.auth.OauthLoginGrantedAuthoritiesMapper;
import org.niis.xroad.restapi.config.audit.AuditEventLoggingFacade;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.niis.xroad.restapi.config.audit.RestApiAuditEvent.FORM_LOGOUT;

@Configuration
@ConditionalOnProperty(
        value = "xroad.ui.authentication-method",
        havingValue = "OAUTH2")
@Order(MultiAuthWebSecurityConfig.OAUTH2_LOGIN_SECURITY_ORDER)
@Slf4j
public class Oauth2WebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    public static final String OAUTH_REDIRECT_URL = "/oauth_login/";
    public static final String OAUTH_CALLBACK_URL = "/#/oauth-login";
    public static final String AUTH_CONF_URL = "/authentication-configuration";

    @Autowired
    private GrantedAuthorityMapper grantedAuthorityMapper;
    @Autowired
    private AuditEventLoggingFacade auditEventLoggingFacade;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http

                .authorizeRequests()
                .antMatchers("/error").permitAll()
                .antMatchers(AUTH_CONF_URL).permitAll()
                .antMatchers("/logout").fullyAuthenticated()
                .antMatchers("/api/**").denyAll()
                .anyRequest().denyAll()
                .and()
                .csrf()
                .ignoringAntMatchers(OAUTH_REDIRECT_URL, "/login/**", "/oauth2/**")
                .csrfTokenRepository(new CookieAndSessionCsrfTokenRepository())
                .and()
                .headers()
                .contentSecurityPolicy("default-src 'self' 'unsafe-inline'")
                .and()
                .and()
                .oauth2Login()
                .defaultSuccessUrl(OAUTH_CALLBACK_URL, true)
                .userInfoEndpoint()
                .userAuthoritiesMapper(oidcLoginGrantedAuthoritiesMapper())
                .and()
                .and()
                .logout()
                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
                .addLogoutHandler(new AuditLoggingLogoutHandler())
                .permitAll();
    }

    @Bean
    OauthLoginGrantedAuthoritiesMapper oidcLoginGrantedAuthoritiesMapper() {
        return new OauthLoginGrantedAuthoritiesMapper(grantedAuthorityMapper);
    }

    class AuditLoggingLogoutHandler implements LogoutHandler {
        @Override
        public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
            try {
                auditEventLoggingFacade.auditLogSuccess(FORM_LOGOUT);
            } catch (Exception e) {
                log.error("failed to audit log logout", e);
            }
        }
    }


}
