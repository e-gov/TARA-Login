package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.security.NoSessionCreatingHttpSessionCsrfTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static ee.ria.taraauthserver.authentication.eidas.EidasCallbackController.EIDAS_CALLBACK_REQUEST_MAPPING;
import static ee.ria.taraauthserver.authentication.idcard.IdCardController.AUTH_ID_REQUEST_MAPPING;

@Slf4j
@EnableWebSecurity
public class SecurityConfiguration {

    @Order(1)
    @ConditionalOnProperty(value = "tara.auth-methods.id-card.basic-auth.enabled")
    @Configuration
    @RequiredArgsConstructor
    // TODO Replace deprecated WebSecurityConfigurerAdapter with SecurityFilterChain etc.
    public static class IdCardApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        private final AuthConfigurationProperties authConfigurationProperties;
        @Value("${tara.auth-methods.id-card.basic-auth.username}")
        private String username;
        @Value("${tara.auth-methods.id-card.basic-auth.password}")
        private String password;

        protected void configure(HttpSecurity http) throws Exception {
            http
                    .antMatcher(AUTH_ID_REQUEST_MAPPING)
                    .exceptionHandling()
                    .accessDeniedHandler(new CustomAccessDeniedHandler())
                    .and()
                    .securityContext().disable()
                    .anonymous().disable()
                    .logout().disable()
                    .rememberMe().disable()
                    .servletApi().disable()
                    .sessionManagement().disable()
                    .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .httpBasic()
                    .and()
                    .headers()
                    .xssProtection().xssProtectionEnabled(false)
                    .and()
                    .frameOptions().deny()
                    .contentSecurityPolicy(authConfigurationProperties.getContentSecurityPolicy())
                    .and()
                    .httpStrictTransportSecurity()
                    .includeSubDomains(true)
                    .maxAgeInSeconds(16070400);
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                    .inMemoryAuthentication()
                    .withUser(username)
                    .password(passwordEncoder().encode(password))
                    .roles("AUTH_ID_REQUEST");
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
    }

    @Order(2)
    @Configuration
    @RequiredArgsConstructor
    public static class AuthenticationApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        private final AuthConfigurationProperties authConfigurationProperties;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .exceptionHandling()
                    .accessDeniedHandler(new CustomAccessDeniedHandler())
                    .and()
                    .securityContext().disable()
                    .anonymous().disable()
                    .logout().disable()
                    .rememberMe().disable()
                    .httpBasic().disable()
                    .servletApi().disable()
                    .sessionManagement().disable()
                    .csrf(this::configureCsrf)
                    .headers()
                    .xssProtection().xssProtectionEnabled(false)
                    .and()
                    .frameOptions().deny()
                    .contentSecurityPolicy(authConfigurationProperties.getContentSecurityPolicy())
                    .and()
                    .httpStrictTransportSecurity()
                    .includeSubDomains(true)
                    .maxAgeInSeconds(16070400);
        }

        private void configureCsrf(CsrfConfigurer<HttpSecurity> csrf) {
            csrf.csrfTokenRepository(csrfTokenRepository())
                    .requireCsrfProtectionMatcher(new AndRequestMatcher(
                            CsrfFilter.DEFAULT_CSRF_MATCHER,
                            new NegatedRequestMatcher(new AntPathRequestMatcher(EIDAS_CALLBACK_REQUEST_MAPPING))));
        }

        @Override
        public void configure(WebSecurity webSecurity) {
            StrictHttpFirewall firewall = new StrictHttpFirewall();
            firewall.setUnsafeAllowAnyHttpMethod(true);
            webSecurity.httpFirewall(firewall);
        }

        @Bean
        public CsrfTokenRepository csrfTokenRepository() {
            return new NoSessionCreatingHttpSessionCsrfTokenRepository();
        }
    }

    static class CustomAccessDeniedHandler implements AccessDeniedHandler {
        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
                throws IOException, ServletException {
            if (accessDeniedException instanceof CsrfException) {
                setErrorAttributes(request, ErrorCode.INVALID_CSRF_TOKEN, "Invalid CSRF token.");
            } else {
                setErrorAttributes(request, ErrorCode.INVALID_REQUEST, "Invalid request: " + accessDeniedException.getMessage());
            }
            request.getRequestDispatcher("/error").forward(request, response);
        }

        private void setErrorAttributes(HttpServletRequest request, ErrorCode invalidCsrfToken, String message) {
            request.setAttribute(RequestDispatcher.ERROR_STATUS_CODE, 403);
            request.setAttribute(DefaultErrorAttributes.class.getName() + ".ERROR", new BadRequestException(invalidCsrfToken, message));
            log.error("Access denied: " + message);
        }
    }
}
