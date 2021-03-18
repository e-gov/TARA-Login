package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.firewall.StrictHttpFirewall;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static ee.ria.taraauthserver.authentication.idcard.IdCardController.AUTH_ID_REQUEST_MAPPING;

@Slf4j
@EnableWebSecurity
public class SecurityConfiguration {
    public static final String TARA_SESSION_CSRF_TOKEN = "tara.csrf";

    @Order(1)
    @ConditionalOnProperty(value = "tara.auth-methods.id-card.basic-auth.enabled")
    @Configuration
    @RequiredArgsConstructor
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
                    .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository()))
                    .headers()
                    .frameOptions().deny()
                    .contentSecurityPolicy(authConfigurationProperties.getContentSecurityPolicy())
                    .and()
                    .httpStrictTransportSecurity()
                    .includeSubDomains(true)
                    .maxAgeInSeconds(16070400);
        }

        @Override
        public void configure(WebSecurity webSecurity) {
            StrictHttpFirewall firewall = new StrictHttpFirewall();
            firewall.setUnsafeAllowAnyHttpMethod(true);
            webSecurity.httpFirewall(firewall);
        }

        @Bean
        public CsrfTokenRepository csrfTokenRepository() {
            HttpSessionCsrfTokenRepository tokenRepository = new HttpSessionCsrfTokenRepository();
            tokenRepository.setSessionAttributeName(TARA_SESSION_CSRF_TOKEN);
            return tokenRepository;
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