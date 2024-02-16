package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.security.NoSessionCreatingHttpSessionCsrfTokenRepository;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;

import java.io.IOException;

import static ee.ria.taraauthserver.authentication.eidas.EidasCallbackController.EIDAS_CALLBACK_REQUEST_MAPPING;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final AuthConfigurationProperties authConfigurationProperties;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .exceptionHandling(exceptionHandlingConfigurer -> exceptionHandlingConfigurer
                        .accessDeniedHandler(new CustomAccessDeniedHandler()))
                .securityContext(AbstractHttpConfigurer::disable)
                .anonymous(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .rememberMe(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .servletApi(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .csrf(this::configureCsrf)
                .headers(headersConfigurer -> headersConfigurer
                        .xssProtection(xssConfig -> xssConfig
                                .headerValue(XXssProtectionHeaderWriter.HeaderValue.DISABLED))
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                        .contentSecurityPolicy(policyConfig -> policyConfig
                                .policyDirectives(authConfigurationProperties.getContentSecurityPolicy()))
                        .httpStrictTransportSecurity(hstsConfig -> hstsConfig
                                .includeSubDomains(true)
                                .maxAgeInSeconds(16070400)));
        return http.build();
    }

    private void configureCsrf(CsrfConfigurer<HttpSecurity> csrf) {
        csrf.csrfTokenRepository(csrfTokenRepository())
                .csrfTokenRequestHandler(csrfRequestHandler())
                .requireCsrfProtectionMatcher(new AndRequestMatcher(
                        CsrfFilter.DEFAULT_CSRF_MATCHER,
                        new NegatedRequestMatcher(new AntPathRequestMatcher(EIDAS_CALLBACK_REQUEST_MAPPING))));
    }

    private CsrfTokenRequestAttributeHandler csrfRequestHandler() {
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        //Opt-out of Deferred CSRF Tokens as described in https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#deferred-csrf-token
        requestHandler.setCsrfRequestAttributeName(null);
        return requestHandler;
    }

    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        return new NoSessionCreatingHttpSessionCsrfTokenRepository();
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
