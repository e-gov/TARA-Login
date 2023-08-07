package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.security.NoSessionCreatingHttpSessionCsrfTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static ee.ria.taraauthserver.authentication.eidas.EidasCallbackController.EIDAS_CALLBACK_REQUEST_MAPPING;
import static ee.ria.taraauthserver.authentication.webauthn.WebauthnCallbackController.WEBAUTHN_LOGIN_CALLBACK_REQUEST_MAPPING;
import static ee.ria.taraauthserver.authentication.webauthn.WebauthnCallbackController.WEBAUTHN_REGISTER_CALLBACK_REQUEST_MAPPING;
import static ee.ria.taraauthserver.authentication.webauthn.WebauthnCancelController.WEBAUTHN_LOGIN_CANCEL_REQUEST_MAPPING;
import static ee.ria.taraauthserver.authentication.webauthn.WebauthnCancelController.WEBAUTHN_REGISTRATION_CANCEL_REQUEST_MAPPING;
import static ee.ria.taraauthserver.authentication.AuthInitController.AUTH_INIT_REQUEST_MAPPING;

@Slf4j
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final AuthConfigurationProperties authConfigurationProperties;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
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
        return http.build();
    }

    private void configureCsrf(CsrfConfigurer<HttpSecurity> csrf) {
        csrf.csrfTokenRepository(csrfTokenRepository())
                .requireCsrfProtectionMatcher(new AndRequestMatcher(
                        CsrfFilter.DEFAULT_CSRF_MATCHER,
                        new NegatedRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher(EIDAS_CALLBACK_REQUEST_MAPPING),
                        new AntPathRequestMatcher(WEBAUTHN_LOGIN_CALLBACK_REQUEST_MAPPING),
                        new AntPathRequestMatcher(WEBAUTHN_REGISTER_CALLBACK_REQUEST_MAPPING),
                        new AntPathRequestMatcher(WEBAUTHN_LOGIN_CANCEL_REQUEST_MAPPING),
                        new AntPathRequestMatcher(WEBAUTHN_REGISTRATION_CANCEL_REQUEST_MAPPING)
                    ))));
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            StrictHttpFirewall firewall = new StrictHttpFirewall();
            firewall.setUnsafeAllowAnyHttpMethod(true);
            web.httpFirewall(firewall);
        };
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
