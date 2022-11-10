package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
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

@Slf4j
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    public static final String TARA_SESSION_CSRF_TOKEN = "tara.csrf";
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
                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository()))
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
        HttpSessionCsrfTokenRepository tokenRepository = new HttpSessionCsrfTokenRepository();
        tokenRepository.setSessionAttributeName(TARA_SESSION_CSRF_TOKEN);
        return tokenRepository;
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
