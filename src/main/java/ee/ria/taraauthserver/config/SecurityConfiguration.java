package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.firewall.StrictHttpFirewall;

@Slf4j
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    public static final String TARA_SESSION_CSRF_TOKEN = "tara.csrf";
    private final AuthConfigurationProperties authConfigurationProperties;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
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