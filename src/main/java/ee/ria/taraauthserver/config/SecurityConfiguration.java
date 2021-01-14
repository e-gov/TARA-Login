package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.LazyCsrfTokenRepository;
import org.springframework.security.web.firewall.StrictHttpFirewall;

@Slf4j
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    public static final String TARA_SESSION_CSRF_TOKEN = "tara.csrf";

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository()))
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
        HttpSessionCsrfTokenRepository delegate = new HttpSessionCsrfTokenRepository();
        delegate.setSessionAttributeName(TARA_SESSION_CSRF_TOKEN);
        return new LazyCsrfTokenRepository(delegate);
    }
}