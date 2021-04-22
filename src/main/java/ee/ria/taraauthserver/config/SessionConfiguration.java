package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.security.RequestCorrelationFilter;
import ee.ria.taraauthserver.security.SessionManagementFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.session.web.http.SessionRepositoryFilter;

import static java.util.List.of;

/**
 * Replace {@link EnableSpringHttpSession} with Spring Session Ignite module or corresponding Community Extension,
 * that provides concurrency safe SessionRepository implementation backed by Ignite and configuration support when it becomes available.
 *
 * @see <a href="https://github.com/spring-projects/spring-session/pull/1730">Ignite integration module pull request</a>
 * @see <a href="https://docs.spring.io/spring-session/docs/2.4.1/reference/html5/#httpsession">HttpSession Integration</a>
 * @see <a href="https://docs.spring.io/spring-session/docs/2.4.2/reference/html5/#custom-sessionrepository">Remarks about concurrency</a>
 * @see <a href="https://docs.spring.io/spring-session/docs/2.4.1/reference/html5/#community">Spring Session Community Extensions</a>
 */
@Configuration
@EnableSpringHttpSession
public class SessionConfiguration {
    public static final String TARA_SESSION_COOKIE_NAME = "SESSION";

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookiePath("/");
        serializer.setUseSecureCookie(true);
        serializer.setSameSite("Strict");
        serializer.setUseHttpOnlyCookie(true);
        serializer.setUseBase64Encoding(false);
        serializer.setCookieName(TARA_SESSION_COOKIE_NAME);
        return serializer;
    }

    @Bean
    public FilterRegistrationBean<SessionRepositoryFilter<?>> sessionRepositoryFilterRegistrationTest(@Value("${spring.session.servlet.filter-order}") Integer filterOrder, SessionRepositoryFilter<?> filter) {
        FilterRegistrationBean<SessionRepositoryFilter<?>> registrationBean = new FilterRegistrationBean<>(filter);
        registrationBean.setUrlPatterns(of("/auth/*", "/oidc-error"));
        registrationBean.setOrder(filterOrder);
        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean<SessionManagementFilter> sessionManagementFilter(@Value("${spring.session.servlet.filter-order}") Integer filterOrder) {
        FilterRegistrationBean<SessionManagementFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setUrlPatterns(of("/auth/*"));
        registrationBean.setFilter(new SessionManagementFilter());
        registrationBean.setOrder(filterOrder + 1);
        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean<RequestCorrelationFilter> requestCorrelationFilter(@Value("${spring.session.servlet.filter-order}") Integer filterOrder, BuildProperties buildProperties) {
        FilterRegistrationBean<RequestCorrelationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new RequestCorrelationFilter(buildProperties));
        registrationBean.setOrder(filterOrder + 2);
        return registrationBean;
    }
}
