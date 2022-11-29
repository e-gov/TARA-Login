package ee.ria.taraauthserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Configuration
public class CsrfConfiguration {

    /**
     * Mark requests for static resources to be skipped by {@link org.springframework.security.web.csrf.CsrfFilter}
     * in order to prevent it from creating a user session if one did not exist already.
     */
    @Bean
    public FilterRegistrationBean<SkipCsrfFilter> skipStaticContentCsrfFilterRegistration() {
        List<RequestMatcher> doNotSkip = List.of(
                new AntPathRequestMatcher("/auth/**"),
                new AntPathRequestMatcher("/oidc-error"));
        RequestMatcher requestMatcher = new NegatedRequestMatcher(new OrRequestMatcher(doNotSkip));
        SkipCsrfFilter filter = new SkipCsrfFilter(requestMatcher);
        FilterRegistrationBean<SkipCsrfFilter> registrationBean = new FilterRegistrationBean<>(filter);
        registrationBean.setOrder(Integer.MIN_VALUE);
        return registrationBean;
    }

    @RequiredArgsConstructor
    public static class SkipCsrfFilter extends OncePerRequestFilter {

        private final RequestMatcher requestMatcher;

        @Override
        protected void doFilterInternal(
                HttpServletRequest request, HttpServletResponse response, FilterChain filterChain
        ) throws ServletException, IOException {
            if (requestMatcher.matches(request)) {
                CsrfFilter.skipRequest(request);
            }
            filterChain.doFilter(request, response);
        }
    }
}
