package ee.ria.taraauthserver.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

@Component
public class DuplicateRequestParameterFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Optional<Map.Entry<String, String[]>> duplicateParameter = request.getParameterMap().entrySet().stream().filter(es -> es.getValue().length > 1).findFirst();
        if (duplicateParameter.isPresent()) {
            logger.error(String.format("Duplicate parameters not allowed in request. Found multiple parameters with name: %s", duplicateParameter.get().getKey()));
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Multiple request parameters with the same name not allowed");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
