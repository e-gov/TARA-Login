package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.SPType;
import io.restassured.filter.Filter;
import io.restassured.filter.FilterContext;
import io.restassured.response.Response;
import io.restassured.specification.FilterableRequestSpecification;
import io.restassured.specification.FilterableResponseSpecification;
import lombok.Builder;
import lombok.Getter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.util.List;
import java.util.UUID;

import static ee.ria.taraauthserver.config.SecurityConfiguration.TARA_SESSION_CSRF_TOKEN;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

public class MockSessionFilter implements Filter {
    @Getter
    private final Session session;

    public MockSessionFilter(Session session) {
        this.session = session;
    }

    @Builder(builderMethodName = "withTaraSession", builderClassName = "WithTaraSessionBuilder")
    public static MockSessionFilter buildWithTaraSession(SessionRepository<Session> sessionRepository, TaraAuthenticationState authenticationState,
                                                         List<AuthenticationType> authenticationTypes, List<String> clientAllowedScopes, List<String> requestedScopes,
                                                         List<TaraSession.LegalPerson> legalPersonList,
                                                         SPType spType,
                                                         TaraSession.AuthenticationResult authenticationResult) {
        Session session = createTaraSession(sessionRepository, authenticationState, authenticationTypes, clientAllowedScopes, requestedScopes, legalPersonList, spType, authenticationResult);
        sessionRepository.save(session);
        return new MockSessionFilter(session);
    }

    @Builder(builderMethodName = "withoutTaraSession", builderClassName = "WithoutTaraSessionBuilder")
    public static MockSessionFilter buildWithoutTaraSession(SessionRepository<Session> sessionRepository) {
        Session session = createSession(sessionRepository);
        sessionRepository.save(session);
        return new MockSessionFilter(session);
    }

    @Builder(builderMethodName = "withoutCsrf", builderClassName = "WithoutCsrfBuilder")
    public static MockSessionFilter buildWithoutCsrf(SessionRepository<Session> sessionRepository) {
        Session session = sessionRepository.createSession();
        TaraSession taraSession = new TaraSession(session.getId());
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
        return new MockSessionFilter(session);
    }

    @Override
    public Response filter(FilterableRequestSpecification requestSpec, FilterableResponseSpecification responseSpec, FilterContext ctx) {
        CsrfToken csrfToken = session.getAttribute(TARA_SESSION_CSRF_TOKEN);
        requestSpec.sessionId(session.getId());
        if (csrfToken != null) {
            requestSpec.formParam("_csrf", csrfToken.getToken());
        }
        return ctx.next(requestSpec, responseSpec);
    }

    private static Session createSession(SessionRepository<Session> sessionRepository) {
        Session session = sessionRepository.createSession();
        session.setAttribute(TARA_SESSION_CSRF_TOKEN, new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", UUID.randomUUID().toString()));
        return session;
    }

    private static Session createTaraSession(SessionRepository<Session> sessionRepository,
                                             TaraAuthenticationState authenticationState,
                                             List<AuthenticationType> authenticationTypes,
                                             List<String> clientAllowedScopes,
                                             List<String> requestedScopes,
                                             List<TaraSession.LegalPerson> legalPersonList,
                                             SPType spType,
                                             TaraSession.AuthenticationResult authenticationResult) {
        Session session = createSession(sessionRepository);
        TaraSession taraSession = MockTaraSessionBuilder.builder()
                .sessionId(session.getId())
                .authenticationState(authenticationState)
                .authenticationTypes(authenticationTypes)
                .clientAllowedScopes(clientAllowedScopes)
                .requestedScopes(requestedScopes)
                .legalPersonList(legalPersonList)
                .spType(spType)
                .authenticationResult(authenticationResult)
                .build();
        session.setAttribute(TARA_SESSION, taraSession);
        return session;
    }
}
