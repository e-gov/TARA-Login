package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.SPType;
import eu.webeid.security.challenge.ChallengeNonce;
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
import java.util.Map;
import java.util.UUID;

import static ee.ria.taraauthserver.security.NoSessionCreatingHttpSessionCsrfTokenRepository.CSRF_HEADER_NAME;
import static ee.ria.taraauthserver.security.NoSessionCreatingHttpSessionCsrfTokenRepository.CSRF_PARAMETER_NAME;
import static ee.ria.taraauthserver.security.NoSessionCreatingHttpSessionCsrfTokenRepository.CSRF_TOKEN_ATTR_NAME;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

public class MockSessionFilter implements Filter {

    private final CsrfMode csrfMode;

    @Getter
    private final Session session;

    public MockSessionFilter(Session session) {
        this(session, CsrfMode.FORM_PARAMETER);
    }

    public MockSessionFilter(Session session, CsrfMode csrfMode) {
        this.session = session;
        if (csrfMode == null) {
            this.csrfMode = CsrfMode.FORM_PARAMETER;
        } else {
            this.csrfMode = csrfMode;
        }
    }

    @Builder(builderMethodName = "withTaraSession", builderClassName = "WithTaraSessionBuilder")
    public static MockSessionFilter buildWithTaraSession(SessionRepository<Session> sessionRepository,
                                                         TaraAuthenticationState authenticationState,
                                                         List<AuthenticationType> authenticationTypes,
                                                         List<String> clientAllowedScopes,
                                                         List<String> requestedScopes,
                                                         List<TaraSession.LegalPerson> legalPersonList,
                                                         SPType spType,
                                                         Map<String, String> shortNameTranslations,
                                                         CsrfMode csrfMode,
                                                         ChallengeNonce nonce,
                                                         TaraSession.AuthenticationResult authenticationResult,
                                                         String chosenLanguage) {
        Session session = createTaraSession(sessionRepository, authenticationState, authenticationTypes, clientAllowedScopes, requestedScopes, legalPersonList, spType, shortNameTranslations, nonce, authenticationResult, chosenLanguage);
        sessionRepository.save(session);
        return new MockSessionFilter(session, csrfMode);
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
        CsrfToken csrfToken = session.getAttribute(CSRF_TOKEN_ATTR_NAME);
        requestSpec.sessionId(session.getId());
        if (csrfToken != null && csrfMode == CsrfMode.FORM_PARAMETER) {
            requestSpec.formParam(CSRF_PARAMETER_NAME, csrfToken.getToken());
        } else if (csrfToken != null && csrfMode == CsrfMode.HEADER) {
            requestSpec.header(CSRF_HEADER_NAME, csrfToken.getToken());
        }
        return ctx.next(requestSpec, responseSpec);
    }

    private static Session createSession(SessionRepository<Session> sessionRepository) {
        Session session = sessionRepository.createSession();
        session.setAttribute(CSRF_TOKEN_ATTR_NAME, new DefaultCsrfToken(CSRF_HEADER_NAME, CSRF_PARAMETER_NAME, UUID.randomUUID().toString()));
        return session;
    }

    private static Session createTaraSession(SessionRepository<Session> sessionRepository,
                                             TaraAuthenticationState authenticationState,
                                             List<AuthenticationType> authenticationTypes,
                                             List<String> clientAllowedScopes,
                                             List<String> requestedScopes,
                                             List<TaraSession.LegalPerson> legalPersonList,
                                             SPType spType,
                                             Map<String, String> shortNameTranslations,
                                             ChallengeNonce webEidChallengeNonce,
                                             TaraSession.AuthenticationResult authenticationResult,
                                             String chosenLanguage) {
        Session session = createSession(sessionRepository);
        TaraSession taraSession = MockTaraSessionBuilder.builder()
                .sessionId(session.getId())
                .authenticationState(authenticationState)
                .authenticationTypes(authenticationTypes)
                .clientAllowedScopes(clientAllowedScopes)
                .requestedScopes(requestedScopes)
                .legalPersonList(legalPersonList)
                .spType(spType)
                .shortNameTranslations(shortNameTranslations)
                .authenticationResult(authenticationResult)
                .webEidChallengeNonce(webEidChallengeNonce)
                .chosenLanguage(chosenLanguage)
                .build();
        session.setAttribute(TARA_SESSION, taraSession);
        return session;
    }

    public enum CsrfMode {
        HEADER,
        FORM_PARAMETER
    }
}
