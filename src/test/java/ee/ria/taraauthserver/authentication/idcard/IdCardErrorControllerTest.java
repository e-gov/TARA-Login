package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.authentication.idcard.IdCardErrorController.WebEidErrorParameters;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.MockSessionFilter.CsrfMode;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.util.UUID;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static ee.ria.taraauthserver.config.SecurityConfiguration.TARA_SESSION_CSRF_TOKEN;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
class IdCardErrorControllerTest extends BaseTest {

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    @Tag(value = "CSRF_PROTCTION")
    // TODO: AUT-1057: Add new tags?
    void handleRequest_NoCsrf_Fails() {
        given()
                .body(new WebEidErrorParameters())
                .filter(MockSessionFilter.withoutCsrf().sessionRepository(sessionRepository).build())
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/error")
                .then()
                .assertThat()
                .statusCode(403)
                .body("error", equalTo("Forbidden"))
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36}"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    // TODO: AUT-1057: Add new tags?
    void handleRequest_MissingSession_Fails() {
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withoutTaraSession()
                .sessionRepository(sessionRepository)
                .csrfMode(CsrfMode.HEADER)
                .build();
        given()
                .body(createRequestBody())
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/error")
                .then()
                .assertThat()
                .statusCode(400)
                .body("message", equalTo("Teie seanssi ei leitud! Seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Bad Request"))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36}"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("User exception: Invalid session");
        assertStatisticsIsNotLogged();
    }

    @ParameterizedTest
    @ValueSource(strings = {"ERR_WEBEID_EXTENSION_UNAVAILABLE", "ERR_WEBEID_NATIVE_UNAVAILABLE", "ERR_WEBEID_VERSION_MISMATCH"})
    // TODO: AUT-1057: Add new tags?
    void handleRequest_ExtensionUnavailableWithEstonianLocale_ReturnsCorrectResponse(String errorCode) {
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withTaraSession()
                .csrfMode(CsrfMode.HEADER)
                .sessionRepository(sessionRepository)
                .build();
        WebEidErrorParameters requestBody = createRequestBody();
        requestBody.setCode(errorCode);
        given()
                .body(requestBody)
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/error")
                .then()
                .assertThat()
                .statusCode(200)
                .body("message", equalTo("Palun uuendage ID-tarkvara <a href=\"https://www.id.ee/artikkel/paigalda-id-tarkvara/\">id.ee veebilehelt</a> ja järgige seal kirjeldatud veebibrauseri seadistamise juhiseid.<br/>Uuendamata ID-tarkvaraga ei ole võimalik ID-kaardiga sisse logida autentimisteenuse kaudu."))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36}"))
                .body("reportable", equalTo(false));

        TaraSession taraSession = sessionRepository.findById(mockSessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
        assertMessageWithMarkerIsLoggedOnce(IdCardErrorController.class, ERROR,
                "Client-side Web eID operation error: " + errorCode,
                "tara.webeid.extension_version=1.1.1, tara.webeid.native_app_version=2.2.2, tara.webeid.status_duration_ms=999, tara.webeid.error_stack=error\nstack");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=null)");
    }

    @Test
    // TODO: AUT-1057: Add new tags?
    void handleRequest_WebEidErrorMessageWithEstonianLocale_ReturnsCorrectResponse() {
        MockSessionFilter mockSessionFilter = MockSessionFilter
                .withTaraSession()
                .csrfMode(CsrfMode.HEADER)
                .sessionRepository(sessionRepository)
                .build();

        WebEidErrorParameters requestBody = createRequestBody();
        requestBody.setCode("ERR_WEBEID_UNKNOWN_ERROR");
        given()
                .body(requestBody)
                .filter(mockSessionFilter)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/error")
                .then()
                .assertThat()
                .statusCode(200)
                .body("message", equalTo("ID-kaardiga veebis sisse logimiseks ja allkirjastamiseks vajalik Web eID laiendus ei ole Teie arvutis töökorras.<br/>Palun kontrollige vastavalt <a href=\"https://www.id.ee/artikkel/id-kaardiga-sisenemine-voi-allkirjastamine-e-teenustes-ebaonnestub-2/\">id.ee juhendile</a>, kas ID-tarkvara on ajakohane ja veebilehitseja õigesti seadistatud.<br/>Uuendamata ID-tarkvaraga ja valesti seadistatud veebilehitsejaga ei ole võimalik ID-kaardiga sisse logida autentimisteenuse kaudu.<br/>Vea kood ERR_WEBEID_UNKNOWN_ERROR"))
                .body("incident_nr", matchesPattern("[A-Za-z0-9,-]{36}"))
                .body("reportable", equalTo(true));

        TaraSession taraSession = sessionRepository.findById(mockSessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(TaraAuthenticationState.AUTHENTICATION_FAILED, taraSession.getState());
        assertMessageWithMarkerIsLoggedOnce(IdCardErrorController.class, ERROR,
                "Client-side Web eID operation error: ERR_WEBEID_UNKNOWN_ERROR",
                "tara.webeid.extension_version=1.1.1, tara.webeid.native_app_version=2.2.2, tara.webeid.status_duration_ms=999, tara.webeid.error_stack=error\nstack");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=null)");
    }

    // TODO: Add test for another locale

    private WebEidErrorParameters createRequestBody() {
        WebEidErrorParameters body = new WebEidErrorParameters();
        body.setCode("ERR_WEBEID_EXTENSION_UNAVAILABLE");
        body.setExtensionVersion("1.1.1");
        body.setNativeAppVersion("2.2.2");
        body.setErrorStack("error\nstack");
        body.setStatusDurationMs("999");
        return body;
    }

    private Session createSessionWithAuthenticationState(TaraAuthenticationState authenticationState) {
        Session session = sessionRepository.createSession();
        TaraSession authSession = new TaraSession(session.getId());
        authSession.setState(authenticationState);
        TaraSession.LoginRequestInfo loginRequestInfo = new TaraSession.LoginRequestInfo();
        loginRequestInfo.getClient().getMetaData().getOidcClient().getInstitution().setSector(SPType.PUBLIC);
        authSession.setLoginRequestInfo(loginRequestInfo);
        session.setAttribute(TARA_SESSION, authSession);
        session.setAttribute(TARA_SESSION_CSRF_TOKEN, new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", UUID.randomUUID().toString()));
        sessionRepository.save(session);
        return session;
    }
}
