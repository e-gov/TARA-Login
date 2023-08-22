package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.authentication.idcard.IdCardErrorController.WebEidErrorParameters;
import ee.ria.taraauthserver.error.ErrorHandler;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.MockSessionFilter.CsrfMode;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.WARN;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static java.lang.String.format;

@Slf4j
class IdCardErrorControllerTest extends BaseTest {

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    @Tag(value = "CSRF_PROTECTION")
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
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @Test
    @Tag(value = "CSRF_PROTECTION")
    void handleRequest_MissingSession_Fails() {
        given()
                .body(createRequestBody())
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .when()
                .post("/auth/id/error")
                .then()
                .assertThat()
                .statusCode(403)
                .header("Set-Cookie", nullValue())
                .body("message", equalTo("Keelatud päring. Päring esitati topelt, seanss aegus või on küpsiste kasutamine Teie brauseris piiratud."))
                .body("error", equalTo("Forbidden"))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        assertErrorIsLogged("Access denied: Invalid CSRF token.");
        assertStatisticsIsNotLogged();
    }

    @ParameterizedTest
    @ValueSource(strings = {"ERR_WEBEID_EXTENSION_UNAVAILABLE", "ERR_WEBEID_NATIVE_UNAVAILABLE", "ERR_WEBEID_VERSION_MISMATCH"})
    @Tag(value = "IDCARD_ERROR_HANDLING")
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
                .statusCode(400)
                .body("message", startsWith("Palun uuendage ID-tarkvara <a href=\"https://www.id.ee/artikkel/paigalda-id-tarkvara/\">id.ee veebilehelt</a> ja järgige seal kirjeldatud veebibrauseri seadistamise juhiseid.<br>Uuendamata ID-tarkvaraga ei ole võimalik ID-kaardiga sisse logida "))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(false));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertMessageWithMarkerIsLoggedOnce(IdCardErrorController.class, ERROR,
                "Client-side Web eID operation error: " + errorCode,
                "tara.webeid.extension_version=1.1.1, tara.webeid.native_app_version=2.2.2, tara.webeid.status_duration_ms=999, tara.webeid.error_stack=error\nstack");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=IDC_WEBEID_NOT_AVAILABLE)", mockSessionFilter.getSession().getId()));
    }

    @Test
    @Tag(value = "IDCARD_ERROR_HANDLING")
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
                .statusCode(400)
                .body("message", startsWith("ID-kaardiga veebis sisselogimiseks ja allkirjastamiseks vajalik<span translate=\"no\"> Web eID </span>laiendus ei ole Teie arvutis töökorras.<br>Palun kontrollige vastavalt <a href=\"https://www.id.ee/artikkel/id-kaardiga-sisenemine-voi-allkirjastamine-e-teenustes-ebaonnestub-2/\">id.ee juhendile</a>, kas ID-tarkvara on ajakohane ja veebilehitseja õigesti seadistatud.<br>Uuendamata ID-tarkvaraga ja valesti seadistatud veebilehitsejaga ei ole võimalik ID-kaardiga sisse logida "))
                .body("message", endsWith(" autentimisteenuse kaudu.<br>Vea kood<span translate=\"no\"> ERR_WEBEID_UNKNOWN_ERROR</span>"))
                .body("incident_nr", matchesPattern("[a-f0-9]{32}"))
                .body("reportable", equalTo(true));

        String sessionId = mockSessionFilter.getSession().getId();
        assertNull(sessionRepository.findById(sessionId));
        assertMessageWithMarkerIsLoggedOnce(IdCardErrorController.class, ERROR,
                "Client-side Web eID operation error: ERR_WEBEID_UNKNOWN_ERROR",
                "tara.webeid.extension_version=1.1.1, tara.webeid.native_app_version=2.2.2, tara.webeid.status_duration_ms=999, tara.webeid.error_stack=error\nstack");
        assertMessageWithMarkerIsLoggedOnce(ErrorHandler.class, WARN, "Session has been invalidated: " + sessionId, "tara.session=TaraSession(sessionId=" + sessionId + ", state=AUTHENTICATION_FAILED, loginRequestInfo=TaraSession.LoginRequestInfo(");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", format("StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, clientNotifyUrl=null, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, subject=null, firstName=null, lastName=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, authenticationSessionId=%s, errorCode=IDC_WEBEID_ERROR)", sessionId));
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
}
