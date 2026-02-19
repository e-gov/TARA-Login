package ee.ria.taraauthserver.authentication.smartid.web2app;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.DeviceLinkAuthenticationResponseValidator;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.SessionStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_SECONDS;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasProperty;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.when;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.auth-methods.eidas.enabled=false"}) // Disabled to avoid EIDAS /supportedCountries API call
class SmartIdWeb2AppControllerTest extends BaseTest {

    // Base64URL-without-padding of SHA-256(Base64Decode("dGVzdC1zZWNyZXQ"))
    // where "dGVzdC1zZWNyZXQ" is the sessionSecret from sid_device_link_init_response.json
    private static final String SESSION_SECRET_DIGEST = "nK8Gu0Q2zb-iCvkSGmJrwQk8T1SzHA-pN5V4VhNTRbY";

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @MockitoBean
    private DeviceLinkAuthenticationResponseValidator responseValidator;

    @Test
    void sidWeb2AppCallbackPoll_countryAllowed_authenticationSucceeds() {
        createDeviceLinkAuthInitStub();
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        mockDeviceLinkAuthenticationResponseValidator("EE");
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .chosenLanguage("et")
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/sid/web2app/init")
                .then()
                .assertThat()
                .statusCode(200);
        TaraSession taraSessionAfterPoll = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION),
                        hasProperty("state", equalTo(POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED)));
        String urlToken = taraSessionAfterPoll.getSmartIdWeb2AppSession().getUrlToken();
        given()
                .filter(sessionFilter)
                .queryParam("value", urlToken)
                .queryParam("sessionSecretDigest", SESSION_SECRET_DIGEST)
                .queryParam("userChallengeVerifier", "test-verifier")
                .when()
                .get("/auth/sid/web2app/callback/poll")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("COMPLETED"));

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(NATURAL_PERSON_AUTHENTICATION_COMPLETED, taraSession.getState());
        TaraSession.SidAuthenticationResult result = (TaraSession.SidAuthenticationResult) taraSession.getAuthenticationResult();
        assertEquals("EE", result.getCountry());
        assertEquals("38001085718", result.getIdCode());
        assertEquals("Jaak-Kristjan", result.getFirstName());
        assertEquals("Jõeorg", result.getLastName());
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: EXTERNAL_TRANSACTION",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=38001085718, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=null, smartIdFlowType=WEB2APP)");
    }

    @Test
    void sidWeb2AppCallbackPoll_countryNotAllowed_authenticationFails() {
        createDeviceLinkAuthInitStub();
        createSidApiPollStub("mock_responses/sid/sid_poll_response_ok.json", 200);
        mockDeviceLinkAuthenticationResponseValidator("LV");
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .chosenLanguage("et")
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_AUTH_PROCESS).build();

        given()
                .filter(sessionFilter)
                .when()
                .post("/auth/sid/web2app/init")
                .then()
                .assertThat()
                .statusCode(200);
        TaraSession taraSessionAfterPoll = await().atMost(FIVE_SECONDS)
                .until(() -> sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION),
                        hasProperty("state", equalTo(POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED)));
        String urlToken = taraSessionAfterPoll.getSmartIdWeb2AppSession().getUrlToken();
        given()
                .filter(sessionFilter)
                .queryParam("value", urlToken)
                .queryParam("sessionSecretDigest", SESSION_SECRET_DIGEST)
                .queryParam("userChallengeVerifier", "test-verifier")
                .when()
                .get("/auth/sid/web2app/callback/poll")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("COMPLETED"));

        TaraSession taraSession = sessionRepository.findById(sessionFilter.getSession().getId()).getAttribute(TARA_SESSION);
        assertEquals(AUTHENTICATION_FAILED, taraSession.getState());
        assertEquals(ee.ria.taraauthserver.error.ErrorCode.SID_COUNTRY_NOT_ALLOWED,
                taraSession.getAuthenticationResult().getErrorCode());
        assertWarningIsLogged("Smart-ID authentication failed: Smart-ID authentication is not allowed for country: LV, Error code: SID_COUNTRY_NOT_ALLOWED");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=AUTHENTICATION_FAILED, errorCode=SID_COUNTRY_NOT_ALLOWED, smartIdFlowType=WEB2APP)");
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: EXTERNAL_TRANSACTION",
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=SMART_ID, authenticationState=EXTERNAL_TRANSACTION, errorCode=SID_COUNTRY_NOT_ALLOWED, smartIdFlowType=WEB2APP)");
    }

    private void createDeviceLinkAuthInitStub() {
        wireMockServer.stubFor(any(urlPathEqualTo("/smart-id-rp/v3/authentication/device-link/anonymous"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(200)
                        .withBodyFile("mock_responses/sid/sid_device_link_init_response.json")));
    }

    private void mockDeviceLinkAuthenticationResponseValidator(String country) {
        AuthenticationIdentity authenticationIdentity = new AuthenticationIdentity();
        authenticationIdentity.setCountry(country);
        authenticationIdentity.setIdentityNumber("38001085718");
        authenticationIdentity.setGivenName("Jaak-Kristjan");
        authenticationIdentity.setSurname("Jõeorg");
        when(responseValidator.validate(
                any(SessionStatus.class),
                any(DeviceLinkAuthenticationSessionRequest.class),
                nullable(String.class),
                any(String.class)
        )).thenReturn(authenticationIdentity);
    }
}
