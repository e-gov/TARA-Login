package ee.ria.taraauthserver.logging;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.AuthenticationResult;
import ee.ria.taraauthserver.session.TaraSession.Client;
import ee.ria.taraauthserver.session.TaraSession.IdCardAuthenticationResult;
import ee.ria.taraauthserver.session.TaraSession.Institution;
import ee.ria.taraauthserver.session.TaraSession.LegalPerson;
import ee.ria.taraauthserver.session.TaraSession.LoginRequestInfo;
import ee.ria.taraauthserver.session.TaraSession.MetaData;
import ee.ria.taraauthserver.session.TaraSession.OidcClient;
import ee.ria.taraauthserver.logging.StatisticsLogger.SessionStatistics;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.UUID;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.EIDAS;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.ID_CARD;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static ee.ria.taraauthserver.error.ErrorCode.INTERNAL_ERROR;
import static ee.ria.taraauthserver.logging.StatisticsLogger.SERVICE_GOVSSO;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_MID_STATUS_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_STATUS_CANCELED;
import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class StatisticsLoggerTest extends BaseTest {
    public static final String TEST_REQUESTER_ID = "urn:uuid:80e48e38-e5a5-11ec-acbb-ff7824b5b847";

    @Autowired
    private StatisticsLogger statisticsLogger;

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILED", "AUTHENTICATION_CANCELED", "POLL_MID_STATUS_CANCELED", "POLL_SID_STATUS_CANCELED"},
            mode = EnumSource.Mode.EXCLUDE)
    void eventNotLoggedWhen_InvalidState(TaraAuthenticationState state) {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setState(state);

        statisticsLogger.log(taraSession);

        assertMessageIsNotLogged(StatisticsLogger.class, "Authentication result: " + state.name());
    }

    @ParameterizedTest
    @EnumSource(value = TaraAuthenticationState.class)
    void eventNotLoggedWhen_NoLoginRequestInfo(TaraAuthenticationState state) {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setState(state);
        taraSession.setLoginRequestInfo(null);

        statisticsLogger.log(taraSession);

        assertMessageIsNotLogged(StatisticsLogger.class, "Authentication result: " + state.name());
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILED", "AUTHENTICATION_CANCELED", "POLL_MID_STATUS_CANCELED", "POLL_SID_STATUS_CANCELED"},
            mode = EnumSource.Mode.INCLUDE)
    void eventLoggedWhen_NoAuthenticationResult(TaraAuthenticationState state) {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setState(state);
        taraSession.setAuthenticationResult(null);

        statisticsLogger.log(taraSession);

        TaraAuthenticationState expectedState = (state == POLL_MID_STATUS_CANCELED || state == POLL_SID_STATUS_CANCELED) ? AUTHENTICATION_CANCELED : state;
        if (state == AUTHENTICATION_FAILED) {
            assertStatisticsIsLoggedOnce(INFO, format("Authentication result: %s", expectedState.name()),
                    defaultStatisticsMarkerBuilder()
                            .clientId("test_client_id")
                            .sector("public")
                            .registryCode("test_registry_code")
                            .authenticationState(expectedState)
                            .errorCode(INTERNAL_ERROR)
                            .build());
        } else {
            assertStatisticsIsLoggedOnce(INFO, format("Authentication result: %s", expectedState.name()),
                    defaultStatisticsMarkerBuilder()
                            .clientId("test_client_id")
                            .sector("public")
                            .registryCode("test_registry_code")
                            .authenticationState(expectedState)
                            .build());
        }
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILED", "AUTHENTICATION_CANCELED", "POLL_MID_STATUS_CANCELED", "POLL_SID_STATUS_CANCELED"},
            mode = EnumSource.Mode.INCLUDE)
    void eventLoggedWhen_ValidState(TaraAuthenticationState state) {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setState(state);

        statisticsLogger.log(taraSession);

        TaraAuthenticationState expectedState = (state == POLL_MID_STATUS_CANCELED || state == POLL_SID_STATUS_CANCELED) ? AUTHENTICATION_CANCELED : state;
        assertStatisticsIsLoggedOnce(INFO, format("Authentication result: %s", expectedState.name()),
                defaultStatisticsMarkerBuilder()
                        .clientId("test_client_id")
                        .sector("public")
                        .registryCode("test_registry_code")
                        .country("EE")
                        .idCode("test_person_id_code")
                        .authenticationType(MOBILE_ID)
                        .authenticationState(expectedState)
                        .build());
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILED", "AUTHENTICATION_CANCELED", "POLL_MID_STATUS_CANCELED", "POLL_SID_STATUS_CANCELED"},
            mode = EnumSource.Mode.INCLUDE)
    void requesterIdLoggedWhen_EidasPrivateSectorRequest(TaraAuthenticationState state) throws URISyntaxException {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.getLoginRequestInfo().getOidcClient().get().setEidasRequesterId(new URI(TEST_REQUESTER_ID));
        taraSession.getLoginRequestInfo().getInstitution().get().setSector(SPType.PRIVATE);
        taraSession.getAuthenticationResult().setAmr(EIDAS);
        taraSession.setState(state);

        statisticsLogger.log(taraSession);

        TaraAuthenticationState expectedState = (state == POLL_MID_STATUS_CANCELED || state == POLL_SID_STATUS_CANCELED) ? AUTHENTICATION_CANCELED : state;
        assertStatisticsIsLoggedOnce(INFO, format("Authentication result: %s", expectedState.name()),
                defaultStatisticsMarkerBuilder()
                        .clientId("test_client_id")
                        .eidasRequesterId(TEST_REQUESTER_ID)
                        .sector("private")
                        .registryCode("test_registry_code")
                        .country("EE")
                        .idCode("test_person_id_code")
                        .authenticationType(EIDAS)
                        .authenticationState(expectedState)
                        .build());
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILED", "AUTHENTICATION_CANCELED", "POLL_MID_STATUS_CANCELED", "POLL_SID_STATUS_CANCELED"},
            mode = EnumSource.Mode.INCLUDE)
    void requesterIdNullWhen_EidasPublicSectorRequest(TaraAuthenticationState state) throws URISyntaxException {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.getLoginRequestInfo().getOidcClient().get().setEidasRequesterId(new URI(TEST_REQUESTER_ID));
        taraSession.getAuthenticationResult().setAmr(EIDAS);
        taraSession.setState(state);

        statisticsLogger.log(taraSession);

        TaraAuthenticationState expectedState = (state == POLL_MID_STATUS_CANCELED || state == POLL_SID_STATUS_CANCELED) ? AUTHENTICATION_CANCELED : state;
        assertStatisticsIsLoggedOnce(INFO, format("Authentication result: %s", expectedState.name()),
                defaultStatisticsMarkerBuilder()
                        .clientId("test_client_id")
                        .sector("public")
                        .registryCode("test_registry_code")
                        .country("EE")
                        .idCode("test_person_id_code")
                        .authenticationType(EIDAS)
                        .authenticationState(expectedState)
                        .build());
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILED", "AUTHENTICATION_CANCELED", "POLL_MID_STATUS_CANCELED", "POLL_SID_STATUS_CANCELED"},
            mode = EnumSource.Mode.INCLUDE)
    void requesterIdNullWhen_NonEidasPrivateSectorRequest(TaraAuthenticationState state) throws URISyntaxException {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.getLoginRequestInfo().getOidcClient().get().setEidasRequesterId(new URI(TEST_REQUESTER_ID));
        taraSession.getLoginRequestInfo().getInstitution().get().setSector(SPType.PRIVATE);
        taraSession.getAuthenticationResult().setAmr(SMART_ID);
        taraSession.setState(state);

        statisticsLogger.log(taraSession);

        TaraAuthenticationState expectedState = (state == POLL_MID_STATUS_CANCELED || state == POLL_SID_STATUS_CANCELED) ? AUTHENTICATION_CANCELED : state;
        assertStatisticsIsLoggedOnce(INFO, format("Authentication result: %s", expectedState.name()),
                defaultStatisticsMarkerBuilder()
                        .clientId("test_client_id")
                        .sector("private")
                        .registryCode("test_registry_code")
                        .country("EE")
                        .idCode("test_person_id_code")
                        .authenticationType(SMART_ID)
                        .authenticationState(expectedState)
                        .build());
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILED", "AUTHENTICATION_CANCELED", "POLL_MID_STATUS_CANCELED", "POLL_SID_STATUS_CANCELED"},
            mode = EnumSource.Mode.INCLUDE)
    void eventLoggedWithErrorCode(TaraAuthenticationState state) {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setState(state);
        taraSession.getAuthenticationResult().setErrorCode(INTERNAL_ERROR);

        statisticsLogger.log(taraSession);

        TaraAuthenticationState expectedState = (state == POLL_MID_STATUS_CANCELED || state == POLL_SID_STATUS_CANCELED) ? AUTHENTICATION_CANCELED : state;
        assertStatisticsIsLoggedOnce(ERROR, format("Authentication result: %s", expectedState.name()),
                defaultStatisticsMarkerBuilder()
                        .clientId("test_client_id")
                        .sector("public")
                        .registryCode("test_registry_code")
                        .country("EE")
                        .idCode("test_person_id_code")
                        .authenticationType(MOBILE_ID)
                        .authenticationState(expectedState)
                        .errorCode(INTERNAL_ERROR)
                        .build());
    }

    @Test
    void eventWithOcspUrlLoggedWhen_IdCardAuthenticationResult() {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setState(AUTHENTICATION_SUCCESS);
        IdCardAuthenticationResult authenticationResult = new IdCardAuthenticationResult();
        authenticationResult.setIdCode("test_person_id_code");
        authenticationResult.setAmr(ID_CARD);
        authenticationResult.setOcspUrl("https://test-ocsp");
        taraSession.setAuthenticationResult(authenticationResult);

        statisticsLogger.log(taraSession);

        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_SUCCESS",
                defaultStatisticsMarkerBuilder()
                .clientId("test_client_id")
                .sector("public")
                .registryCode("test_registry_code")
                .country("EE")
                .idCode("test_person_id_code")
                .ocspUrl("https://test-ocsp")
                .authenticationType(ID_CARD)
                .authenticationState(AUTHENTICATION_SUCCESS)
                .build());
    }

    @Test
    void eventWithLegalpersonIdCodeLoggedWhen_LegalPersonSelected() {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setState(AUTHENTICATION_SUCCESS);
        LegalPerson legalPerson = new LegalPerson("test_legal_person", "test_legal_person_id_code");
        taraSession.setSelectedLegalPerson(legalPerson);

        statisticsLogger.log(taraSession);

        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_SUCCESS",
                defaultStatisticsMarkerBuilder()
                .clientId("test_client_id")
                .sector("public")
                .registryCode("test_registry_code")
                .legalPerson(true)
                .country("EE")
                .idCode("test_legal_person_id_code")
                .authenticationType(MOBILE_ID)
                .authenticationState(AUTHENTICATION_SUCCESS)
                .build());
    }

    @ParameterizedTest
    @EnumSource(
            value = TaraAuthenticationState.class,
            names = {"AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILED", "AUTHENTICATION_CANCELED", "POLL_MID_STATUS_CANCELED", "POLL_SID_STATUS_CANCELED"},
            mode = EnumSource.Mode.INCLUDE)
    void eventWithServiceNameLoggedWhen_GovSsoLoginRequestInfoIsSet(TaraAuthenticationState state) {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setState(state);
        LoginRequestInfo loginRequestInfo = new LoginRequestInfo();
        Client client = new Client();
        String expectedClientId = "govsso_test_client_id";
        String expectedRegistryCode = "govsso_test_registry_code";
        SPType expectedSector = SPType.PRIVATE;
        client.setClientId(expectedClientId);
        MetaData metaData = new MetaData();
        OidcClient oidcClient = new OidcClient();
        Institution institution = new Institution();
        institution.setSector(expectedSector);
        institution.setRegistryCode(expectedRegistryCode);
        oidcClient.setInstitution(institution);
        metaData.setOidcClient(oidcClient);
        client.setMetaData(metaData);
        loginRequestInfo.setClient(client);
        taraSession.setGovSsoLoginRequestInfo(loginRequestInfo);

        statisticsLogger.log(taraSession);

        TaraAuthenticationState expectedState = (state == POLL_MID_STATUS_CANCELED || state == POLL_SID_STATUS_CANCELED) ? AUTHENTICATION_CANCELED : state;
        assertStatisticsIsLoggedOnce(INFO, format("Authentication result: %s", expectedState.name()),
                defaultStatisticsMarkerBuilder()
                        .service(SERVICE_GOVSSO)
                        .clientId(expectedClientId)
                        .sector(expectedSector.toString())
                        .registryCode(expectedRegistryCode)
                        .country("EE")
                        .idCode("test_person_id_code")
                        .authenticationType(MOBILE_ID)
                        .authenticationState(expectedState)
                        .build());
    }

    @Test
    void sessionStatistics_toString_producesExpectedLiteralFormat() {
        SessionStatistics statistics = SessionStatistics.builder()
                .clientId("openIdDemo")
                .clientName("client name")
                .clientShortName("client shortname")
                .sector("public")
                .registryCode("10001234")
                .country("EE")
                .idCode("38001085718")
                .authenticationType(MOBILE_ID)
                .authenticationState(AUTHENTICATION_SUCCESS)
                .build();

        assertEquals(
                "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, " +
                        "clientName=client name, clientShortName=client shortname, eidasRequesterId=null, " +
                        "sector=public, registryCode=10001234, legalPerson=false, country=EE, " +
                        "idCode=38001085718, ocspUrl=null, authenticationType=MOBILE_ID, " +
                        "authenticationState=AUTHENTICATION_SUCCESS, errorCode=null, " +
                        "smartIdFlowType=null, flowDuration=null)",
                statistics.toString());
    }

    @Test
    void processFlowDuration_logsErrorAndOmitsDuration_whenStartTimeSetButEndTimeNull() {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setAuthFlowStartTime(Instant.parse("2025-01-01T00:00:00Z"));
        taraSession.setState(AUTHENTICATION_SUCCESS);

        statisticsLogger.log(taraSession);

        assertErrorIsLogged(StatisticsLogger.class, "authFlowEndTime not set before statistics logging for session");
        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_SUCCESS",
                defaultStatisticsMarkerBuilder()
                        .clientId("test_client_id")
                        .sector("public")
                        .registryCode("test_registry_code")
                        .country("EE")
                        .idCode("test_person_id_code")
                        .authenticationType(MOBILE_ID)
                        .authenticationState(AUTHENTICATION_SUCCESS)
                        .build());
    }

    @Test
    void processFlowDuration_omitsDurationSilently_whenOnlyEndTimeSet() {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setAuthFlowEndTime(Instant.parse("2025-01-01T00:00:00Z"));
        taraSession.setState(AUTHENTICATION_SUCCESS);

        statisticsLogger.log(taraSession);

        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_SUCCESS",
                defaultStatisticsMarkerBuilder()
                        .clientId("test_client_id")
                        .sector("public")
                        .registryCode("test_registry_code")
                        .country("EE")
                        .idCode("test_person_id_code")
                        .authenticationType(MOBILE_ID)
                        .authenticationState(AUTHENTICATION_SUCCESS)
                        .build());
    }

    @Test
    void processFlowDuration_calculatesCorrectDuration_whenBothTimesSet() {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setAuthFlowStartTime(Instant.parse("2025-01-01T00:00:00Z"));
        taraSession.setAuthFlowEndTime(Instant.parse("2025-01-01T00:00:00.500Z"));
        taraSession.setState(AUTHENTICATION_SUCCESS);

        statisticsLogger.log(taraSession);

        assertStatisticsIsLoggedOnce(INFO, "Authentication result: AUTHENTICATION_SUCCESS",
                defaultStatisticsMarkerBuilder()
                        .clientId("test_client_id")
                        .sector("public")
                        .registryCode("test_registry_code")
                        .country("EE")
                        .idCode("test_person_id_code")
                        .authenticationType(MOBILE_ID)
                        .authenticationState(AUTHENTICATION_SUCCESS)
                        .flowDuration(500L)
                        .build());
    }

    private TaraSession buildValidSessionWithoutState() {
        LoginRequestInfo loginRequestInfo = new LoginRequestInfo();
        Client client = new Client();
        client.setClientId("test_client_id");
        MetaData metaData = new MetaData();
        OidcClient oidcClient = new OidcClient();
        Institution institution = new Institution();
        institution.setSector(SPType.PUBLIC);
        institution.setRegistryCode("test_registry_code");
        oidcClient.setInstitution(institution);
        metaData.setOidcClient(oidcClient);
        client.setMetaData(metaData);
        loginRequestInfo.setClient(client);

        AuthenticationResult authenticationResult = new AuthenticationResult();
        authenticationResult.setIdCode("test_person_id_code");
        authenticationResult.setAmr(MOBILE_ID);

        TaraSession taraSession = new TaraSession(UUID.randomUUID().toString());
        taraSession.setLoginRequestInfo(loginRequestInfo);
        taraSession.setAuthenticationResult(authenticationResult);
        return taraSession;
    }
}
