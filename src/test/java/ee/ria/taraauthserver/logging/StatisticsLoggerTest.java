package ee.ria.taraauthserver.logging;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.*;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.ObjectFieldsAppendingMarker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.UUID;

import static ch.qos.logback.classic.Level.INFO;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.ID_CARD;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.error.ErrorCode.INTERNAL_ERROR;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Slf4j
class StatisticsLoggerTest extends BaseTest {

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

        assertMessageNotIsLogged(StatisticsLogger.class, "Authentication result: " + state.name());
    }

    @ParameterizedTest
    @EnumSource(value = TaraAuthenticationState.class)
    void eventNotLoggedWhen_NoLoginRequestInfo(TaraAuthenticationState state) {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setState(state);
        taraSession.setLoginRequestInfo(null);
        statisticsLogger.log(taraSession);
        assertMessageNotIsLogged(StatisticsLogger.class, "Authentication result: " + state.name());
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
        ObjectFieldsAppendingMarker statisticsMarker = assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, INFO, format("Authentication result: %s", state.name()));
        assertEquals(format("StatisticsLogger.SessionStatistics(clientId=test_client_id, sector=test_sector, registryCode=test_registry_code, legalPerson=false, country=null, " +
                        "idCode=null, ocspUrl=null, authenticationType=null, authenticationState=%s, errorCode=null)", expectedState.name()),
                statisticsMarker.toStringSelf());
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
        ObjectFieldsAppendingMarker statisticsMarker = assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, INFO, format("Authentication result: %s", state.name()));
        assertEquals(format("StatisticsLogger.SessionStatistics(clientId=test_client_id, sector=test_sector, registryCode=test_registry_code, legalPerson=false, country=EE, " +
                        "idCode=test_person_id_code, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=%s, errorCode=null)", expectedState.name()),
                statisticsMarker.toStringSelf());
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
        ObjectFieldsAppendingMarker statisticsMarker = assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, INFO, format("Authentication result: %s", state.name()));
        assertEquals(format("StatisticsLogger.SessionStatistics(clientId=test_client_id, sector=test_sector, registryCode=test_registry_code, legalPerson=false, country=EE, " +
                        "idCode=test_person_id_code, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=%s, errorCode=INTERNAL_ERROR)", expectedState.name()),
                statisticsMarker.toStringSelf());
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

        ObjectFieldsAppendingMarker statisticsMarker = assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, INFO, "Authentication result: AUTHENTICATION_SUCCESS");
        assertEquals("StatisticsLogger.SessionStatistics(clientId=test_client_id, sector=test_sector, registryCode=test_registry_code, legalPerson=false, country=EE, " +
                        "idCode=test_person_id_code, ocspUrl=https://test-ocsp, authenticationType=ID_CARD, authenticationState=AUTHENTICATION_SUCCESS, errorCode=null)",
                statisticsMarker.toStringSelf());
    }

    @Test
    void eventWithLegalpersonIdCodeLoggedWhen_LegalPersonSelected() {
        TaraSession taraSession = buildValidSessionWithoutState();
        taraSession.setState(AUTHENTICATION_SUCCESS);
        LegalPerson legalPerson = new LegalPerson("test_legal_person", "test_legal_person_id_code");
        taraSession.setSelectedLegalPerson(legalPerson);
        statisticsLogger.log(taraSession);

        ObjectFieldsAppendingMarker statisticsMarker = assertMessageWithMarkerIsLoggedOnce(StatisticsLogger.class, INFO, "Authentication result: AUTHENTICATION_SUCCESS");
        assertEquals("StatisticsLogger.SessionStatistics(clientId=test_client_id, sector=test_sector, registryCode=test_registry_code, legalPerson=true, country=EE, " +
                        "idCode=test_legal_person_id_code, ocspUrl=null, authenticationType=MOBILE_ID, authenticationState=AUTHENTICATION_SUCCESS, errorCode=null)",
                statisticsMarker.toStringSelf());
    }

    private TaraSession buildValidSessionWithoutState() {
        LoginRequestInfo loginRequestInfo = new LoginRequestInfo();
        Client client = new Client();
        client.setClientId("test_client_id");
        MetaData metaData = new MetaData();
        OidcClient oidcClient = new OidcClient();
        Institution institution = new Institution();
        institution.setSector("test_sector");
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