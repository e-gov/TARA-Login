package ee.ria.taraauthserver.logging;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.TaraException;
import ee.ria.taraauthserver.logging.StatisticsLogger.SessionStatistics.SessionStatisticsBuilder;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraSession.AuthenticationResult;
import ee.ria.taraauthserver.session.TaraSession.LegalPerson;
import ee.ria.taraauthserver.session.TaraSession.LoginRequestInfo;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Optional;

import static ee.ria.taraauthserver.error.ErrorCode.INTERNAL_ERROR;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_MID_STATUS_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_STATUS_CANCELED;
import static java.util.Optional.empty;
import static java.util.Optional.of;
import static net.logstash.logback.marker.Markers.appendFields;

@Slf4j
@Component
public class StatisticsLogger {
    public void log(TaraSession taraSession) {
        log(taraSession, null);
    }

    public void log(TaraSession taraSession, Exception ex) {
        if (taraSession != null && taraSession.getLoginRequestInfo() != null) {
            getStateToLog(taraSession)
                    .ifPresent(state -> {
                        SessionStatisticsBuilder statisticsBuilder = SessionStatistics.builder();
                        processAuthenticationRequest(taraSession, state, statisticsBuilder);
                        processAuthenticationResult(taraSession, ex, statisticsBuilder);
                        SessionStatistics sessionStatistics = statisticsBuilder.build();
                        if (ex != null) {
                            log.error(appendFields(sessionStatistics), "Authentication result: " + state, ex);
                        } else if (taraSession.getAuthenticationResult() != null
                                && taraSession.getAuthenticationResult().getErrorCode() != null) {
                            log.error(appendFields(sessionStatistics), "Authentication result: {}", state);
                        } else {
                            log.info(appendFields(sessionStatistics), "Authentication result: {}", state);
                        }
                    });
        }
    }

    private void processAuthenticationRequest(TaraSession taraSession, TaraAuthenticationState state, SessionStatisticsBuilder statisticsBuilder) {
        LoginRequestInfo loginRequestInfo = taraSession.getLoginRequestInfo();
        LegalPerson selectedLegalPerson = taraSession.getSelectedLegalPerson();
        statisticsBuilder
                .clientId(loginRequestInfo.getClientId())
                .authenticationState(state)
                .legalPerson(selectedLegalPerson != null);
        loginRequestInfo.getInstitution().ifPresent(i -> {
            statisticsBuilder.registryCode(i.getRegistryCode());
            statisticsBuilder.sector(i.getSector().toString());
        });
    }

    private void processAuthenticationResult(TaraSession taraSession, Exception ex, SessionStatisticsBuilder sessionStatisticsBuilder) {
        AuthenticationResult authenticationResult = taraSession.getAuthenticationResult();
        LegalPerson selectedLegalPerson = taraSession.getSelectedLegalPerson();
        if (authenticationResult != null) {
            String idCode = selectedLegalPerson == null ? authenticationResult.getIdCode() : selectedLegalPerson.getLegalPersonIdentifier();
            sessionStatisticsBuilder
                    .country(authenticationResult.getCountry())
                    .idCode(idCode)
                    .authenticationType(authenticationResult.getAmr())
                    .errorCode(authenticationResult.getErrorCode());
            if (authenticationResult.getAmr() == AuthenticationType.ID_CARD) {
                sessionStatisticsBuilder.ocspUrl(((TaraSession.IdCardAuthenticationResult) authenticationResult).getOcspUrl());
            }
        } else if (taraSession.getState() == AUTHENTICATION_FAILED) {
            if (ex instanceof TaraException) {
                sessionStatisticsBuilder.errorCode(((TaraException) ex).getErrorCode());
            } else {
                sessionStatisticsBuilder.errorCode(INTERNAL_ERROR);
            }
        }
    }

    private Optional<TaraAuthenticationState> getStateToLog(TaraSession taraSession) {
        TaraAuthenticationState state = taraSession.getState();
        if (AUTHENTICATION_SUCCESS == state || AUTHENTICATION_FAILED == state) {
            return of(state);
        } else if (AUTHENTICATION_CANCELED == state || POLL_MID_STATUS_CANCELED == state || POLL_SID_STATUS_CANCELED == state) {
            return of(AUTHENTICATION_CANCELED);
        } else {
            return empty();
        }
    }

    @Builder
    @Data
    public static class SessionStatistics {
        @JsonProperty("client.id")
        private String clientId;

        @JsonProperty("institution.sector")
        private String sector;

        @JsonProperty("institution.registry_code")
        private String registryCode;

        @JsonProperty("authentication.legal_person")
        private boolean legalPerson;

        @JsonProperty("authentication.country")
        private String country;

        @JsonProperty("authentication.id_code")
        private String idCode;

        @JsonProperty("authentication.ocsp_url")
        private String ocspUrl;

        @JsonProperty("authentication.type")
        private AuthenticationType authenticationType;

        @JsonProperty("authentication.state")
        private TaraAuthenticationState authenticationState;

        @JsonProperty("authentication.error_code")
        private ErrorCode errorCode;
    }
}
