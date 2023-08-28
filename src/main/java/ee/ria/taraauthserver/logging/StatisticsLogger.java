package ee.ria.taraauthserver.logging;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.config.properties.TaraScope;
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

import java.util.Objects;
import java.util.Optional;

import static ee.ria.taraauthserver.error.ErrorCode.INTERNAL_ERROR;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WEBAUTHN_AUTHENTICATION_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_FAILED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.WEBAUTHN_AUTHENTICATION_SUCCESS;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.EXTERNAL_TRANSACTION;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_MID_STATUS_CANCELED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_STATUS_CANCELED;
import static java.util.Optional.empty;
import static java.util.Optional.of;
import static net.logstash.logback.marker.Markers.appendFields;

@Slf4j
@Component
public class StatisticsLogger {

    public static final String SERVICE_GOVSSO = "GOVSSO";

    public void log(TaraSession taraSession) {
        log(taraSession, null);
    }

    public void log(TaraSession taraSession, Exception ex) {
        if (taraSession != null && taraSession.getLoginRequestInfo() != null) {
            getStateToLog(taraSession)
                    .ifPresent(state -> log(taraSession, state, ex));
        }
    }

    public void logExternalTransaction(TaraSession taraSession) {
        log(taraSession, EXTERNAL_TRANSACTION, null);
    }

    public void logExternalTransaction(TaraSession taraSession, Exception ex) {
        log(taraSession, EXTERNAL_TRANSACTION, ex);
    }

    private void log(TaraSession taraSession, TaraAuthenticationState state, Exception ex) {
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
    }

    private void processAuthenticationRequest(TaraSession taraSession, TaraAuthenticationState state, SessionStatisticsBuilder statisticsBuilder) {
        LoginRequestInfo taraLoginRequestInfo = taraSession.getLoginRequestInfo();
        LoginRequestInfo govSsoLoginRequestInfo = taraSession.getGovSsoLoginRequestInfo();

        statisticsBuilder
                .authenticationState(state)
                .legalPerson(taraSession.getSelectedLegalPerson() != null);

        if (taraSession.getAuthenticationResult() != null
                && isEidasAuthentication(taraSession)
                && isPrivateSectorRequest(taraLoginRequestInfo)
                && taraLoginRequestInfo.getOidcClient().isPresent()) {
            statisticsBuilder.eidasRequesterId(Objects.toString(taraLoginRequestInfo.getOidcClient().get().getEidasRequesterId(), null));
        }

        if (taraSession.getAuthenticationResult() != null && taraLoginRequestInfo.getOidcClient().isPresent()) {
            statisticsBuilder.clientNotifyUrl(Objects.toString(taraLoginRequestInfo.getOidcClient().get().getNotifyUrl(), null));
        }

        if (govSsoLoginRequestInfo != null) {
            statisticsBuilder
                    .service(SERVICE_GOVSSO)
                    .clientId(govSsoLoginRequestInfo.getClientId());
            govSsoLoginRequestInfo.getInstitution().ifPresent(i -> {
                statisticsBuilder.registryCode(i.getRegistryCode());
                statisticsBuilder.sector(i.getSector().toString());
            });
        } else {
            statisticsBuilder
                    .clientId(taraLoginRequestInfo.getClientId());
            taraLoginRequestInfo.getInstitution().ifPresent(i -> {
                statisticsBuilder.registryCode(i.getRegistryCode());
                statisticsBuilder.sector(i.getSector().toString());
            });
        }
    }

    private boolean isEidasAuthentication(TaraSession taraSession) {
        return taraSession.getAuthenticationResult().getAmr() != null
                && taraSession.getAuthenticationResult().getAmr().getScope() == TaraScope.EIDAS;
    }

    private boolean isPrivateSectorRequest(LoginRequestInfo taraLoginRequestInfo) {
        return taraLoginRequestInfo.getInstitution().isPresent()
                && taraLoginRequestInfo.getInstitution().get().getSector() == SPType.PRIVATE;
    }

    private void processAuthenticationResult(TaraSession taraSession, Exception ex, SessionStatisticsBuilder sessionStatisticsBuilder) {
        AuthenticationResult authenticationResult = taraSession.getAuthenticationResult();
        LegalPerson selectedLegalPerson = taraSession.getSelectedLegalPerson();
        if (authenticationResult != null) {
            String idCode = selectedLegalPerson == null ? authenticationResult.getIdCode() : selectedLegalPerson.getLegalPersonIdentifier();
            sessionStatisticsBuilder
                    .country(authenticationResult.getCountry())
                    .idCode(idCode)
                    .subject(authenticationResult.getSubject())
                    .authenticationType(authenticationResult.getAmr())
                    .authenticationSessionId(taraSession.getSessionId())
                    .firstName(authenticationResult.getFirstName())
                    .lastName(authenticationResult.getLastName())
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
        if (AUTHENTICATION_SUCCESS == state || WEBAUTHN_AUTHENTICATION_SUCCESS == state) {
            return of(AUTHENTICATION_SUCCESS);
        } else if (AUTHENTICATION_FAILED == state) {
            return of(state);
        } else if (AUTHENTICATION_CANCELED == state || WEBAUTHN_AUTHENTICATION_CANCELED == state || POLL_MID_STATUS_CANCELED == state || POLL_SID_STATUS_CANCELED == state) {
            return of(AUTHENTICATION_CANCELED);
        } else {
            return empty();
        }
    }

    @Builder
    @Data
    public static class SessionStatistics {

        @JsonProperty("client.service")
        private String service;

        @JsonProperty("client.id")
        private String clientId;

        @JsonProperty("client.notify_url")
        private String clientNotifyUrl;

        @JsonProperty("client.eidas_requester_id")
        private String eidasRequesterId;

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

        @JsonProperty("authentication.subject")
        private String subject;

        @JsonProperty("authentication.first_name")
        private String firstName;

        @JsonProperty("authentication.last_name")
        private String lastName;

        @JsonProperty("authentication.ocsp_url")
        private String ocspUrl;

        @JsonProperty("authentication.type")
        private AuthenticationType authenticationType;

        @JsonProperty("authentication.state")
        private TaraAuthenticationState authenticationState;

        @JsonProperty("authentication.session_id")
        private String authenticationSessionId;

        @JsonProperty("authentication.error_code")
        private ErrorCode errorCode;
    }
}
