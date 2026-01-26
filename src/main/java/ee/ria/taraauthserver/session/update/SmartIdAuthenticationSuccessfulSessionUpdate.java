package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import ee.sk.smartid.AuthenticationIdentity;
import lombok.Value;

import java.util.Set;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_QR_CODE;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED;
import static java.util.Objects.requireNonNull;

@Value
public class SmartIdAuthenticationSuccessfulSessionUpdate implements TaraSessionUpdate {

    private final AuthenticationIdentity authenticationIdentity;
    private final LevelOfAssurance levelOfAssurance;

    @Override
    public void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, Set.of(POLL_SID_QR_CODE, POLL_SID_WEB2APP_STATUS_AFTER_FINAL_STATUS_RECEIVED));
        TaraSession.AuthenticationResult authenticationResult = requireNonNull(session.getAuthenticationResult());
        if (!(authenticationResult instanceof TaraSession.SidAuthenticationResult sidAuthenticationResult)) {
            throw new IllegalStateException(
                    "Cannot mark Smart-ID authentication as successful, wrong AuthenticationResult type");
        }
        sidAuthenticationResult.setIdCode(authenticationIdentity.getIdentityNumber());
        sidAuthenticationResult.setCountry(authenticationIdentity.getCountry());
        sidAuthenticationResult.setFirstName(authenticationIdentity.getGivenName());
        sidAuthenticationResult.setLastName(authenticationIdentity.getSurname());
        sidAuthenticationResult.setSubject(
                authenticationIdentity.getCountry() + authenticationIdentity.getIdentityNumber());
        sidAuthenticationResult.setDateOfBirth(
                MidNationalIdentificationCodeValidator.getBirthDate(authenticationIdentity.getIdentityNumber()));
        sidAuthenticationResult.setAmr(AuthenticationType.SMART_ID);
        sidAuthenticationResult.setAcr(levelOfAssurance);
        session.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
    }

}
