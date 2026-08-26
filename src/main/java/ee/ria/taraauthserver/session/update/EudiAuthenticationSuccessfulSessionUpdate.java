package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.time.LocalDate;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static java.util.Objects.requireNonNull;

/**
 * One subclass per flow, each accepting only its own waiting state, so that a result obtained one way never completes a
 * transaction started another way.
 */
@Getter
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
public abstract sealed class EudiAuthenticationSuccessfulSessionUpdate implements TaraSessionUpdate
        permits EudiWeb2AppAuthenticationSuccessfulSessionUpdate, EudiDcApiAuthenticationSuccessfulSessionUpdate {

    @NonNull private final String idCode;
    @NonNull private final String country;
    @NonNull private final String firstName;
    @NonNull private final String lastName;
    @NonNull private final LocalDate dateOfBirth;
    @NonNull private final LevelOfAssurance levelOfAssurance;

    protected abstract TaraAuthenticationState waitingState();

    @Override
    public final void apply(TaraSession session) {
        SessionUtils.assertSessionInState(session, waitingState());
        TaraSession.AuthenticationResult authenticationResult = requireNonNull(session.getAuthenticationResult());
        if (!(authenticationResult instanceof TaraSession.EudiAuthenticationResult eudiAuthenticationResult)) {
            throw new IllegalStateException(
                    "Cannot mark EUDI wallet authentication as successful, wrong AuthenticationResult type");
        }
        eudiAuthenticationResult.setIdCode(idCode);
        eudiAuthenticationResult.setCountry(country);
        eudiAuthenticationResult.setFirstName(firstName);
        eudiAuthenticationResult.setLastName(lastName);
        eudiAuthenticationResult.setDateOfBirth(dateOfBirth);
        eudiAuthenticationResult.setSubject(country + idCode);
        eudiAuthenticationResult.setAmr(AuthenticationType.EUDI_WALLET);
        eudiAuthenticationResult.setAcr(levelOfAssurance);
        session.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
    }

}
