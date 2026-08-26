package ee.ria.taraauthserver.session.update;

import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.session.TaraAuthenticationState;

import java.time.LocalDate;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.WAITING_EUDI_DC_API_RESPONSE;

public final class EudiDcApiAuthenticationSuccessfulSessionUpdate extends EudiAuthenticationSuccessfulSessionUpdate {

    public EudiDcApiAuthenticationSuccessfulSessionUpdate(String idCode,
                                                          String country,
                                                          String firstName,
                                                          String lastName,
                                                          LocalDate dateOfBirth,
                                                          LevelOfAssurance levelOfAssurance) {
        super(idCode, country, firstName, lastName, dateOfBirth, levelOfAssurance);
    }

    @Override
    protected TaraAuthenticationState waitingState() {
        return WAITING_EUDI_DC_API_RESPONSE;
    }

}
