package ee.ria.taraauthserver.error.exceptions;

import ee.ria.taraauthserver.error.ErrorCode;

public class SidCountryNotAllowedException extends TaraException {

    public SidCountryNotAllowedException(String countryCode) {
        super(ErrorCode.SID_COUNTRY_NOT_ALLOWED, "Smart-ID authentication is not allowed for country: " + countryCode, null, null);
    }
}
