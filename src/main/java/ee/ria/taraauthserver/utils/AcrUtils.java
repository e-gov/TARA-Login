package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.InvalidLoginRequestException;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Optional;

import static ee.ria.taraauthserver.error.ErrorCode.INVALID_ACR_VALUE;

@Slf4j
@UtilityClass
public class AcrUtils {

    public String getAppropriateAcrValue(TaraSession.LoginRequestInfo loginRequestInfo) {
        List<String> loginRequestAcrList = getAcrFromSessionOidcContext(loginRequestInfo);
        String clientSettingsAcrName = getAcrFromClientSettings(loginRequestInfo);

        if (loginRequestAcrList != null && !loginRequestAcrList.isEmpty()) {
            validateAcrValues(loginRequestInfo, loginRequestAcrList, clientSettingsAcrName);
            return loginRequestAcrList.get(0);
        } else if (clientSettingsAcrName != null) {
            return clientSettingsAcrName;
        }
        return null;
    }

    private static void validateAcrValues(TaraSession.LoginRequestInfo loginRequestInfo, List<String> loginRequestAcrList, String clientSettingsAcrName) {
        if (loginRequestAcrList.size() > 1) {
            throw new InvalidLoginRequestException("acrValues must contain only 1 value", loginRequestInfo);
        }
        String loginRequestAcrName = loginRequestAcrList.get(0);
        LevelOfAssurance loginRequestAcr = LevelOfAssurance.findByAcrName(loginRequestAcrName);
        if (loginRequestAcr == null) {
            throw new InvalidLoginRequestException("Unsupported acr value requested by client: '" + loginRequestAcrName + "'", loginRequestInfo);
        }
        if (clientSettingsAcrName != null && !loginRequestAcr.equals(LevelOfAssurance.findByAcrName(clientSettingsAcrName))) {
            throw new BadRequestException(INVALID_ACR_VALUE, "Requested acr_values must match configured minimum_acr_value");
        }
    }

    private List<String> getAcrFromSessionOidcContext(TaraSession.LoginRequestInfo loginRequestInfo) {
        return Optional.of(loginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getOidcContext)
                .map(TaraSession.OidcContext::getAcrValues)
                .orElse(null);
    }

    private String getAcrFromClientSettings(TaraSession.LoginRequestInfo loginRequestInfo) {
        return Optional.of(loginRequestInfo)
                .map(TaraSession.LoginRequestInfo::getClient)
                .map(TaraSession.Client::getMetaData)
                .map(TaraSession.MetaData::getMinimumAcrValue)
                .orElse(null);
    }
}
