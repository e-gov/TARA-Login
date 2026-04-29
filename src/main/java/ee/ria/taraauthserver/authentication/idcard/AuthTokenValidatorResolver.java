package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.session.TaraSession;
import eu.webeid.security.validator.AuthTokenValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
class AuthTokenValidatorResolver {

    private final AuthConfigurationProperties.FilterForEidasProxy filterForEidasProxy;

    @Qualifier("defaultAuthTokenValidator")
    private final AuthTokenValidator defaultAuthTokenValidator;

    @Qualifier("eidasProxyAuthTokenValidator")
    private final AuthTokenValidator eidasProxyAuthTokenValidator;

    public AuthTokenValidator resolve(TaraSession.Client client) {
        String eidasClientId = filterForEidasProxy.getClientId();
        String clientId = client.getClientId();

        return clientId.equals(eidasClientId)
                ? eidasProxyAuthTokenValidator
                : defaultAuthTokenValidator;
    }
}
