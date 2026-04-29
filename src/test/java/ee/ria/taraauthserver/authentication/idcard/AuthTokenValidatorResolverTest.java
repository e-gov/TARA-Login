package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.session.TaraSession;
import eu.webeid.security.validator.AuthTokenValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthTokenValidatorResolverTest {

    private AuthConfigurationProperties.FilterForEidasProxy filterForEidasProxy;
    private AuthTokenValidator defaultAuthTokenValidator;
    private AuthTokenValidator eidasProxyAuthTokenValidator;

    private AuthTokenValidatorResolver resolver;

    @BeforeEach
    void setUp() {
        filterForEidasProxy = mock(AuthConfigurationProperties.FilterForEidasProxy.class);
        defaultAuthTokenValidator = mock(AuthTokenValidator.class);
        eidasProxyAuthTokenValidator = mock(AuthTokenValidator.class);

        resolver = new AuthTokenValidatorResolver(
                filterForEidasProxy,
                defaultAuthTokenValidator,
                eidasProxyAuthTokenValidator
        );
    }

    @Test
    void resolve_whenEidasProxyClient_returnsEidasProxyValidator() {
        TaraSession.Client client = createClient("eidas-client");
        when(filterForEidasProxy.getClientId()).thenReturn("eidas-client");

        AuthTokenValidator result = resolver.resolve(client);

        assertThat(result).isSameAs(eidasProxyAuthTokenValidator);
    }

    @Test
    void resolve_whenRegularClient_returnsIdCardValidator() {
        TaraSession.Client client = createClient("regular-client");
        when(filterForEidasProxy.getClientId()).thenReturn("eidas-client");

        AuthTokenValidator result = resolver.resolve(client);

        assertThat(result).isSameAs(defaultAuthTokenValidator);
    }

    private static TaraSession.Client createClient(String clientId) {
        TaraSession.Client client = mock(TaraSession.Client.class);
        when(client.getClientId()).thenReturn(clientId);
        return client;
    }
}
