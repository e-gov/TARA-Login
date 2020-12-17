package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.MidAuthConfigurationProperties;
import ee.sk.mid.MidAuthenticationResponseValidator;
import ee.sk.mid.MidClient;
import ee.sk.mid.rest.MidLoggingFilter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Slf4j
@Configuration
@ConditionalOnProperty(value = "tara.auth-methods.mobile-id.enabled", matchIfMissing = true)
public class MidConfiguration {

    @Bean
    public MidAuthenticationResponseValidator midAuthenticationResponseValidator(KeyStore midTrustStore) {
        return new MidAuthenticationResponseValidator(midTrustStore);
    }

    @Bean
    public KeyStore midTrustStore(MidAuthConfigurationProperties properties, ResourceLoader loader) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        Resource resource = loader.getResource(properties.getTruststorePath());
        KeyStore trustStore = KeyStore.getInstance(properties.getTruststoreType());
        trustStore.load(resource.getInputStream(), properties.getTruststorePassword().toCharArray());
        return trustStore;
    }

    @Bean
    @SneakyThrows
    public MidClient midClient(SSLContext tlsTrustStore, MidAuthConfigurationProperties properties) {
        return MidClient.newBuilder()
                .withHostUrl(properties.getHostUrl())
                .withRelyingPartyUUID(properties.getRelyingPartyUuid())
                .withRelyingPartyName(properties.getRelyingPartyName())
                .withTrustSslContext(tlsTrustStore)
                .withNetworkConnectionConfig(clientConfig(properties))
                .withLongPollingTimeoutSeconds(properties.getLongPollingTimeoutSeconds())
                .build();
    }

    private ClientConfig clientConfig(MidAuthConfigurationProperties properties) {
        ClientConfig clientConfig = new ClientConfig();
        clientConfig.property(ClientProperties.CONNECT_TIMEOUT, properties.getConnectionTimeoutMilliseconds());
        clientConfig.property(ClientProperties.READ_TIMEOUT, properties.getReadTimeoutMilliseconds());
        clientConfig.register(new MidLoggingFilter());
        return clientConfig;
    }
}
