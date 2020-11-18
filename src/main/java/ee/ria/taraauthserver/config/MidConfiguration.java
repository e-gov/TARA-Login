package ee.ria.taraauthserver.config;

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
@ConditionalOnProperty(value = "tara.mid-authentication.enabled", matchIfMissing = true)
public class MidConfiguration {

    @Bean
    public KeyStore midTrustStore(AuthConfigurationProperties.MidAuthConfigurationProperties midAuthConfigurationProperties, ResourceLoader loader) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        Resource resource = loader.getResource(midAuthConfigurationProperties.getTruststorePath());
        KeyStore trustStore = KeyStore.getInstance(midAuthConfigurationProperties.getTruststoreType());
        trustStore.load(resource.getInputStream(), midAuthConfigurationProperties.getTruststorePassword().toCharArray());
        return trustStore;
    }

    @Bean
    @SneakyThrows
    public MidClient midClient(KeyStore midTrustStore, AuthConfigurationProperties.MidAuthConfigurationProperties midAuthConfigurationProperties) {

        return MidClient.newBuilder()
                .withHostUrl(midAuthConfigurationProperties.getHostUrl())
                .withRelyingPartyUUID(midAuthConfigurationProperties.getRelyingPartyUuid())
                .withRelyingPartyName(midAuthConfigurationProperties.getRelyingPartyName())
                .withTrustSslContext(SSLContext.getDefault())
                .withNetworkConnectionConfig(clientConfig(midAuthConfigurationProperties))
                .withLongPollingTimeoutSeconds(30)
                .build();
    }

    private ClientConfig clientConfig(AuthConfigurationProperties.MidAuthConfigurationProperties midAuthConfigurationProperties) {
        ClientConfig clientConfig = new ClientConfig();
        clientConfig.property(ClientProperties.CONNECT_TIMEOUT, midAuthConfigurationProperties.getConnectionTimeoutMilliseconds());
        clientConfig.property(ClientProperties.READ_TIMEOUT, midAuthConfigurationProperties.getReadTimeoutMilliseconds());
        clientConfig.register(new MidLoggingFilter());
        return clientConfig;
    }
}
