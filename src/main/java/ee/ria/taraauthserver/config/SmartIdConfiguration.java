package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.ria.taraauthserver.logging.JaxRsClientRequestLogger;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.SmartIdClient;
import lombok.extern.slf4j.Slf4j;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
@Configuration
@ConditionalOnProperty(value = "tara.auth-methods.smart-id.enabled")
public class SmartIdConfiguration {

    @Autowired
    SmartIdConfigurationProperties smartIdConfigurationProperties;

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    public SmartIdClient smartIdClient(SSLContext trustContext) {
        SmartIdClient smartIdClient = new SmartIdClient();
        smartIdClient.setHostUrl(smartIdConfigurationProperties.getHostUrl());
        smartIdClient.setRelyingPartyName(smartIdConfigurationProperties.getRelyingPartyName());
        smartIdClient.setRelyingPartyUUID(smartIdConfigurationProperties.getRelyingPartyUuid());
        smartIdClient.setSessionStatusResponseSocketOpenTime(TimeUnit.MILLISECONDS, smartIdConfigurationProperties.getLongPollingTimeoutMilliseconds());
        smartIdClient.setTrustSslContext(trustContext);
        smartIdClient.setNetworkConnectionConfig(clientConfig());

        return smartIdClient;
    }

    private ClientConfig clientConfig() {
        ClientConfig clientConfig = new ClientConfig();
        clientConfig.property(ClientProperties.CONNECT_TIMEOUT, smartIdConfigurationProperties.getConnectionTimeoutMilliseconds());
        clientConfig.property(ClientProperties.READ_TIMEOUT, smartIdConfigurationProperties.getReadTimeoutMilliseconds());
        clientConfig.register(new JaxRsClientRequestLogger("Smart-ID"));
        return clientConfig;
    }

    @Bean
    public AuthenticationResponseValidator authResponseValidator() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        AuthenticationResponseValidator authResponseValidator = new AuthenticationResponseValidator();
        authResponseValidator.clearTrustedCACertificates();
        Resource resource = resourceLoader.getResource(smartIdConfigurationProperties.getTruststorePath());
        KeyStore trustStore = KeyStore.getInstance(smartIdConfigurationProperties.getTruststoreType());
        trustStore.load(resource.getInputStream(), smartIdConfigurationProperties.getTruststorePassword().toCharArray());
        List<String> aliases = Collections.list(trustStore.aliases());
        for (String alias : aliases) {
            authResponseValidator.addTrustedCACertificate(trustStore.getCertificate(alias).getEncoded());
        }
        return authResponseValidator;
    }

}
