package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.authentication.common.AuthenticationDisplayTextFactory;
import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.ria.taraauthserver.logging.JaxRsClientRequestLogger;
import ee.sk.smartid.CertificateValidatorImpl;
import ee.sk.smartid.DefaultTrustedCAStoreBuilder;
import ee.sk.smartid.DeviceLinkAuthenticationResponseValidator;
import ee.sk.smartid.NotificationAuthenticationResponseValidator;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.TrustedCACertStore;
import lombok.extern.slf4j.Slf4j;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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
    AuthenticationDisplayTextFactory smartIdDisplayTextFactory(MessageSource messageSource) {
        return new AuthenticationDisplayTextFactory(messageSource, smartIdConfigurationProperties.getDisplayText());
    }

    @Bean
    public DeviceLinkAuthenticationResponseValidator deviceLinkAuthenticationResponseValidator() throws Exception {
        return DeviceLinkAuthenticationResponseValidator.defaultSetupWithCertificateValidator(
                new CertificateValidatorImpl(getTrustedCACertStore()));
    }

    @Bean
    public NotificationAuthenticationResponseValidator notificationAuthenticationResponseValidator() throws Exception {
        return NotificationAuthenticationResponseValidator.defaultSetupWithCertificateValidator(
                new CertificateValidatorImpl(getTrustedCACertStore()));
    }

    private TrustedCACertStore getTrustedCACertStore() throws Exception {
        return new DefaultTrustedCAStoreBuilder()
                .withTrustAnchors(getTrustAnchors())
                .withIntermediateCACertificate(getIntermediateCaCertificates())
                // TODO: Enable when OCSP support will be implemented in newer Smart ID versions.
                //   See https://github.com/SK-EID/smart-id-java-client/blob/master/src/main/java/ee/sk/smartid/DefaultTrustedCAStoreBuilder.java#L111
                //   (as of Smart-ID version 3.1, this line throws UnsupportedOperationException with message "will be implemented later")
                .withOcspEnabled(false)
                .build();
    }

    private Set<TrustAnchor> getTrustAnchors() throws Exception {
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        Resource resource = resourceLoader.getResource(smartIdConfigurationProperties.getTrustAnchorTruststore().getPath());
        KeyStore trustStore = KeyStore.getInstance(smartIdConfigurationProperties.getTrustAnchorTruststore().getType());
        try(InputStream inputStream = resource.getInputStream()) {
            trustStore.load(inputStream, smartIdConfigurationProperties.getTrustAnchorTruststore().getPassword().toCharArray());
        }
        List<String> aliases = Collections.list(trustStore.aliases());
        for (String alias : aliases) {
            X509Certificate certificate = (X509Certificate) trustStore.getCertificate(alias);
            trustAnchors.add(new TrustAnchor(certificate, null));
        }
        return trustAnchors;
    }

    private List<X509Certificate> getIntermediateCaCertificates() throws Exception {
        List<X509Certificate> certificates = new ArrayList<>();
        Resource resource = resourceLoader.getResource(smartIdConfigurationProperties.getIntermediateCaTruststore().getPath());
        KeyStore trustStore = KeyStore.getInstance(smartIdConfigurationProperties.getIntermediateCaTruststore().getType());
        try(InputStream inputStream = resource.getInputStream()) {
            trustStore.load(inputStream, smartIdConfigurationProperties.getIntermediateCaTruststore().getPassword().toCharArray());
        }
        List<String> aliases = Collections.list(trustStore.aliases());
        for (String alias : aliases) {
            X509Certificate certificate = (X509Certificate) trustStore.getCertificate(alias);
            certificates.add(certificate);
        }
        return certificates;
    }

}
