package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.SmartIdClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

@Slf4j
@Configuration
@ConditionalOnProperty(value = "tara.auth-methods.smart-id.enabled", matchIfMissing = true)
public class SmartIdConfiguration {

    @Autowired
    SmartIdConfigurationProperties smartIdConfigurationProperties;

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    public SmartIdClient smartIdClient(SSLContext tlsTrustStore) {
        SmartIdClient smartIdClient = new SmartIdClient();
        smartIdClient.setHostUrl(smartIdConfigurationProperties.getHostUrl());
        smartIdClient.setRelyingPartyName(smartIdConfigurationProperties.getRelyingPartyName());
        smartIdClient.setRelyingPartyUUID(smartIdConfigurationProperties.getRelyingPartyUuid());
        smartIdClient.setTrustSslContext(tlsTrustStore);

        return smartIdClient;
    }

    @Bean
    public AuthenticationResponseValidator authResponseValidator() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        AuthenticationResponseValidator authResponseValidator = new AuthenticationResponseValidator();
        authResponseValidator.clearTrustedCACertificates();
        Resource resource = resourceLoader.getResource(smartIdConfigurationProperties.getTrustedCaCertificatesLocation());

        File certificateFile = resource.getFile();
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(resource.getInputStream(), "changeit".toCharArray());
        List<String> aliases = Collections.list(trustStore.aliases());
        for (String alias : aliases) {
            authResponseValidator.addTrustedCACertificate(trustStore.getCertificate(alias).getEncoded());
        }
        return authResponseValidator;
    }

}
