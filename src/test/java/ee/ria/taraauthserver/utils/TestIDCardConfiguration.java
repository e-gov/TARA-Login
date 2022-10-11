package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.authentication.idcard.OCSPValidator;
import lombok.extern.slf4j.Slf4j;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Slf4j
@TestConfiguration
@Profile("mock_configuration")
public class TestIDCardConfiguration {

    @Autowired
    private ResourceLoader resourceLoader;

    @Bean
    X509Certificate mockIDCardUserCertificate2015() throws CertificateException, IOException {
        return loadCertificate("file:src/test/resources/id-card/37101010021(TEST_of_ESTEID-SK_2015).pem");
    }

    @Bean
    X509Certificate mockIDCardUserCertificate2015withoutAiaExtension() throws CertificateException, IOException {
        return loadCertificate("file:src/test/resources/id-card/37101010021(TEST_of_ESTEID-SK_2015)-no_aia_extension.pem");
    }

    @Bean
    X509Certificate mockIDCardUserCertificate2018() throws CertificateException, IOException {
        return loadCertificate("file:src/test/resources/id-card/38001085718(TEST_of_ESTEID2018).pem");
    }

    @Bean
    X509Certificate mockIDCardUserCertificate2011() throws CertificateException, IOException {
        return loadCertificate("file:src/test/resources/id-card/48812040138(TEST_of_ESTEID-SK_2011).pem");
    }

    private X509Certificate loadCertificate(String resourcePath) throws CertificateException, IOException {
        Resource resource = resourceLoader.getResource(resourcePath);
        if (!resource.exists()) {
            throw new IllegalArgumentException("Could not find resource " + resourcePath);
        }

        try (InputStream inputStream = resource.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(inputStream);
        }
    }

    @Bean
    @Primary
    @ConditionalOnProperty("tara.auth-methods.id-card.enabled")
    OCSPValidator mockOCSPValidator() {
        return Mockito.mock(OCSPValidator.class);
    }
}
