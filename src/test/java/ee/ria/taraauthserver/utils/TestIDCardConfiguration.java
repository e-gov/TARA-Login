package ee.ria.taraauthserver.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;

import java.security.cert.X509Certificate;

@Slf4j
@TestConfiguration
@Profile("mock_configuration")
public class TestIDCardConfiguration {

    @Bean
    X509Certificate mockIDCardUserCertificate2015() {
        return TestUtils.loadCertificateFromResource("file:src/test/resources/id-card/37101010021(TEST_of_ESTEID-SK_2015).pem");
    }

    @Bean
    X509Certificate mockIDCardUserCertificate2015withoutAiaExtension() {
        return TestUtils.loadCertificateFromResource("file:src/test/resources/id-card/37101010021(TEST_of_ESTEID-SK_2015)-no_aia_extension.pem");
    }

    @Bean
    X509Certificate mockIDCardUserCertificate2018() {
        return TestUtils.loadCertificateFromResource("file:src/test/resources/id-card/38001085718(TEST_of_ESTEID2018).pem");
    }

    @Bean
    X509Certificate mockIDCardUserCertificate2011() {
        return TestUtils.loadCertificateFromResource("file:src/test/resources/id-card/48812040138(TEST_of_ESTEID-SK_2011).pem");
    }
}
