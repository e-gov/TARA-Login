package ee.ria.taraauthserver.utils;

import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@UtilityClass
public class TestUtils {

    @SneakyThrows
    public X509Certificate loadCertificateFromResource(String resourcePath) {
        try (InputStream inputStream = TestUtils.class.getClassLoader().getResourceAsStream(resourcePath)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        }
    }
}
