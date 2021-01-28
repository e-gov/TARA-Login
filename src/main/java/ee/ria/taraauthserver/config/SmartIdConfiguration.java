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
    public SmartIdClient smartIdClient() {
        SmartIdClient smartIdClient = new SmartIdClient();
        smartIdClient.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
        smartIdClient.setRelyingPartyName("DEMO");
        smartIdClient.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        smartIdClient.setTrustedCertificates("-----BEGIN CERTIFICATE-----\n" +
                "MIIGCTCCBPGgAwIBAgIQCXnvf1BVTGUPxVHFrsj1UTANBgkqhkiG9w0BAQsFADBN\n" +
                "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E\n" +
                "aWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMjAwOTMwMDAwMDAwWhcN\n" +
                "MjExMDEzMTIwMDAwWjBVMQswCQYDVQQGEwJFRTEQMA4GA1UEBxMHVGFsbGlubjEb\n" +
                "MBkGA1UEChMSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQQDEw5zaWQuZGVtby5z\n" +
                "ay5lZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI8JcI/gMKTECzWU\n" +
                "NNtHqpT5HErG/3HOeitfk9NVHvmOHdQ4BmWlMkTKjgIaHUdX3BKij+RdTxYJu7uN\n" +
                "IKAFNJGDePtSnfOB5G8/zR3UT+O2SiB+7MK+1dOzJY2KexWnoTpjO72MeWYesfAZ\n" +
                "jdclO6eFRZd1iRN0UB9E6GbgGbaZqindw4ChqWmrWOkIPjn5p5C3qW0OvOg+BCUa\n" +
                "B3C0XICakZYQmxdvujnW1Lk7BXgoobhBG36CO8x0ZDZvJ7zXyriWolnzl1/zkJGC\n" +
                "2kU5+lcbfbDA8NX7rdh7n5xfCQVcs5aaX6AV1eptaa6Xk6XfRqqZe3dTYGJ8jUp1\n" +
                "XztpuEcCAwEAAaOCAtswggLXMB8GA1UdIwQYMBaAFA+AYRyCMWHVLyjnjUY4tCzh\n" +
                "xtniMB0GA1UdDgQWBBSkZr/qNmU1VkQZhGcUTXj43is2mjAZBgNVHREEEjAQgg5z\n" +
                "aWQuZGVtby5zay5lZTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUH\n" +
                "AwEGCCsGAQUFBwMCMGsGA1UdHwRkMGIwL6AtoCuGKWh0dHA6Ly9jcmwzLmRpZ2lj\n" +
                "ZXJ0LmNvbS9zc2NhLXNoYTItZzcuY3JsMC+gLaArhilodHRwOi8vY3JsNC5kaWdp\n" +
                "Y2VydC5jb20vc3NjYS1zaGEyLWc3LmNybDBMBgNVHSAERTBDMDcGCWCGSAGG/WwB\n" +
                "ATAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgG\n" +
                "BmeBDAECAjB8BggrBgEFBQcBAQRwMG4wJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw\n" +
                "LmRpZ2ljZXJ0LmNvbTBGBggrBgEFBQcwAoY6aHR0cDovL2NhY2VydHMuZGlnaWNl\n" +
                "cnQuY29tL0RpZ2lDZXJ0U0hBMlNlY3VyZVNlcnZlckNBLmNydDAMBgNVHRMBAf8E\n" +
                "AjAAMIIBAgYKKwYBBAHWeQIEAgSB8wSB8ADuAHUA9lyUL9F3MCIUVBgIMJRWjuNN\n" +
                "Exkzv98MLyALzE7xZOMAAAF03zz1EQAABAMARjBEAiAtBjQ5T1Ph9VcOYCkR2VtA\n" +
                "X2W4FtMe/iLHoofe0fzGGwIgMmI5z2lYPY5Z0PQGSmkhaVP/oJCMXLOxpl1jl2jv\n" +
                "glgAdQBc3EOS/uarRUSxXprUVuYQN/vV+kfcoXOUsl7m9scOygAAAXTfPPVTAAAE\n" +
                "AwBGMEQCIFuhhCSPYcro3jrRUEIXSR2hx0HpEcXBm8JmpagSq0jDAiBufmHyR5LE\n" +
                "Vf+DXUNtq+fYvBs/SZsNM5QSAyqUjB9S6TANBgkqhkiG9w0BAQsFAAOCAQEA2cHE\n" +
                "SIZIO4BHjWqr2awZwVEhiQ0Le1LzgRu9Zz+fpIEZW9e0OhCf72QMH58ZUgm+a41T\n" +
                "IbmE1z4ARGsug1v8eFul4WQ5iYdMnyLfDg8V/RU8vfTnIxEs+DqiDQPdLRw4qkVh\n" +
                "AX+Kak+3tieWDHp1RZfs7gAgAIG7aFyn+huvLbmbkDHbbqyrJVRIHmaBtctPt3XD\n" +
                "rlg7vdmgEKyHshixlUlBBqzosy6tOfsD4vjV9q4/ivNSRO7i04Gi+jjbzaQl0HKh\n" +
                "1ehQnPmzSxLm9qLVpD27/PN7bIRZY6jlznLBAjxv04SQIZXO7lzYoXtic8E5OsFH\n" +
                "ZpvrImWECmeotyNYkg==\n" +
                "-----END CERTIFICATE-----");

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
