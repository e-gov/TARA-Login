package ee.ria.taraauthserver.config.properties;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.CertificateChain;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.FallbackOcspServer;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.FilterForEidasProxy;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.Ocsp;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.OcspCircuitBreakerConfig;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.OcspRetryConfig;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.PrimaryOcspServer;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.TruststoreConfigurationProperties;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthConfigurationPropertiesTest {

    @Nested
    class OcspValidation {

        @Test
        void validateConfiguration_whenEnabledAndCertificateChainsNull_throwsIllegalArgumentException() {
            Ocsp ocsp = new Ocsp();
            ocsp.setEnabled(true);

            assertThatThrownBy(ocsp::validateConfiguration)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("At least one certificate chain configuration must be defined!");
        }

        @Test
        void validateConfiguration_whenEnabledAndCertificateChainsEmpty_throwsIllegalArgumentException() {
            Ocsp ocsp = new Ocsp();
            ocsp.setEnabled(true);
            ocsp.setCertificateChains(List.of());

            assertThatThrownBy(ocsp::validateConfiguration)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("At least one certificate chain configuration must be defined!");
        }

        @Test
        void validateConfiguration_whenDuplicateIssuerDns_throwsIllegalArgumentException() {
            Ocsp ocsp = new Ocsp();
            ocsp.setCertificateChains(List.of(
                    certificateChain("CN=Duplicate Issuer"),
                    certificateChain("CN=Unique Issuer"),
                    certificateChain("CN=Duplicate Issuer")));

            assertThatThrownBy(ocsp::validateConfiguration)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageStartingWith("Multiple certificate chain configurations detected for issuer's with CN's: ")
                    .hasMessageContaining("CN=Duplicate Issuer")
                    .hasMessageEndingWith(". Please check your configuration!");
        }

        @Test
        void validateConfiguration_whenDistinctIssuerDns_passes() {
            Ocsp ocsp = new Ocsp();
            ocsp.setCertificateChains(List.of(
                    certificateChain("CN=First Issuer"),
                    certificateChain("CN=Second Issuer")));

            assertThatCode(ocsp::validateConfiguration).doesNotThrowAnyException();
        }

        @Test
        void validateConfiguration_whenDisabled_passesWithoutCertificateChains() {
            Ocsp ocsp = new Ocsp();
            ocsp.setEnabled(false);

            assertThatCode(ocsp::validateConfiguration).doesNotThrowAnyException();
        }
    }

    @Nested
    class CertificateChainValidation {

        @Test
        void validateConfiguration_whenSecondFallbackWithoutFirst_throwsIllegalArgumentException() {
            CertificateChain chain = certificateChain("CN=Test Issuer");
            chain.setSecondFallbackServer(fallbackServer("http://fallback2.test/ocsp"));

            assertThatThrownBy(chain::validateConfiguration)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Second fallback is only allowed when first fallback is set");
        }

        @Test
        void validateConfiguration_whenFirstAndSecondFallbackSet_passes() {
            CertificateChain chain = certificateChain("CN=Test Issuer");
            chain.setFirstFallbackServer(fallbackServer("http://fallback1.test/ocsp"));
            chain.setSecondFallbackServer(fallbackServer("http://fallback2.test/ocsp"));

            assertThatCode(chain::validateConfiguration).doesNotThrowAnyException();
        }

        @Test
        void validateConfiguration_whenNoFallbacksSet_passes() {
            CertificateChain chain = certificateChain("CN=Test Issuer");

            assertThatCode(chain::validateConfiguration).doesNotThrowAnyException();
        }
    }

    @Nested
    class FilterForEidasProxyPolicyOids {

        @Test
        void setAllowedPolicyOids_whenValidOidStrings_parsesToAsn1ObjectIdentifiers() {
            FilterForEidasProxy filterForEidasProxy = new FilterForEidasProxy();

            filterForEidasProxy.setAllowedPolicyOids(Set.of("1.3.6.1.4.1.51361.1.2.1", "0.4.0.2042.1.2"));

            assertThat(filterForEidasProxy.getAllowedPolicyOids()).containsExactlyInAnyOrder(
                    new ASN1ObjectIdentifier("1.3.6.1.4.1.51361.1.2.1"),
                    new ASN1ObjectIdentifier("0.4.0.2042.1.2"));
        }

        @Test
        void setAllowedPolicyOids_whenInvalidOid_throwsIllegalArgumentException() {
            FilterForEidasProxy filterForEidasProxy = new FilterForEidasProxy();

            assertThatThrownBy(() -> filterForEidasProxy.setAllowedPolicyOids(Set.of("not-an-oid")))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Invalid eIDAS proxy allowed certificate policy OID: not-an-oid")
                    .cause().isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void getAllowedPolicyOids_byDefault_returnsEmptySet() {
            FilterForEidasProxy filterForEidasProxy = new FilterForEidasProxy();

            assertThat(filterForEidasProxy.getAllowedPolicyOids()).isEmpty();
        }
    }

    @Nested
    class Defaults {

        @Test
        void ocsp_hasExpectedDefaults() {
            Ocsp ocsp = new Ocsp();

            assertThat(ocsp.isEnabled()).isTrue();
            assertThat(ocsp.getAllowedResponseTimeSkew()).isEqualTo(Duration.ofMinutes(15));
            assertThat(ocsp.getPrimaryServerThisUpdateMaxAge()).isEqualTo(Duration.ofMinutes(2));
            assertThat(ocsp.getFallbackServerThisUpdateMaxAge()).isEqualTo(Duration.ofHours(24));
            assertThat(ocsp.getRequestTimeout()).isEqualTo(Duration.ofSeconds(5));
            assertThat(ocsp.getRetry()).isNotNull();
            assertThat(ocsp.getCircuitBreaker()).isNotNull();
        }

        @Test
        void ocspRetryConfig_hasExpectedDefaults() {
            OcspRetryConfig retry = new OcspRetryConfig();

            assertThat(retry.getWaitDuration()).isEqualTo(Duration.ofMillis(500));
            assertThat(retry.getMaxAttempts()).isEqualTo(2);
        }

        @Test
        void ocspCircuitBreakerConfig_hasExpectedDefaults() {
            OcspCircuitBreakerConfig circuitBreaker = new OcspCircuitBreakerConfig();

            assertThat(circuitBreaker.getSlidingWindowSize()).isEqualTo(100);
            assertThat(circuitBreaker.getMinimumNumberOfCalls()).isEqualTo(100);
            assertThat(circuitBreaker.getFailureRateThreshold()).isEqualTo(50);
            assertThat(circuitBreaker.getPermittedNumberOfCallsInHalfOpenState()).isEqualTo(10);
            assertThat(circuitBreaker.getWaitDurationInOpenState()).isEqualTo(Duration.ofSeconds(60));
        }

        @Test
        void ocspServers_haveExpectedDefaults() {
            assertThat(new PrimaryOcspServer().isNonceEnabled()).isTrue();
            FallbackOcspServer fallbackServer = new FallbackOcspServer();
            assertThat(fallbackServer.isNonceEnabled()).isTrue();
            assertThat(fallbackServer.isEnabledForEidasProxy()).isTrue();
            assertThat(fallbackServer.getResponderSubjectDn()).isNull();
        }

        @Test
        void getType_byDefault_returnsPkcs12() {
            TruststoreConfigurationProperties truststore = new TruststoreConfigurationProperties();

            assertThat(truststore.getType()).isEqualTo("PKCS12");
        }
    }

    @Nested
    class TruststoreValidation {

        @Test
        void validateConfiguration_whenPathAndPasswordSet_passes() {
            TruststoreConfigurationProperties truststore = new TruststoreConfigurationProperties();
            truststore.setPath("file:src/test/resources/idcard-truststore-test.p12");
            truststore.setPassword("changeit");

            assertThatCode(truststore::validateConfiguration).doesNotThrowAnyException();
        }

        @Test
        void validateConfiguration_whenPathMissing_throwsIllegalArgumentException() {
            TruststoreConfigurationProperties truststore = new TruststoreConfigurationProperties();
            truststore.setPassword("changeit");

            assertThatThrownBy(truststore::validateConfiguration)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Keystore location cannot be empty!");
        }

        @Test
        void validateConfiguration_whenPasswordMissing_throwsIllegalArgumentException() {
            TruststoreConfigurationProperties truststore = new TruststoreConfigurationProperties();
            truststore.setPath("file:src/test/resources/idcard-truststore-test.p12");

            assertThatThrownBy(truststore::validateConfiguration)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Keystore password cannot be empty!");
        }
    }

    private static CertificateChain certificateChain(String issuerDn) {
        CertificateChain chain = new CertificateChain();
        chain.setIssuerDn(new X500Name(issuerDn));
        chain.setPrimaryServer(new PrimaryOcspServer());
        return chain;
    }

    private static FallbackOcspServer fallbackServer(String url) {
        FallbackOcspServer fallbackServer = new FallbackOcspServer();
        fallbackServer.setUrl(url);
        return fallbackServer;
    }
}
