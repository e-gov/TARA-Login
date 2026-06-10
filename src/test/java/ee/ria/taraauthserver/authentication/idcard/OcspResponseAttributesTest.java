package ee.ria.taraauthserver.authentication.idcard;

import eu.webeid.resilientocsp.ResilientOcspCertificateRevocationChecker;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class OcspResponseAttributesTest {

    private static final URI OCSP_URI = URI.create("http://ocsp.test");

    @Test
    void parse_whenAllAttributesPresent_mapsTypedFields() {
        OCSPReq ocspReq = mock(OCSPReq.class);
        OCSPResp ocspResp = mock(OCSPResp.class);
        Exception error = new RuntimeException("OCSP request failed");
        Duration requestDuration = Duration.ofMillis(150);
        ResilientOcspCertificateRevocationChecker.CircuitBreakerStatistics circuitBreakerStatistics
                = mock(ResilientOcspCertificateRevocationChecker.CircuitBreakerStatistics.class);
        Instant responseTime = Instant.parse("2025-01-01T00:00:00Z");
        RevocationInfo revocationInfo = new RevocationInfo(OCSP_URI, Map.of(
                RevocationInfo.KEY_OCSP_REQUEST, ocspReq,
                RevocationInfo.KEY_OCSP_RESPONSE, ocspResp,
                RevocationInfo.KEY_OCSP_ERROR, error,
                RevocationInfo.KEY_REQUEST_DURATION, requestDuration,
                RevocationInfo.KEY_CIRCUIT_BREAKER_STATISTICS, circuitBreakerStatistics,
                RevocationInfo.KEY_OCSP_RESPONSE_TIME, responseTime));

        OcspResponseAttributes result = OcspResponseAttributes.parse(revocationInfo, 2, true);

        assertThat(result.ocspUrl()).isEqualTo("http://ocsp.test");
        assertThat(result.ocspRequest()).isSameAs(ocspReq);
        assertThat(result.ocspResponse()).isSameAs(ocspResp);
        assertThat(result.error()).isSameAs(error);
        assertThat(result.requestDuration()).isEqualTo(requestDuration);
        assertThat(result.circuitBreakerStatistics()).isSameAs(circuitBreakerStatistics);
        assertThat(result.responseTime()).isEqualTo(responseTime);
        assertThat(result.requestNumber()).isEqualTo(2);
        assertThat(result.lastRequest()).isTrue();
    }

    @Test
    void parse_whenAttributesMissing_mapsNulls() {
        RevocationInfo revocationInfo = new RevocationInfo(OCSP_URI, Map.of());

        OcspResponseAttributes result = OcspResponseAttributes.parse(revocationInfo, 1, false);

        assertThat(result.ocspUrl()).isEqualTo("http://ocsp.test");
        assertThat(result.ocspRequest()).isNull();
        assertThat(result.ocspResponse()).isNull();
        assertThat(result.error()).isNull();
        assertThat(result.requestDuration()).isNull();
        assertThat(result.circuitBreakerStatistics()).isNull();
        assertThat(result.responseTime()).isNull();
        assertThat(result.requestNumber()).isEqualTo(1);
        assertThat(result.lastRequest()).isFalse();
    }

    @Test
    void parse_whenOcspResponseHasWrongType_mapsNullResponse() {
        OCSPReq ocspReq = mock(OCSPReq.class);
        RevocationInfo revocationInfo = new RevocationInfo(OCSP_URI, Map.of(
                RevocationInfo.KEY_OCSP_REQUEST, ocspReq,
                RevocationInfo.KEY_OCSP_RESPONSE, "not-an-ocsp-response"));

        OcspResponseAttributes result = OcspResponseAttributes.parse(revocationInfo, 1, true);

        assertThat(result.ocspResponse()).isNull();
        assertThat(result.ocspRequest()).isSameAs(ocspReq);
    }

    @Test
    void parse_whenRevocationInfoNull_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> OcspResponseAttributes.parse(null, 1, true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Revocation info cannot be null");
    }

    @Test
    void toOcspInfo_mapsFieldsForStatisticsLogging() {
        OCSPResp ocspResp = mock(OCSPResp.class);
        Duration requestDuration = Duration.ofMillis(150);
        ResilientOcspCertificateRevocationChecker.CircuitBreakerStatistics circuitBreakerStatistics
                = mock(ResilientOcspCertificateRevocationChecker.CircuitBreakerStatistics.class);
        Instant responseTime = Instant.parse("2025-01-01T00:00:00Z");
        OcspResponseAttributes attributes = new OcspResponseAttributes(
                "http://ocsp.test", null, ocspResp, null, requestDuration, circuitBreakerStatistics, responseTime, 2, true);

        OcspInfo ocspInfo = attributes.toOcspInfo();

        assertThat(ocspInfo.ocspResp()).isSameAs(ocspResp);
        assertThat(ocspInfo.requestCount()).isEqualTo(2);
        assertThat(ocspInfo.requestDuration()).isEqualTo(requestDuration);
        assertThat(ocspInfo.isLastRequest()).isTrue();
        assertThat(ocspInfo.circuitBreakerStatistics()).isSameAs(circuitBreakerStatistics);
        assertThat(ocspInfo.responseTime()).isEqualTo(responseTime);
    }
}
