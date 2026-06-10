package ee.ria.taraauthserver.authentication.idcard;

import eu.webeid.resilientocsp.ResilientOcspCertificateRevocationChecker;
import org.bouncycastle.cert.ocsp.OCSPResp;

import java.time.Duration;
import java.time.Instant;

public record OcspInfo(
        OCSPResp ocspResp,
        Integer requestCount,
        Duration requestDuration,
        boolean isLastRequest,
        ResilientOcspCertificateRevocationChecker.CircuitBreakerStatistics circuitBreakerStatistics,
        Instant responseTime
) {
}
