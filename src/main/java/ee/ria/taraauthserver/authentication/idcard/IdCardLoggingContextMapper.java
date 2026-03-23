package ee.ria.taraauthserver.authentication.idcard;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.webeid.resilientocsp.ResilientOcspCertificateRevocationChecker;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Component
@Slf4j
public class IdCardLoggingContextMapper {

    public IdCardLoggingContext toIdCardLoggingContext(IdCardLoginService.OcspInfo ocspInfo) {
        IdCardLoggingContext.IdCardLoggingContextBuilder idCardLoggingContextBuilder = IdCardLoggingContext.builder();

        if (ocspInfo == null) {
            return null;
        }
        if (ocspInfo.requestDuration() != null) {
            idCardLoggingContextBuilder.requestDuration(ocspInfo.requestDuration().toNanos());
        }
        idCardLoggingContextBuilder.requestCount(ocspInfo.requestCount());
        idCardLoggingContextBuilder.isLastRequest(ocspInfo.isLastRequest());
        addCircuitBreakerStatistics(idCardLoggingContextBuilder, ocspInfo.circuitBreakerStatistics());

        OCSPResp ocspResp = ocspInfo.ocspResp();
        if (ocspResp == null) {
            return idCardLoggingContextBuilder.build();
        }

        BasicOCSPResp basicResponse = null;
        try {
            basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
        } catch (OCSPException e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to decode OCSP response");
        }
        if (basicResponse == null) {
            // TODO
            return idCardLoggingContextBuilder.build();
        }
        Instant responseTime = ocspInfo.responseTime();

        Date producedAt = basicResponse.getProducedAt();
        idCardLoggingContextBuilder.producedAt(producedAt);
        if (responseTime != null) {
            idCardLoggingContextBuilder.timeSinceProducedAt(Duration.between(producedAt.toInstant(), responseTime).toMillis());
        }

        SingleResp singleResp = basicResponse.getResponses()[0];
        if (singleResp == null) {
            // TODO
            return idCardLoggingContextBuilder.build();
        }
        Date thisUpdate = singleResp.getThisUpdate();
        idCardLoggingContextBuilder.thisUpdate(thisUpdate);
        if (responseTime != null) {
            idCardLoggingContextBuilder.timeSinceThisUpdate(Duration.between(thisUpdate.toInstant(), responseTime).toMillis());
        }

        Date nextUpdate = singleResp.getNextUpdate();
        if (nextUpdate != null) {
            idCardLoggingContextBuilder.nextUpdate(nextUpdate);
            if (responseTime != null) {
                idCardLoggingContextBuilder.timeUntilNextUpdate(Duration.between(responseTime, nextUpdate.toInstant()).toMillis());
            }
        }

        try {
            idCardLoggingContextBuilder.ocspResponseSize(ocspResp.getEncoded().length);
        } catch (IOException e) {
            log.atError()
                    .setCause(e)
                    .log("Failed to encode OCSP response");
        }

        return idCardLoggingContextBuilder.build();
    }

    private void addCircuitBreakerStatistics(IdCardLoggingContext.IdCardLoggingContextBuilder builder,
                                             ResilientOcspCertificateRevocationChecker.CircuitBreakerStatistics circuitBreakerStatistics) {
        builder
                .state(circuitBreakerStatistics.state())
                .failureRate(circuitBreakerStatistics.failureRate())
                .totalCalls(circuitBreakerStatistics.numberOfBufferedCalls())
                .failedCalls(circuitBreakerStatistics.numberOfFailedCalls())
                .notPermittedCalls(circuitBreakerStatistics.numberOfNotPermittedCalls())
                .successfulCalls(circuitBreakerStatistics.numberOfSuccessfulCalls());
    }

    @Builder
    @Data
    public static class IdCardLoggingContext {

        @JsonProperty("tara.ocsp.produced_at")
        private Date producedAt;

        @JsonProperty("tara.ocsp.time_since_produced_at")
        private Long timeSinceProducedAt;

        @JsonProperty("tara.ocsp.this_update")
        private Date thisUpdate;

        @JsonProperty("tara.ocsp.time_since_this_update")
        private Long timeSinceThisUpdate;

        @JsonProperty("tara.ocsp.next_update")
        private Date nextUpdate;

        @JsonProperty("tara.ocsp.time_until_next_update")
        private Long timeUntilNextUpdate;

        @JsonProperty("tara.ocsp.request_number")
        private Integer requestCount;

        @JsonProperty("http.request.body.bytes")
        private Integer ocspResponseSize;

        @JsonProperty("event.duration")
        private Long requestDuration;

        @JsonProperty("tara.ocsp.last_request")
        private Boolean isLastRequest;

        @JsonProperty("tara.ocsp.circuit_breaker.state")
        private CircuitBreaker.State state;

        @JsonProperty("tara.ocsp.circuit_breaker.failure_rate")
        private Float failureRate;

        @JsonProperty("tara.ocsp.circuit_breaker.total_calls")
        private Integer totalCalls;

        @JsonProperty("tara.ocsp.circuit_breaker.failed_calls")
        private Integer failedCalls;

        @JsonProperty("tara.ocsp.circuit_breaker.not_permitted_calls")
        private Long notPermittedCalls;

        @JsonProperty("tara.ocsp.circuit_breaker.successful_calls")
        private Integer successfulCalls;
    }
}
