package ee.ria.taraauthserver.health;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.TimeGauge;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.Double.valueOf;
import static java.time.Duration.ofSeconds;
import static java.time.Instant.now;
import static java.time.Instant.ofEpochMilli;
import static java.util.Map.of;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static java.util.stream.Collectors.toList;

@Slf4j
@Component
@ConditionalOnExpression("'${management.endpoints.web.exposure.include}'.contains('heartbeat')")
@Endpoint(id = "heartbeat", enableByDefault = false)
public class ApplicationHealthEndpoint {

    @Autowired
    private HealthContributorRegistry healthContributorRegistry;

    @Autowired
    private GitProperties gitProperties;

    @Autowired
    private BuildProperties buildProperties;

    @Autowired
    private MeterRegistry meterRegistry;

    @Autowired
    private TruststoreHealthIndicator truststoreHealthIndicator;

    @Value("${management.endpoint.health.show-details:never}")
    private String showDetails;

    @ReadOperation(produces = "application/json")
    public ResponseEntity<Map<String, Object>> health() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        Map<String, Object> details = getHealthDetails();
        if (details.containsKey("status") && details.get("status").equals(Status.UP.getCode())) {
            return ResponseEntity.status(200).headers(headers).body(details);
        } else {
            return ResponseEntity.status(503).headers(headers).body(details);
        }

    }

    private Map<String, Object> getHealthDetails() {
        Map<String, Object> details = new HashMap<>();
        details.put("status", getAggregatedStatus().getCode());
        details.put("name", buildProperties.getName());
        details.put("version", buildProperties.getVersion());
        details.put("buildTime", buildProperties.getTime());
        details.put("commitId", gitProperties.getCommitId());
        details.put("commitBranch", gitProperties.getBranch());
        details.put("currentTime", now());
        details.computeIfAbsent("startTime", v -> getServiceStartTime());
        details.computeIfAbsent("upTime", v -> getServiceUpTime());
        details.computeIfAbsent("warnings", v -> getTrustStoreWarnings());
        details.put("dependencies", getDependencies());
        return details;
    }

    private List<String> getTrustStoreWarnings() {
        List<String> certificateExpirationWarnings = truststoreHealthIndicator.getCertificateExpirationWarnings();
        return certificateExpirationWarnings.isEmpty() ? null : certificateExpirationWarnings;
    }

    private String getServiceStartTime() {
        TimeGauge startTime = meterRegistry.find("process.start.time").timeGauge();
        return startTime != null ? ofEpochMilli(valueOf(startTime.value(MILLISECONDS)).longValue()).toString() : null;
    }

    private String getServiceUpTime() {
        TimeGauge upTime = meterRegistry.find("process.uptime").timeGauge();
        return upTime != null ? ofSeconds(valueOf(upTime.value(SECONDS)).longValue()).toString() : null;
    }

    private Status getAggregatedStatus() {
        Optional<Status> anyDown = healthContributorRegistry.stream()
                .filter(hc -> hc.getContributor() instanceof HealthIndicator)
                .map(hc -> (HealthIndicator) hc.getContributor())
                .map(hi -> hi.health().getStatus())
                .filter(Status.DOWN::equals)
                .findAny();
        return anyDown.isPresent() ? Status.DOWN : Status.UP;
    }

    private List<Map<String, ?>> getDependencies() {
        return healthContributorRegistry
                .stream()
                .filter(hc -> hc.getContributor() instanceof HealthIndicator)
                .map(hc -> {
                    HealthIndicator healthIndicator = (HealthIndicator) hc.getContributor();
                    Status status = healthIndicator.health().getStatus();

                    if ("always".equals(showDetails)) {
                        return of("name", hc.getName(),
                                "status", status.getCode(),
                                "details", healthIndicator.health().getDetails());
                    } else {
                        return of("name", hc.getName(), "status", status.getCode());
                    }
                })
                .collect(toList());
    }
}
