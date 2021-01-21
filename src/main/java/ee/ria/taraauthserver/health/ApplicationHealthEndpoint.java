package ee.ria.taraauthserver.health;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.TimeGauge;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.boot.actuate.health.HealthContributorRegistry;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.NamedContributor;
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
import java.util.stream.Collectors;

import static java.lang.Double.valueOf;
import static java.time.Duration.ofSeconds;
import static java.time.Instant.now;
import static java.time.Instant.ofEpochMilli;
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
        Map<String, Status> healthIndicatorStatuses = getHealthIndicatorStatuses();
        Map<String, Object> details = new HashMap<>();
        details.put("status", getAggregatedStatus(healthIndicatorStatuses).getCode());
        details.put("name", buildProperties.getName());
        details.put("version", buildProperties.getVersion());
        details.put("buildTime", buildProperties.getTime());
        details.put("commitId", gitProperties.getCommitId());
        details.put("commitBranch", gitProperties.getBranch());
        details.put("currentTime", now());
        details.computeIfAbsent("startTime", v -> getServiceStartTime());
        details.computeIfAbsent("upTime", v -> getServiceUpTime());
        details.computeIfAbsent("warnings", v -> getTrustStoreWarnings());
        details.put("dependencies", getFormattedStatuses(healthIndicatorStatuses));
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

    private Map<String, Status> getHealthIndicatorStatuses() {
        return healthContributorRegistry.stream()
                .filter(hc -> hc.getContributor() instanceof HealthIndicator)
                .collect(Collectors.toMap(NamedContributor::getName,
                        healthContributorNamedContributor -> ((HealthIndicator) healthContributorNamedContributor
                                .getContributor()).health().getStatus()));
    }

    private Status getAggregatedStatus(Map<String, Status> healthIndicatorStatuses) {
        Optional<Status> anyDown = healthIndicatorStatuses.values().stream()
                .filter(status -> Status.DOWN.equals(status))
                .findAny();
        return anyDown.isPresent() ? Status.DOWN : Status.UP;
    }

    private List<HashMap<String, String>> getFormattedStatuses(Map<String, Status> healthIndicatorStatuses) {
        return healthIndicatorStatuses.entrySet().stream()
                .map(healthIndicator -> new HashMap<String, String>() {{
                    put("name", healthIndicator.getKey());
                    put("status", healthIndicator.getValue().getCode());
                }}).collect(toList());
    }
}
