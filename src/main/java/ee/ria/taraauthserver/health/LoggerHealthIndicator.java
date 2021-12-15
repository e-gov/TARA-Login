package ee.ria.taraauthserver.health;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.util.ContextSelectorStaticBinder;
import ch.qos.logback.core.FileAppender;
import ch.qos.logback.core.status.Status;
import ch.qos.logback.core.status.StatusManager;
import ch.qos.logback.core.status.StatusUtil;
import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.HealthConfigurationProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static ch.qos.logback.core.status.StatusUtil.filterStatusListByTimeThreshold;
import static java.lang.System.currentTimeMillis;
import static java.nio.file.Paths.get;
import static org.slf4j.Logger.ROOT_LOGGER_NAME;

@Component
public class LoggerHealthIndicator extends AbstractHealthIndicator {
    private final LoggerContext loggerContext = ContextSelectorStaticBinder.getSingleton().getContextSelector().getLoggerContext();
    private final StatusManager statusManager = loggerContext.getStatusManager();
    private final StatusUtil statusUtil = new StatusUtil(statusManager);
    private final List<FileAppender<?>> fileAppenders = getLogFileAppenders();

    @Autowired
    private HealthConfigurationProperties healthConfiguration;

    public LoggerHealthIndicator() {
        super("Logger health check failed");
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {
        long threshold = currentTimeMillis() - healthConfiguration.getLoggerErrorThresholdInMillis();

        for (FileAppender<?> fileAppender : fileAppenders) {
            if (!Files.exists(get(fileAppender.getFile()))) {
                builder.down().withDetail("error", "File handle error");
                return;
            }
        }

        if (!statusUtil.isErrorFree(threshold)) {
            List<Status> statuses = filterStatusListByTimeThreshold(statusManager.getCopyOfStatusList(), threshold);
            Optional<Status> ioException = statuses.stream()
                    .filter(s -> s.getThrowable() instanceof IOException)
                    .findFirst();
            ioException.ifPresent(status -> builder.down().withDetail("error", "I/O error"));
        } else if (statusUtil.containsMatch(threshold, Status.WARN, "Failed to rename file*")) {
            builder.down().withDetail("error", "Rollover error");
        } else {
            builder.up();
        }
    }

    private List<FileAppender<?>> getLogFileAppenders() {
        List<FileAppender<?>> appenders = new ArrayList<>();
        Logger rootLogger = loggerContext.getLogger(ROOT_LOGGER_NAME);
        rootLogger.iteratorForAppenders().forEachRemaining(a -> {
            if (a instanceof FileAppender) {
                appenders.add((FileAppender<?>) a);
            }
        });
        return List.copyOf(appenders);
    }
}
