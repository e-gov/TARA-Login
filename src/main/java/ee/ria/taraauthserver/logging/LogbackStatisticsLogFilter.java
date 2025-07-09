package ee.ria.taraauthserver.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.filter.Filter;
import ch.qos.logback.core.spi.FilterReply;
import lombok.Setter;

public class LogbackStatisticsLogFilter extends Filter<ILoggingEvent> {

    private static final String STATISTICS_LOGGER_NAME = StatisticsLogger.class.getName();

    @Setter
    private Mode mode;

    @Override
    public FilterReply decide(ILoggingEvent event) {
        if (!isStarted()) {
            return FilterReply.NEUTRAL;
        }
        boolean isStatisticsLog = STATISTICS_LOGGER_NAME.equals(event.getLoggerName());
        if (mode == Mode.NOT_STATISTICS && isStatisticsLog) {
            return FilterReply.DENY;
        }
        if (mode == Mode.STATISTICS_ONLY && !isStatisticsLog) {
            return FilterReply.DENY;
        }
        return FilterReply.NEUTRAL;
    }

    @Override
    public void start() {
        if (mode == null) {
            addError("Mode not set for filter " + this.getName());
            return;
        }
        super.start();
    }

    public enum Mode {
        NOT_STATISTICS,
        STATISTICS_ONLY
    }

}
