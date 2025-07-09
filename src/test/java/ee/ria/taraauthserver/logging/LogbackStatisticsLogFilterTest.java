package ee.ria.taraauthserver.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.core.spi.FilterReply;
import ee.ria.taraauthserver.authentication.AuthInitController;
import ee.ria.taraauthserver.logging.LogbackStatisticsLogFilter.Mode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogbackStatisticsLogFilterTest {

    private final LoggerContext loggerContext = new LoggerContext();
    private final Logger someRegularLogger = loggerContext.getLogger(AuthInitController.class);
    private final Logger statisticsLogger = loggerContext.getLogger(StatisticsLogger.class);

    @Test
    void modeNotSet_thenFilterFailsToStart() {
        LogbackStatisticsLogFilter filter = createFilter(null);
        assertFalse(filter.isStarted());
    }

    @ParameterizedTest
    @EnumSource(Mode.class)
    void modeSet_thenFilterStarts(Mode mode) {
        LogbackStatisticsLogFilter filter = createFilter(mode);
        assertTrue(filter.isStarted());
    }

    @Test
    void statisticsOnlyMode_regularLogItem_logItemDropped() {
        LogbackStatisticsLogFilter filter = createFilter(Mode.STATISTICS_ONLY);
        LoggingEvent loggingEvent = new LoggingEvent("foo", someRegularLogger, Level.INFO, "message", null, null);
        assertEquals(FilterReply.DENY, filter.decide(loggingEvent));
    }

    @Test
    void statisticsOnlyMode_statisticsLogItem_logItemKept() {
        LogbackStatisticsLogFilter filter = createFilter(Mode.STATISTICS_ONLY);
        LoggingEvent loggingEvent = new LoggingEvent("foo", statisticsLogger, Level.INFO, "message", null, null);
        assertEquals(FilterReply.NEUTRAL, filter.decide(loggingEvent));
    }

    @Test
    void notStatisticsMode_regularLogItem_logItemKept() {
        LogbackStatisticsLogFilter filter = createFilter(Mode.NOT_STATISTICS);
        LoggingEvent loggingEvent = new LoggingEvent("foo", someRegularLogger, Level.INFO, "message", null, null);
        assertEquals(FilterReply.NEUTRAL, filter.decide(loggingEvent));
    }

    @Test
    void notStatisticsMode_statisticsLogItem_logItemDropped() {
        LogbackStatisticsLogFilter filter = createFilter(Mode.NOT_STATISTICS);
        LoggingEvent loggingEvent = new LoggingEvent("foo", statisticsLogger, Level.INFO, "message", null, null);
        assertEquals(FilterReply.DENY, filter.decide(loggingEvent));
    }

    private LogbackStatisticsLogFilter createFilter(Mode mode) {
        LogbackStatisticsLogFilter filter = new LogbackStatisticsLogFilter();
        filter.setContext(loggerContext);
        filter.setMode(mode);
        filter.start();
        return filter;
    }

}
