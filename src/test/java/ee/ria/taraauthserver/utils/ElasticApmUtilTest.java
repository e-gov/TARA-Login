package ee.ria.taraauthserver.utils;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;

class ElasticApmUtilTest {

    @Test
    void currentTimeMicros_MicrosecondsSinceUnixEpochReturned() {
        Instant instant = Instant.ofEpochSecond(999, 123_456_789);
        Clock clock = Clock.fixed(instant, ZoneId.of("Asia/Kolkata"));

        long actual = ElasticApmUtil.currentTimeMicros(clock);

        assertThat(actual).isEqualTo(999_123_456L);
    }

    @Test
    void currentMethodName_CallingMethodNameWithClassNameReturned() {
        String actual = ElasticApmUtil.currentMethodName();

        assertThat(actual)
                .isEqualTo("ElasticApmUtilTest" + "#" + "currentMethodName_CallingMethodNameWithClassNameReturned");
    }

}
