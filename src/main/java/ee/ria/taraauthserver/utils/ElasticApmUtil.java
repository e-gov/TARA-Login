package ee.ria.taraauthserver.utils;

import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.jetbrains.annotations.NotNull;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@UtilityClass
public class ElasticApmUtil {

    public static long currentTimeMicros(Clock clock) {
        return ChronoUnit.MICROS.between(Instant.EPOCH, Instant.now(clock));
    }

    public static String currentMethodName() {
        StackWalker walker = StackWalker.getInstance();
        return walker.walk(frames -> frames
                        .filter(frame -> !ElasticApmUtil.class.getName().equals(frame.getClassName()))
                        .findFirst()
                        .map(ElasticApmUtil::getMethodName))
                .orElseThrow();
    }

    @SneakyThrows
    private static @NotNull String getMethodName(StackWalker.StackFrame frame) {
        String className = Class.forName(frame.getClassName()).getSimpleName();
        return className + "#" + frame.getMethodName();
    }

}
