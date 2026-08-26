package ee.ria.taraauthserver.authentication.eudi;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Outcome;
import co.elastic.apm.api.Scope;
import co.elastic.apm.api.Span;
import ee.ria.taraauthserver.utils.ElasticApmUtil;
import lombok.experimental.UtilityClass;

import java.time.Clock;
import java.util.function.Supplier;

@UtilityClass
class EudiSpans {

    static <T> T inSpan(Clock clock, String action, String name, Supplier<T> call) {
        Span span = ElasticApm.currentSpan().startSpan("app", "EUDI", action)
                .setName(name)
                .setStartTimestamp(ElasticApmUtil.currentTimeMicros(clock));
        try (Scope scope = span.activate()) {
            return call.get();
        } catch (Exception e) {
            span.captureException(e);
            span.setOutcome(Outcome.FAILURE);
            throw e;
        } finally {
            span.end(ElasticApmUtil.currentTimeMicros(clock));
        }
    }

}
