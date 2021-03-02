package ee.ria.taraauthserver.session.logging;

import com.fasterxml.jackson.core.JsonStreamContext;
import lombok.NoArgsConstructor;
import net.logstash.logback.mask.ValueMasker;
import org.apache.commons.codec.digest.DigestUtils;

import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.MASKED_FIELD_NAMES;

@NoArgsConstructor
public class LogbackFieldValueMasker implements ValueMasker {
    public static final String MASKED_VALUE = "MASKED_VALUE";

    @Override
    public Object mask(JsonStreamContext context, Object value) {
        // NOTE: Can be further constrained by using context.getParent().getCurrentName() + context.getCurrentName()
        if (context.hasCurrentName() && MASKED_FIELD_NAMES != null && MASKED_FIELD_NAMES.contains(context.getCurrentName())) {
            if (value instanceof String) {
                return DigestUtils.sha256Hex((String) value);
            } else {
                return MASKED_VALUE;
            }
        } else {
            return null;
        }
    }
}