package ee.ria.taraauthserver.logging;

import lombok.NoArgsConstructor;
import net.logstash.logback.mask.ValueMasker;
import org.apache.commons.codec.digest.DigestUtils;
import tools.jackson.core.TokenStreamContext;

import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.MASKED_FIELD_NAMES;

@NoArgsConstructor
public class LogbackFieldValueMasker implements ValueMasker {
    public static final String MASKED_VALUE = "MASKED_VALUE";

    @Override
    public Object mask(TokenStreamContext context, Object value) {
        // NOTE: Can be further constrained by using context.getParent().getCurrentName() + context.getCurrentName()
        if (context.hasCurrentName() && MASKED_FIELD_NAMES != null && MASKED_FIELD_NAMES.contains(context.currentName())) {
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
