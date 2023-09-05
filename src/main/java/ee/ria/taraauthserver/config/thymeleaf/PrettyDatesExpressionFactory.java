package ee.ria.taraauthserver.config.thymeleaf;

import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.thymeleaf.context.IExpressionContext;
import org.thymeleaf.expression.IExpressionObjectFactory;

import java.util.Set;

@RequiredArgsConstructor
public class PrettyDatesExpressionFactory implements IExpressionObjectFactory {

    private static final String EXPRESSION_OBJECT_NAME = "prettyDates";

    private final MessageSource messageSource;

    @Override
    public Set<String> getAllExpressionObjectNames() {
        return Set.of(EXPRESSION_OBJECT_NAME);
    }

    @Override
    public Object buildObject(IExpressionContext context, String expressionObjectName) {
        if (EXPRESSION_OBJECT_NAME.equals(expressionObjectName)) {
            return new PrettyDatesExpression(messageSource);
        }
        return null;
    }

    @Override
    public boolean isCacheable(String expressionObjectName) {
        return EXPRESSION_OBJECT_NAME.equals(expressionObjectName);
    }
}
