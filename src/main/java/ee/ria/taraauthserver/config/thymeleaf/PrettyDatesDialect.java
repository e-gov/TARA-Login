package ee.ria.taraauthserver.config.thymeleaf;

import org.springframework.context.MessageSource;
import org.springframework.stereotype.Component;
import org.thymeleaf.dialect.AbstractDialect;
import org.thymeleaf.dialect.IExpressionObjectDialect;
import org.thymeleaf.expression.IExpressionObjectFactory;

@Component
public class PrettyDatesDialect extends AbstractDialect implements IExpressionObjectDialect {

    private final MessageSource messageSource;

    public PrettyDatesDialect(MessageSource messageSource) {
        super("tara-login-pretty-dates");
        this.messageSource = messageSource;
    }

    @Override
    public IExpressionObjectFactory getExpressionObjectFactory() {
        return new PrettyDatesExpressionFactory(messageSource);
    }
}
