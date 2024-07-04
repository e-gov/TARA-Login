package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.authentication.legalperson.xroad.BusinessRegistryService;
import ee.ria.taraauthserver.config.properties.LegalPersonProperties;
import freemarker.template.TemplateExceptionHandler;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

import javax.net.ssl.SSLContext;
import java.io.IOException;

import static freemarker.template.Configuration.VERSION_2_3_28;

@Configuration
@ConditionalOnProperty(value = "tara.legal-person-authentication.enabled", matchIfMissing = true)
public class LegalPersonConfiguration {

    @Bean
    public freemarker.template.Configuration freemarkerConfiguration() throws IOException {
        freemarker.template.Configuration freemarkerConfiguration = new freemarker.template.Configuration(VERSION_2_3_28);
        freemarkerConfiguration.setClassForTemplateLoading(this.getClass(), "/xroad-request-templates");
        freemarkerConfiguration.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        freemarkerConfiguration.setDefaultEncoding("UTF-8");
        return freemarkerConfiguration;
    }

    @Bean
    public BusinessRegistryService eBusinessRegistryService(freemarker.template.Configuration freemarkerConfiguration,
                                                            LegalPersonProperties legalPersonProperties, SSLContext sslContext) {
        return new BusinessRegistryService(freemarkerConfiguration, legalPersonProperties, sslContext);
    }
}
