package ee.ria.taraauthserver;

import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesBindingPostProcessor;
import org.springframework.context.ApplicationContext;

@RequiredArgsConstructor
public class ConfigurationPropertiesReloader {

    private final ConfigurationPropertiesBindingPostProcessor configurationPropertiesBindingPostProcessor;
    private final ApplicationContext applicationContext;

    public void reload(Object targetBean) {
        for (String beanName : applicationContext.getBeanDefinitionNames()) {
            Object bean = applicationContext.getBean(beanName);
            // Use `==` instead of `.equals()` as we want to find the same object
            if (bean != targetBean) {
                continue;
            }
            ConfigurationProperties configurationPropertiesAnnotation =
                    applicationContext.findAnnotationOnBean(beanName, ConfigurationProperties.class);
            if (configurationPropertiesAnnotation == null) {
                throw new IllegalArgumentException(
                        "Bean '" + beanName + "' is not annotated with @" +
                                ConfigurationProperties.class.getSimpleName());
            }
            reloadConfigurationPropertiesBean(bean, beanName);
            return;
        }
        throw new IllegalArgumentException("Unable to find bean definition");
    }

    private void reloadConfigurationPropertiesBean(@NotNull Object bean, @NotNull String beanName) {
        configurationPropertiesBindingPostProcessor.postProcessBeforeInitialization(bean, beanName);
    }

}
