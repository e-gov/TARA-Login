package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.session.OptionalTaraSessionHandlerMethodArgumentResolver;
import ee.ria.taraauthserver.session.TaraSessionHandlerMethodArgumentResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Component
@RequiredArgsConstructor
public class ArgumentResolverConfiguration implements WebMvcConfigurer {

    private final TaraSessionHandlerMethodArgumentResolver taraSessionHandlerMethodArgumentResolver;
    private final OptionalTaraSessionHandlerMethodArgumentResolver optionalTaraSessionHandlerMethodArgumentResolver;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(taraSessionHandlerMethodArgumentResolver);
        resolvers.add(optionalTaraSessionHandlerMethodArgumentResolver);
    }
}
