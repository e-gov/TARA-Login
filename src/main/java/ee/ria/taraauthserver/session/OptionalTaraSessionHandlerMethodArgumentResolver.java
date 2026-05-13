package ee.ria.taraauthserver.session;

import org.jetbrains.annotations.NotNull;
import org.springframework.core.MethodParameter;
import org.springframework.core.ResolvableType;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.Optional;

import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Component
public class OptionalTaraSessionHandlerMethodArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return Optional.class.equals(parameter.getParameterType()) &&
                TaraSession.class.equals(ResolvableType.forMethodParameter(parameter).getGeneric(0).resolve());
    }

    @Override
    public Object resolveArgument(@NotNull MethodParameter parameter, ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        TaraSession taraSession = (TaraSession) webRequest.getAttribute(TARA_SESSION, RequestAttributes.SCOPE_SESSION);
        if (taraSession == null) {
            return Optional.<TaraSession>empty();
        }
        return Optional.of(taraSession);
    }
}
