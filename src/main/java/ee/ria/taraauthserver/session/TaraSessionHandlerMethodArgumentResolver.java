package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import org.jetbrains.annotations.NotNull;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Component
public class TaraSessionHandlerMethodArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return TaraSession.class.equals(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(@NotNull MethodParameter parameter, ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        TaraSession taraSession = (TaraSession) webRequest.getAttribute(TARA_SESSION, RequestAttributes.SCOPE_SESSION);
        if (taraSession == null) {
            throw new BadRequestException(SESSION_NOT_FOUND, "Invalid session");
        }
        return taraSession;
    }
}
