package ee.ria.taraauthserver.session;

import jakarta.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;
import org.springframework.core.MethodParameter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static ee.ria.taraauthserver.session.OptionalTaraSessionHandlerMethodArgumentResolverTest.SupportsParameter.SimpleTestCase.shouldNotSupport;
import static ee.ria.taraauthserver.session.OptionalTaraSessionHandlerMethodArgumentResolverTest.SupportsParameter.SimpleTestCase.shouldSupport;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class OptionalTaraSessionHandlerMethodArgumentResolverTest {

    private final OptionalTaraSessionHandlerMethodArgumentResolver argumentResolver =
            new OptionalTaraSessionHandlerMethodArgumentResolver();

    @Nested
    class SupportsParameter {

        private static final int PARAM_INDEX_OBJECT = 0;
        private static final int PARAM_INDEX_TARA_SESSION = 1;
        private static final int PARAM_INDEX_OPTIONAL_OF_OBJECT = 2;
        private static final int PARAM_INDEX_SET_OF_TARA_SESSIONS = 3;
        private static final int PARAM_INDEX_OPTIONAL_OF_TARA_SESSION_SUB_CLASS = 4;
        private static final int PARAM_INDEX_OPTIONAL_OF_TARA_SESSION = 5;

        @SuppressWarnings("unused") // Used by `@FieldSource("TEST_CASES")`
        private static final List<SimpleTestCase> TEST_CASES = List.of(
                shouldNotSupport("Object", PARAM_INDEX_OBJECT),
                shouldNotSupport("TaraSession", PARAM_INDEX_TARA_SESSION),
                shouldNotSupport("Optional<Object>", PARAM_INDEX_OPTIONAL_OF_OBJECT),
                shouldNotSupport("Set<TaraSession>", PARAM_INDEX_SET_OF_TARA_SESSIONS),
                shouldNotSupport("Optional<TaraSessionSubClass>", PARAM_INDEX_OPTIONAL_OF_TARA_SESSION_SUB_CLASS),
                shouldSupport("Optional<TaraSession>", PARAM_INDEX_OPTIONAL_OF_TARA_SESSION)
        );

        @ParameterizedTest(name = "{0}")
        @FieldSource("TEST_CASES")
        void supportsParameter_givenType_returnsExpectedResult(SimpleTestCase testCase) {
            MethodParameter methodParameter = getMethodParameter(testCase.parameterIndex);
            boolean result = argumentResolver.supportsParameter(methodParameter);
            assertThat(result).isEqualTo(testCase.expectedResult);
        }

        private MethodParameter getMethodParameter(int parameterIndex) {
            Method method = Arrays.stream(this.getClass().getDeclaredMethods())
                    .filter(it -> "parameterHost".equals(it.getName()))
                    .findAny()
                    .orElseThrow();
            return new MethodParameter(method, parameterIndex);
        }

        // Used only for building MethodParameter objects.
        @SuppressWarnings({"unused", "OptionalUsedAsFieldOrParameterType"})
        void parameterHost(Object object, TaraSession taraSession, Optional<Object> optionalOfObject,
                           Set<TaraSession> setOfTaraSessions, Optional<TaraSessionSub> optionalOfTaraSessionSub,
                           Optional<TaraSession> optionalOfTaraSession) {}

        static class TaraSessionSub extends TaraSession {

            public TaraSessionSub() {
                super("session-id");
            }
        }

        record SimpleTestCase(
                String typeName,
                int parameterIndex,
                boolean expectedResult
        ) {

            static SimpleTestCase shouldSupport(String typeName, int parameterIndex) {
                return new SimpleTestCase(typeName, parameterIndex, true);
            }

            static SimpleTestCase shouldNotSupport(String typeName, int parameterIndex) {
                return new SimpleTestCase(typeName, parameterIndex, false);
            }

            @Override
            @Nonnull
            public String toString() {
                return "%s -> %b".formatted(typeName, expectedResult);
            }
        }

    }

    @Nested
    class ResolveArgument {

        private final MethodParameter parameter = mock(MethodParameter.class);
        private final ModelAndViewContainer mavContainer = mock(ModelAndViewContainer.class);
        private final WebDataBinderFactory binderFactory = mock(WebDataBinderFactory.class);

        @Test
        void givenSessionMissing_throwsBadRequestException() {
            ServletWebRequest servletWebRequest = createWebRequest();

            Object result = argumentResolver.resolveArgument(parameter, mavContainer, servletWebRequest, binderFactory);

            assertThat(result).isEqualTo(Optional.<TaraSession>empty());
        }

        @Test
        void givenSessionPresent_returnsSession() {
            ServletWebRequest servletWebRequest = createWebRequest();
            TaraSession expected = new TaraSession("session-id");
            servletWebRequest.setAttribute(TARA_SESSION, expected, RequestAttributes.SCOPE_SESSION);

            Object result = argumentResolver.resolveArgument(parameter, mavContainer, servletWebRequest, binderFactory);

            assertThat(result).isEqualTo(Optional.of(expected));
        }

        private static @NotNull ServletWebRequest createWebRequest() {
            return new ServletWebRequest(new MockHttpServletRequest());
        }

    }

}
