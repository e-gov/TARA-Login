package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.error.exceptions.BadRequestException;
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

import static ee.ria.taraauthserver.error.ErrorCode.SESSION_NOT_FOUND;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static ee.ria.taraauthserver.session.TaraSessionHandlerMethodArgumentResolverTest.SupportsParameter.SimpleTestCase.shouldNotSupport;
import static ee.ria.taraauthserver.session.TaraSessionHandlerMethodArgumentResolverTest.SupportsParameter.SimpleTestCase.shouldSupport;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

class TaraSessionHandlerMethodArgumentResolverTest {

    private final TaraSessionHandlerMethodArgumentResolver argumentResolver =
            new TaraSessionHandlerMethodArgumentResolver();

    @Nested
    class SupportsParameter {

        private static final int PARAM_INDEX_OBJECT = 0;
        private static final int PARAM_INDEX_TARA_SESSION = 1;
        private static final int PARAM_INDEX_TARA_SESSION_SUB_CLASS = 2;
        private static final int PARAM_INDEX_OPTIONAL_OF_TARA_SESSION = 3;

        @SuppressWarnings("unused") // Used by `@FieldSource("TEST_CASES")`
        private static final List<SimpleTestCase> TEST_CASES = List.of(
                shouldNotSupport("Object", PARAM_INDEX_OBJECT),
                shouldSupport("TaraSession", PARAM_INDEX_TARA_SESSION),
                shouldNotSupport("TaraSessionSubClass", PARAM_INDEX_TARA_SESSION_SUB_CLASS),
                shouldNotSupport("Optional<TaraSession>", PARAM_INDEX_OPTIONAL_OF_TARA_SESSION)
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
        void parameterHost(Object object, TaraSession taraSession, TaraSessionSub taraSessionSub,
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

            assertThatExceptionOfType(BadRequestException.class)
                    .isThrownBy(() -> argumentResolver.resolveArgument(parameter, mavContainer, servletWebRequest, binderFactory))
                    .withMessage("Invalid session")
                    .satisfies(ex -> assertThat(ex.getErrorCode()).isEqualTo(SESSION_NOT_FOUND));
        }

        @Test
        void givenSessionPresent_returnsSession() {
            ServletWebRequest servletWebRequest = createWebRequest();
            TaraSession expected = new TaraSession("session-id");
            servletWebRequest.setAttribute(TARA_SESSION, expected, RequestAttributes.SCOPE_SESSION);

            Object result = argumentResolver.resolveArgument(parameter, mavContainer, servletWebRequest, binderFactory);

            assertThat(result).isEqualTo(expected);
        }

        private static @NotNull ServletWebRequest createWebRequest() {
            return new ServletWebRequest(new MockHttpServletRequest());
        }

    }

}
