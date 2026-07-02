package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.SPType;
import ee.ria.taraauthserver.session.TaraSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.spring6.expression.ThymeleafEvaluationContext;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import java.util.List;
import java.util.Locale;

import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.buildMockHttpSession;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.buildMockLoginRequestInfo;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

class ThymeleafTemplateRenderingTest extends BaseTest {

    @Autowired
    private SpringTemplateEngine templateEngine;

    @Autowired
    private ApplicationContext applicationContext;

    private WebContext context;

    @BeforeEach
    void setUpTemplateContext() {
        TaraSession.LoginRequestInfo loginRequestInfo = buildMockLoginRequestInfo();
        TaraSession.Institution institution = new TaraSession.Institution();
        institution.setSector(SPType.PRIVATE);
        loginRequestInfo.getClient().getMetaData().getOidcClient().setInstitution(institution);
        HttpSession session = buildMockHttpSession(loginRequestInfo);
        TaraSession taraSession = (TaraSession) session.getAttribute(TARA_SESSION);
        taraSession.setAllowedAuthMethods(List.of(AuthenticationType.values()));
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes())
                .getRequest();
        var webApplication = JakartaServletWebApplication.buildApplication(request.getServletContext());
        var webExchange = webApplication.buildExchange(request, new MockHttpServletResponse());
        context = new WebContext(webExchange, Locale.ENGLISH);
        context.setVariable(
                ThymeleafEvaluationContext.THYMELEAF_EVALUATION_CONTEXT_CONTEXT_VARIABLE_NAME,
                new ThymeleafEvaluationContext(applicationContext, DefaultConversionService.getSharedInstance()));
        context.setVariable("_csrf", new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "test-csrf-token"));
        context.setVariable("country", "EE");
        context.setVariable("mobileIdVerificationCode", "1234");
        context.setVariable("secondsToAuthFlowTimeout", 120);
    }

    @ParameterizedTest(name = "renders {0}")
    @ValueSource(strings = {
            "loginView",
            "midLoginCode",
            "sidWeb2AppCallback"
    })
    void templatesRenderUsingRealThymeleafEngine(String template) {
        templateEngine.process(template, context);
    }
}
