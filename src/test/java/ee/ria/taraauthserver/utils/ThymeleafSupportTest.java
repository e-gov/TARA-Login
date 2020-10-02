package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.config.AuthenticationType;
import ee.ria.taraauthserver.session.AuthSession;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static ee.ria.taraauthserver.session.MockSessionUtils.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.web.context.request.RequestAttributes.SCOPE_REQUEST;

@Slf4j
@ExtendWith(MockitoExtension.class)
class ThymeleafSupportTest extends BaseTest {

    private ThymeleafSupport thymeleafSupport;
    private AuthSession testSession;

    @BeforeEach
    public void setUp() {
        thymeleafSupport = new ThymeleafSupport();
        testSession = new AuthSession();
        testSession.setLoginRequestInfo(getMockLoginRequestInfo());
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        createMockHttpSession(testSession);
    }

    @Test
    void isAuthMethodAllowed_falseWhenSessionNotPresent() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest(), new MockHttpServletResponse()));
        for (AuthenticationType authMethod : AuthenticationType.values()) {
            assertFalse(thymeleafSupport.isAuthMethodAllowed(authMethod), "Authmethod " + authMethod + " should NOT be allowed");
        }
    }

    @Test
    void isAuthMethodAllowed_trueWhenAuthMethodListedInSession() {
        for (AuthenticationType authMethod : AuthenticationType.values()) {
            testSession.setAllowedAuthMethods(List.of(authMethod));
            assertTrue(thymeleafSupport.isAuthMethodAllowed(authMethod), "Authmethod " + authMethod + " should be allowed");
        }
    }

    @Test
    void isAuthMethodAllowed_falseWhenAuthMethodNotListedInSession() {
        for (AuthenticationType authMethod : AuthenticationType.values()) {
            assertFalse(thymeleafSupport.isAuthMethodAllowed(authMethod), "Authmethod " + authMethod + " should NOT be allowed");
        }
    }

    @Test
    void getServiceName_returnsNullWhenSessionMissing() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest(), new MockHttpServletResponse()));

        assertEquals(null, thymeleafSupport.getServiceName());
    }

    @Test
    void getServiceName_returnsNullWhenNoClientNameSet() {
        AuthSession.LoginRequestInfo mockLoginRequestInfo = getMockLoginRequestInfo();
        mockLoginRequestInfo.getClient().getMetaData().getOidcClient().setName(null);
        testSession.setLoginRequestInfo(mockLoginRequestInfo);
        createMockHttpSession(testSession);

        assertEquals(null, thymeleafSupport.getServiceName());
    }

    @Test
    void getServiceName_returnsClientNameWhenClientNameSetWithoutTranslations() {
        AuthSession.LoginRequestInfo mockLoginRequestInfo = getMockLoginRequestInfo();
        mockLoginRequestInfo.getClient().getMetaData().getOidcClient().setName(MOCK_CLIENT_NAME);
        mockLoginRequestInfo.getClient().getMetaData().getOidcClient().setNameTranslations(new HashMap<>());
        testSession.setLoginRequestInfo(mockLoginRequestInfo);
        createMockHttpSession(testSession);

        assertEquals(MOCK_CLIENT_NAME, thymeleafSupport.getServiceName());
    }

    @Test
    void getServiceName_returnsClientNameWithTranslationWhenTranslationExists() {
        AuthSession.LoginRequestInfo mockLoginRequestInfo = getMockLoginRequestInfo();
        mockLoginRequestInfo.getClient().getMetaData().getOidcClient().setName(MOCK_CLIENT_NAME);
        testSession.setLoginRequestInfo(mockLoginRequestInfo);
        createMockHttpSession(testSession);

        assertEquals(MOCK_CLIENT_NAME_EN, thymeleafSupport.getServiceName());
    }

    @Test
    void getHomeUrl_returnsNoUrlWhenSessionMissing() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest(), new MockHttpServletResponse()));

        assertEquals("#", thymeleafSupport.getHomeUrl());
    }

    @Test
    void getBackUrl_returnsAuthInitWhenSessionPresent() {
        testSession.setLoginRequestInfo(getMockLoginRequestInfo());
        createMockHttpSession(testSession);

        assertEquals("/auth/init?login_challenge=" + MOCK_CHALLENGE, thymeleafSupport.getBackUrl());
    }

    @Test
    void getBackUrl_returnsNoUrlWhenSessionMissing() {
        createMockHttpSession(new AuthSession());

        assertEquals("#", thymeleafSupport.getBackUrl());
    }

    @Test
    void getHomeUrl_returnsLegacyReturnUrlWhenPresent() {
        testSession.setLoginRequestInfo(getMockLoginRequestInfo());
        createMockHttpSession(testSession);

        assertEquals(MOCK_CLIENT_LEGACY_URL, thymeleafSupport.getHomeUrl());
    }

    @Test
    void getHomeUrl_returnsLegacyReturnsUserCancelLinkWhenLegacyNotPresent() {
        AuthSession.LoginRequestInfo mockLoginRequestInfo = getMockLoginRequestInfo();
        mockLoginRequestInfo.getClient().getMetaData().getOidcClient().setLegacyReturnUrl(null);
        testSession.setLoginRequestInfo(mockLoginRequestInfo);
        createMockHttpSession(testSession);

        assertEquals("/auth/reject?error_code=user_cancel", thymeleafSupport.getHomeUrl());
    }
}