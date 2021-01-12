package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.session.TaraSession;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

import static ee.ria.taraauthserver.session.MockSessionUtils.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static org.junit.jupiter.api.Assertions.*;

@Slf4j
@ExtendWith(MockitoExtension.class)
class ThymeleafSupportTest {
    private ThymeleafSupport thymeleafSupport;
    private TaraSession testSession;

    @BeforeEach
    public void setUp() {
        thymeleafSupport = new ThymeleafSupport();
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        HttpSession mockHttpSession = createMockHttpSession(getMockLoginRequestInfo());
        testSession = (TaraSession) mockHttpSession.getAttribute(TARA_SESSION);
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
            testSession.setAllowedAuthMethods(List.of(authMethod)); // TODO:
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
        TaraSession.LoginRequestInfo mockLoginRequestInfo = getMockLoginRequestInfo();
        mockLoginRequestInfo.getClient().getMetaData().getOidcClient().setName(null);
        createMockHttpSession(mockLoginRequestInfo);
        assertEquals(null, thymeleafSupport.getServiceName());
    }

    @Test
    void getServiceName_returnsClientNameWhenClientNameSetWithoutTranslations() {
        TaraSession.LoginRequestInfo mockLoginRequestInfo = getMockLoginRequestInfo();
        mockLoginRequestInfo.getClient().getMetaData().getOidcClient().setName(MOCK_CLIENT_NAME);
        mockLoginRequestInfo.getClient().getMetaData().getOidcClient().setNameTranslations(new HashMap<>());
        createMockHttpSession(mockLoginRequestInfo);
        assertEquals(MOCK_CLIENT_NAME, thymeleafSupport.getServiceName());
    }

    @Test
    void getServiceName_returnsClientNameWithTranslationWhenTranslationExists() {
        TaraSession.LoginRequestInfo mockLoginRequestInfo = getMockLoginRequestInfo();
        mockLoginRequestInfo.getClient().getMetaData().getOidcClient().setName(MOCK_CLIENT_NAME);
        createMockHttpSession(mockLoginRequestInfo);
        assertEquals(MOCK_CLIENT_NAME_EN, thymeleafSupport.getServiceName());
    }

    @Test
    void getHomeUrl_returnsNoUrlWhenSessionMissing() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest(), new MockHttpServletResponse()));

        assertEquals("#", thymeleafSupport.getHomeUrl());
    }

    @Test
    void getBackUrl_returnsAuthInitWhenSessionPresent() {
        createMockHttpSession(getMockLoginRequestInfo());
        assertEquals("/auth/init?login_challenge=" + MOCK_CHALLENGE, thymeleafSupport.getBackUrl());
    }

    @Test
    void getBackUrl_returnsNoUrlWhenSessionMissing() {
        createMockHttpSession(null);
        assertEquals("#", thymeleafSupport.getBackUrl());
    }

    @Test
    void getHomeUrl_returnsLegacyReturnUrlWhenPresent() {
        createMockHttpSession(getMockLoginRequestInfo());
        assertEquals(MOCK_CLIENT_LEGACY_URL, thymeleafSupport.getHomeUrl());
    }

    @Test
    void getHomeUrl_returnsLegacyReturnsUserCancelLinkWhenLegacyNotPresent() {
        TaraSession.LoginRequestInfo mockLoginRequestInfo = getMockLoginRequestInfo();
        mockLoginRequestInfo.getClient().getMetaData().getOidcClient().setLegacyReturnUrl(null);
        createMockHttpSession(mockLoginRequestInfo);
        assertEquals("/auth/reject?error_code=user_cancel", thymeleafSupport.getHomeUrl());
    }
}