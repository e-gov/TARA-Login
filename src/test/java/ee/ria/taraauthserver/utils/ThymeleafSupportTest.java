package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.ria.taraauthserver.session.TaraSession;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;

import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.MOCK_CLIENT_LEGACY_URL;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.MOCK_CLIENT_NAME_EN;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.buildMockHttpSession;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.buildMockLoginRequestInfo;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@Slf4j
@ExtendWith(MockitoExtension.class)
class ThymeleafSupportTest {

    @InjectMocks
    private ThymeleafSupport thymeleafSupport;

    @Mock
    private SmartIdConfigurationProperties configurationProperties;

    private TaraSession testSession;

    @BeforeEach
    public void setUp() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
        HttpSession mockHttpSession = buildMockHttpSession(buildMockLoginRequestInfo());
        testSession = (TaraSession) mockHttpSession.getAttribute(TARA_SESSION);
    }

    @Test
    void getEnabledAuthMethods_WhenSessionNotPresent_NoneEnabled() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest(), new MockHttpServletResponse()));
        assertFalse(thymeleafSupport.getEnabledAuthMethods().idCard());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().mobileId());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().smartId());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().eidas());
    }

    @Test
    void getEnabledAuthMethods_WhenSingleAuthMethodListedInSession_OnlyThisAuthMethodEnabled() {
        setupConfigurationProperties();

        testSession.setAllowedAuthMethods(List.of(AuthenticationType.ID_CARD));
        assertTrue(thymeleafSupport.getEnabledAuthMethods().idCard());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().mobileId());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().smartId());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().eidas());

        testSession.setAllowedAuthMethods(List.of(AuthenticationType.SMART_ID));
        assertFalse(thymeleafSupport.getEnabledAuthMethods().idCard());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().mobileId());
        assertTrue(thymeleafSupport.getEnabledAuthMethods().smartId());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().eidas());

        testSession.setAllowedAuthMethods(List.of(AuthenticationType.MOBILE_ID));
        assertFalse(thymeleafSupport.getEnabledAuthMethods().idCard());
        assertTrue(thymeleafSupport.getEnabledAuthMethods().mobileId());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().smartId());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().eidas());

        testSession.setAllowedAuthMethods(List.of(AuthenticationType.EIDAS));
        assertFalse(thymeleafSupport.getEnabledAuthMethods().idCard());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().mobileId());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().smartId());
        assertTrue(thymeleafSupport.getEnabledAuthMethods().eidas());
    }

    @Test
    void getEnabledAuthMethods_WhenNoAuthMethodsListedInSession_NoneEnabled() {
        assertFalse(thymeleafSupport.getEnabledAuthMethods().idCard());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().mobileId());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().smartId());
        assertFalse(thymeleafSupport.getEnabledAuthMethods().eidas());
    }

    @Test
    void getServiceName_returnsNullWhenSessionMissing() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest(), new MockHttpServletResponse()));
        assertNull(thymeleafSupport.getServiceName());
    }

    @Test
    void getServiceName_returnsDefaultWhenNoClientNameSet() {
        TaraSession.LoginRequestInfo mockLoginRequestInfo = buildMockLoginRequestInfo();
        mockLoginRequestInfo.getClient().getMetaData().getOidcClient().setNameTranslations(new HashMap<>());
        buildMockHttpSession(mockLoginRequestInfo);
        assertNull(thymeleafSupport.getServiceName());
    }

    @Test
    void getServiceName_returnsClientNameWithTranslationWhenTranslationExists() {
        TaraSession.LoginRequestInfo mockLoginRequestInfo = buildMockLoginRequestInfo();
        buildMockHttpSession(mockLoginRequestInfo);
        assertEquals(MOCK_CLIENT_NAME_EN, thymeleafSupport.getServiceName());
    }

    @Test
    void getHomeUrl_returnsNoUrlWhenSessionMissing() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest(), new MockHttpServletResponse()));

        assertEquals("#", thymeleafSupport.getHomeUrl());
    }

    @Test
    void getHomeUrl_returnsLegacyReturnUrlWhenPresent() {
        buildMockHttpSession(buildMockLoginRequestInfo());
        assertEquals(MOCK_CLIENT_LEGACY_URL, thymeleafSupport.getHomeUrl());
    }

    @Test
    void getHomeUrl_returnsLegacyReturnsUserCancelLinkWhenLegacyNotPresent() {
        TaraSession.LoginRequestInfo mockLoginRequestInfo = buildMockLoginRequestInfo();
        mockLoginRequestInfo.getClient().getMetaData().getOidcClient().setLegacyReturnUrl(null);
        buildMockHttpSession(mockLoginRequestInfo);
        assertEquals("/auth/reject?error_code=user_cancel", thymeleafSupport.getHomeUrl());
    }

    @Test
    void getBackUrl_returnsHashWhenSessionMissingOrInvalid() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest(), new MockHttpServletResponse()));
        assertEquals("#", thymeleafSupport.getBackUrl(), "Back URL should be '#' when session is missing");

        TaraSession.LoginRequestInfo mockLoginRequestInfo = buildMockLoginRequestInfo();
        mockLoginRequestInfo.setLoginChallengeExpired(true);
        HttpSession mockHttpSession = buildMockHttpSession(mockLoginRequestInfo);
        testSession = (TaraSession) mockHttpSession.getAttribute(TARA_SESSION);
        assertEquals("#", thymeleafSupport.getBackUrl(), "Back URL should be '#' when login challenge is expired");
    }

    @ParameterizedTest
    @ValueSource(strings = {"et", "en", "ru"})
    void getBackUrl_returnsInitAuthUrlWhenSessionValid(String language) {
        TaraSession.LoginRequestInfo mockLoginRequestInfo = buildMockLoginRequestInfo();
        mockLoginRequestInfo.setLoginChallengeExpired(false);
        mockLoginRequestInfo.setChallenge("valid-challenge");
        HttpSession mockHttpSession = buildMockHttpSession(mockLoginRequestInfo);
        testSession = (TaraSession) mockHttpSession.getAttribute(TARA_SESSION);
        testSession.setChosenLanguage(language);

        String expectedUrl = "/auth/init?login_challenge=valid-challenge&lang=" + language;
        assertEquals(expectedUrl, thymeleafSupport.getBackUrl(), "Back URL should match the expected initialization URL");
    }

    private void setupConfigurationProperties() {
        SmartIdConfigurationProperties.NotificationBased notificationBased = new SmartIdConfigurationProperties.NotificationBased();
        notificationBased.setEnabled(true);
        when(configurationProperties.getNotificationBased()).thenReturn(notificationBased);
        SmartIdConfigurationProperties.Web2App web2App = new SmartIdConfigurationProperties.Web2App();
        web2App.setEnabled(true);
        when(configurationProperties.getWeb2app()).thenReturn(web2App);
        SmartIdConfigurationProperties.QrCode qrCode = new SmartIdConfigurationProperties.QrCode();
        qrCode.setEnabled(true);
        when(configurationProperties.getQrCode()).thenReturn(qrCode);
    }
}
