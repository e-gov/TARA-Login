package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultHandler;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@Slf4j
public class MockSessionUtils {

    public static final String MOCK_LOGIN_CHALLENGE = "abcdefg098AAdsCC";
    public static final String MOCK_CHALLENGE = "123456abcdefg";
    public static final String MOCK_CLIENT_ID = "openIdDemo";
    public static final String MOCK_CLIENT_NAME = "institution.name";
    public static final String MOCK_CLIENT_NAME_EN = "institution.name.en";
    public static final String MOCK_CLIENT_LEGACY_URL = "http://legacy.url";
    public static final String MOCK_CLIENT_NAME_ET = "institution.name.et";
    public static final String MOCK_CLIENT_NAME_RU = "institution.name.ru";
    public static final String MOCK_CLIENT_SHORTNAME = "institution.short.name";
    public static final String MOCK_CLIENT_SHORTNAME_EN = "institution.shortname.en";
    public static final String MOCK_CLIENT_SHORTNAME_ET = "institution.shortname.et";
    public static final String MOCK_CLIENT_SHORTNAME_RU = "institution.shortname.ru";
    public static final String MOCK_NATURAL_PERSON_ID_CODE = "47101010033";
    public static final String MOCK_NATURAL_PERSON_FIRSTNAME = "Mari-Liis";
    public static final String MOCK_NATURAL_PERSON_LASTNAME = "Männik";
    public static final LocalDate MOCK_NATURAL_PERSON_DATE_OF_BIRTH = LocalDate.of(1971, 1, 1);


    public static TaraSession.LoginRequestInfo getMockLoginRequestInfo() {
        TaraSession.LoginRequestInfo loginRequestInfo = new TaraSession.LoginRequestInfo();
        loginRequestInfo.setChallenge(MOCK_CHALLENGE);

        TaraSession.Client client = new TaraSession.Client();
        TaraSession.MetaData metaData = new TaraSession.MetaData();
        TaraSession.OidcClient oidcClient = new TaraSession.OidcClient();

        oidcClient.setName(MOCK_CLIENT_NAME);
        oidcClient.setNameTranslations(Map.of(
                "en", MOCK_CLIENT_NAME_EN,
                "et", MOCK_CLIENT_NAME_ET,
                "ru", MOCK_CLIENT_NAME_RU
        ));
        oidcClient.setShortName(MOCK_CLIENT_SHORTNAME);
        oidcClient.setShortNameTranslations(Map.of(
                "en", MOCK_CLIENT_SHORTNAME_EN,
                "et", MOCK_CLIENT_SHORTNAME_ET,
                "ru", MOCK_CLIENT_SHORTNAME_RU));
        oidcClient.setLegacyReturnUrl(MOCK_CLIENT_LEGACY_URL);

        metaData.setOidcClient(oidcClient);
        client.setMetaData(metaData);
        loginRequestInfo.setClient(client);
        return loginRequestInfo;
    }

    public static void createMockHttpSession(TaraSession session) {
        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        HttpSession httpSession = request.getSession(true);
        httpSession.setAttribute(TARA_SESSION, session);
        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
    }

    @NotNull
    public static TaraSession.AuthenticationResult getMockCredential() {
        return getMockCredential(
                MOCK_NATURAL_PERSON_ID_CODE,
                MOCK_NATURAL_PERSON_FIRSTNAME,
                MOCK_NATURAL_PERSON_LASTNAME,
                MOCK_NATURAL_PERSON_DATE_OF_BIRTH);
    }

    public static TaraSession.AuthenticationResult getMockCredential(String idCode, String firstName, String lastName, LocalDate dateOfBirth) {
        TaraSession.AuthenticationResult credential = new TaraSession.AuthenticationResult();
        credential.setIdCode(idCode);
        credential.setFirstName(firstName);
        credential.setLastName(lastName);
        credential.setDateOfBirth(dateOfBirth);
        credential.setAcr(LevelOfAssurance.HIGH);
        credential.setAmr(AuthenticationType.MobileID);
        credential.setSubject("EE" + idCode);
        return credential;
    }

    public static MockHttpSession getMockHttpSession(TaraAuthenticationState authSessionStatus) {
        return getMockHttpSession(authSessionStatus, getMockCredential());
    }

    @NotNull
    public static MockHttpSession getMockHttpSession(TaraAuthenticationState authSessionStatus, TaraSession.AuthenticationResult credential) {
        return getMockHttpSession(authSessionStatus, credential, List.of("oidc"));
    }

    @NotNull
    public static MockHttpSession getMockHttpSession(
            TaraAuthenticationState authSessionStatus,
            TaraSession.AuthenticationResult credential,
            List<String> requestedScopes) {

        MockHttpSession mockHttpSession = new MockHttpSession();
        TaraSession.LoginRequestInfo loginRequestInfo = new TaraSession.LoginRequestInfo();
        loginRequestInfo.setChallenge(MOCK_LOGIN_CHALLENGE);
        TaraSession.Client client = new TaraSession.Client();
        client.setClientId(MOCK_CLIENT_ID);
        client.setScope("mid legalperson");
        loginRequestInfo.setClient(client);
        loginRequestInfo.setRequestedScopes(requestedScopes);
        TaraSession mockTaraSession = new TaraSession();
        mockTaraSession.setAuthenticationResult(credential);
        mockTaraSession.setState(authSessionStatus);
        mockTaraSession.setLoginRequestInfo(loginRequestInfo);
        mockHttpSession.setAttribute(TARA_SESSION, mockTaraSession);
        return mockHttpSession;
    }

    public static ResultHandler forwardErrorsToSpringErrorhandler(MockMvc mvc) {
        return new ErrorForwardResultHandler(mvc);
    }

    @RequiredArgsConstructor
    private static class ErrorForwardResultHandler implements ResultHandler {

        private final MockMvc mock;

        public final void handle(MvcResult result) throws Exception {
            if (result.getResolvedException() != null) {
                byte[] response = mock.perform(get("/error").requestAttr(RequestDispatcher.ERROR_STATUS_CODE, result.getResponse()
                        .getStatus())
                        .requestAttr(RequestDispatcher.ERROR_REQUEST_URI, result.getRequest().getRequestURI())
                        .requestAttr(RequestDispatcher.ERROR_EXCEPTION, result.getResolvedException())
                        .requestAttr(RequestDispatcher.ERROR_MESSAGE, String.valueOf(result.getResolvedException().getMessage())))
                        .andReturn()
                        .getResponse()
                        .getContentAsByteArray();

                log.info("Response: {}", new String(result.getResponse().getContentAsByteArray(), StandardCharsets.UTF_8));

                result.getResponse()
                        .getOutputStream()
                        .write(response);
            }
        }
    }
}
