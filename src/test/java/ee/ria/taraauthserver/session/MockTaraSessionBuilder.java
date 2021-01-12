package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.lang.String.join;
import static java.util.Objects.requireNonNullElseGet;

@Slf4j
public class MockTaraSessionBuilder {
    public static final String MOCK_LOGIN_CHALLENGE = "abcdefg098AAdsCC";
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

    @Builder
    public static TaraSession buildTaraSession(@NonNull String sessionId, TaraAuthenticationState authenticationState, List<AuthenticationType> authenticationTypes,
                                               List<String> clientAllowedScopes, List<String> requestedScopes, List<TaraSession.LegalPerson> legalPersonList,
                                               TaraSession.AuthenticationResult authenticationResult) {
        TaraSession taraSession = new TaraSession(sessionId);
        TaraSession.LoginRequestInfo lri = new TaraSession.LoginRequestInfo();
        TaraSession.Client client = new TaraSession.Client();
        TaraSession.MetaData metaData = new TaraSession.MetaData();
        TaraSession.OidcClient oidcClient = new TaraSession.OidcClient();
        taraSession.setLegalPersonList(legalPersonList);

        lri.setChallenge(MOCK_LOGIN_CHALLENGE);
        if (requestedScopes != null) {
            lri.setRequestedScopes(requestedScopes);
        }
        oidcClient.setShortName("short_name");
        client.setClientId(MOCK_CLIENT_ID);
        metaData.setOidcClient(oidcClient);
        client.setMetaData(metaData);
        client.setScope(clientAllowedScopes == null ? "" : join(" ", clientAllowedScopes));
        lri.setClient(client);

        taraSession.setAllowedAuthMethods(authenticationTypes);
        taraSession.setState(authenticationState == null ? TaraAuthenticationState.INIT_AUTH_PROCESS : authenticationState);
        taraSession.setLoginRequestInfo(lri);
        taraSession.setAuthenticationResult(requireNonNullElseGet(authenticationResult, () -> new TaraSession.MidAuthenticationResult("testSessionId")));
        return taraSession;
    }

    public static TaraSession.LoginRequestInfo buildMockLoginRequestInfo() {
        TaraSession.LoginRequestInfo loginRequestInfo = new TaraSession.LoginRequestInfo();
        loginRequestInfo.setChallenge(MOCK_LOGIN_CHALLENGE);

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

    public static HttpSession buildMockHttpSession(TaraSession.LoginRequestInfo loginRequestInfo) {
        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        HttpSession httpSession = request.getSession(true);
        TaraSession taraSession = new TaraSession(httpSession.getId());
        taraSession.setLoginRequestInfo(loginRequestInfo);
        httpSession.setAttribute(TARA_SESSION, taraSession);
        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
        return httpSession;
    }

    public static TaraSession.AuthenticationResult buildMockCredential() {
        return buildMockCredential(
                MOCK_NATURAL_PERSON_ID_CODE,
                MOCK_NATURAL_PERSON_FIRSTNAME,
                MOCK_NATURAL_PERSON_LASTNAME,
                MOCK_NATURAL_PERSON_DATE_OF_BIRTH);
    }

    public static TaraSession.AuthenticationResult buildMockCredential(String idCode, String firstName, String lastName, LocalDate dateOfBirth) {
        TaraSession.AuthenticationResult credential = new TaraSession.AuthenticationResult();
        credential.setIdCode(idCode);
        credential.setFirstName(firstName);
        credential.setLastName(lastName);
        credential.setDateOfBirth(dateOfBirth);
        credential.setAcr(LevelOfAssurance.HIGH);
        credential.setAmr(AuthenticationType.MOBILE_ID);
        credential.setSubject("EE" + idCode);
        return credential;
    }
}
