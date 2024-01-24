package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.config.properties.AuthenticationType;
import ee.ria.taraauthserver.config.properties.LevelOfAssurance;
import ee.ria.taraauthserver.config.properties.SPType;
import eu.webeid.security.challenge.ChallengeNonce;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.Builder;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.net.URI;
import java.net.URL;
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
    public static final String MOCK_INSTITUTION_REGISTRY_CODE = "10001234";
    public static final SPType MOCK_INSTITUTION_SECTOR = SPType.PUBLIC;
    public static final String MOCK_REQUESTER_ID = "a:b:c";
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
    public static final String MOCK_LOGIN_REQUEST_URL = "https://oidc-service:8443/oauth2/auth?scope=openid&response_type=code&client_id=dev-local-specificproxyservice&redirect_uri=https://oidc-client-mock:8451/oauth/response&state=c46b216b-e73d-4cd2-907b-6c809b44cec1&nonce=f722ae1d-1a81-4482-8f9b-06d2356ec3d6&ui_locales=et";
    public static final LocalDate MOCK_NATURAL_PERSON_DATE_OF_BIRTH = LocalDate.of(1971, 1, 1);

    @SneakyThrows
    @Builder
    public static TaraSession buildTaraSession(@NonNull String sessionId,
                                               TaraAuthenticationState authenticationState,
                                               List<AuthenticationType> authenticationTypes,
                                               List<String> clientAllowedScopes,
                                               List<String> requestedScopes,
                                               List<TaraSession.LegalPerson> legalPersonList,
                                               SPType spType,
                                               Map<String, String> shortNameTranslations,
                                               ChallengeNonce webEidChallengeNonce,
                                               TaraSession.AuthenticationResult authenticationResult) {
        TaraSession taraSession = new TaraSession(sessionId);
        TaraSession.LoginRequestInfo lri = new TaraSession.LoginRequestInfo();
        TaraSession.Client client = new TaraSession.Client();
        TaraSession.MetaData metaData = new TaraSession.MetaData();
        TaraSession.OidcClient oidcClient = new TaraSession.OidcClient();
        TaraSession.Institution institution = new TaraSession.Institution();
        taraSession.setLegalPersonList(legalPersonList);
        taraSession.setWebEidChallengeNonce(webEidChallengeNonce);

        lri.setChallenge(MOCK_LOGIN_CHALLENGE);
        if (requestedScopes != null) {
            lri.setRequestedScopes(requestedScopes);
        }
        client.setClientId(MOCK_CLIENT_ID);
        institution.setRegistryCode(MOCK_INSTITUTION_REGISTRY_CODE);
        if (spType != null) {
            institution.setSector(spType);
        } else {
            institution.setSector(MOCK_INSTITUTION_SECTOR);
        }
        oidcClient.setInstitution(institution);
        oidcClient.setEidasRequesterId(new URI(MOCK_REQUESTER_ID));
        if (shortNameTranslations != null) {
            oidcClient.setShortNameTranslations(shortNameTranslations);
        }
        metaData.setOidcClient(oidcClient);
        client.setMetaData(metaData);
        client.setScope(clientAllowedScopes == null ? "" : join(" ", clientAllowedScopes));
        lri.setClient(client);
        lri.setUrl(new URL(MOCK_LOGIN_REQUEST_URL));

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

        oidcClient.setNameTranslations(Map.of(
                "en", MOCK_CLIENT_NAME_EN,
                "et", MOCK_CLIENT_NAME_ET,
                "ru", MOCK_CLIENT_NAME_RU
        ));
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
