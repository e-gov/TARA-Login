package ee.ria.taraauthserver.session;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Map;

public class MockSessionUtils {

    public static final String MOCK_CHALLENGE = "123456abcdefg";
    public static final String MOCK_CLIENT_NAME = "institution.name";
    public static final String MOCK_CLIENT_NAME_EN = "institution.name.en";
    public static final String MOCK_CLIENT_LEGACY_URL = "http://legacy.url";
    public static final String MOCK_CLIENT_NAME_ET = "institution.name.et";
    public static final String MOCK_CLIENT_NAME_RU = "institution.name.ru";
    public static final String MOCK_CLIENT_SHORTNAME = "institution.short.name";
    public static final String MOCK_CLIENT_SHORTNAME_EN = "institution.shortname.en";
    public static final String MOCK_CLIENT_SHORTNAME_ET = "institution.shortname.et";
    public static final String MOCK_CLIENT_SHORTNAME_RU = "institution.shortname.ru";

    public static AuthSession.LoginRequestInfo getMockLoginRequestInfo() {
        AuthSession.LoginRequestInfo loginRequestInfo = new AuthSession.LoginRequestInfo();
        loginRequestInfo.setChallenge(MOCK_CHALLENGE);

        AuthSession.Client client = new AuthSession.Client();
        AuthSession.MetaData metaData = new AuthSession.MetaData();
        AuthSession.OidcClient oidcClient = new AuthSession.OidcClient();

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

    public static void createMockHttpSession(AuthSession session) {
        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();
        HttpSession httpSession = request.getSession(true);
        httpSession.setAttribute("session", session);
        org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
    }
}
