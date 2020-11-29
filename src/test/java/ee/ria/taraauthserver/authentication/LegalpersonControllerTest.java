package ee.ria.taraauthserver.authentication;

import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.ResultActions;

import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static ee.ria.taraauthserver.session.MockSessionUtils.*;
import static ee.ria.taraauthserver.config.properties.Constants.TARA_SESSION;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Slf4j
public class LegalpersonControllerTest extends BaseTest {

    public static final String MOCK_LEGAL_PERSON_IDENTIFIER = "ABC-00000000-_abc";
    public static final String MOCK_LEGAL_PERSON_NAME = "Acme & sons OÜ";

    @Test
    void getAuthLegalPersonInit_noSession() throws Exception {
        ResultActions resultActions = mock.perform(
                get("/auth/legal_person/init").session(new MockHttpSession())
        ).andDo(print())
                .andDo(forwardErrorsToSpringErrorhandler(mock));

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Your session was not found! Either your session expired or the cookie usage is limited in your browser.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person/init")));

        assertErrorIsLogged(String.format("User exception: The attribute '%s' was not found in session", TARA_SESSION));
    }

    @Test
    void getAuthLegalPersonInit_invalidSessionStatus() throws Exception {
        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.INIT_AUTH_PROCESS, getMockCredential());

        ResultActions resultActions = mock.perform(
                get("/auth/legal_person/init").session(mockHttpSession)
        ).andDo(print())
                .andDo(forwardErrorsToSpringErrorhandler(mock));

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Invalid request - invalid session.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person/init")));


        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_AUTH_PROCESS', expected: 'NATURAL_PERSON_AUTHENTICATION_COMPLETED'");
    }

    @Test
    void getAuthLegalPersonInit_invalidRequest_noLegalpersonScopeInOidcRequest() throws Exception {
        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, getMockCredential());
        ((TaraSession) mockHttpSession.getAttribute(TARA_SESSION)).getLoginRequestInfo().setRequestedScopes(new ArrayList<>());

        ResultActions resultActions = mock.perform(get("/auth/legal_person/init").session(mockHttpSession))
                .andDo(print()).andDo(forwardErrorsToSpringErrorhandler(mock));

        resultActions
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Invalid request.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person/init")));

        assertErrorIsLogged("User exception: scope 'legalperson' was not requested in the initial OIDC authentication request");
    }

    @Test
    void getAuthLegalPersonInit_invalidRequest_scopeNotAllowed() throws Exception {
        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, getMockCredential());
        ((TaraSession) mockHttpSession.getAttribute(TARA_SESSION)).getLoginRequestInfo().getClient().setScope("");

        ResultActions resultActions = mock.perform(get("/auth/legal_person/init").session(mockHttpSession))
                .andDo(print()).andDo(forwardErrorsToSpringErrorhandler(mock));

        resultActions
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Invalid request.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person/init")));

        assertErrorIsLogged(String.format("User exception: client '%s' is not authorized to use scope 'legalperson'", MOCK_CLIENT_ID));
    }

    @Test
    void getAuthLegalPersonInit_Ok() throws Exception {
        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, getMockCredential(), List.of("legalperson"));

        ResultActions resultActions = mock.perform(get("/auth/legal_person/init").session(mockHttpSession))
                .andDo(print()).andDo(forwardErrorsToSpringErrorhandler(mock));

        resultActions
                .andExpect(status().is(200))
                .andExpect(model().attribute("idCode", is(MOCK_NATURAL_PERSON_ID_CODE)))
                .andExpect(model().attribute("firstName", is(MOCK_NATURAL_PERSON_FIRSTNAME)))
                .andExpect(model().attribute("lastName", is(MOCK_NATURAL_PERSON_LASTNAME)))
                .andExpect(model().attribute("dateOfBirth", is(MOCK_NATURAL_PERSON_DATE_OF_BIRTH)))
                .andExpect(content().string(containsString(MOCK_NATURAL_PERSON_ID_CODE)))
                .andExpect(content().string(containsString(MOCK_NATURAL_PERSON_FIRSTNAME)))
                .andExpect(content().string(containsString(MOCK_NATURAL_PERSON_LASTNAME)))
                .andExpect(content().string(containsString(
                        MOCK_NATURAL_PERSON_DATE_OF_BIRTH.format(DateTimeFormatter.ofPattern("dd.MM.yyyy"))))

                ).andExpect(content().string(containsString("<a href=\"/auth/init?login_challenge=" + MOCK_LOGIN_CHALLENGE + "\">Tagasi tuvastamismeetodite valiku juurde</a>")));
    }

    @Test
    void getAuthLegalPerson_noSession() throws Exception {
        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(new MockHttpSession()))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Your session was not found! Either your session expired or the cookie usage is limited in your browser.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person")));

        assertErrorIsLogged(String.format("User exception: The attribute '%s' was not found in session", TARA_SESSION));
    }

    @Test
    void getAuthLegalPerson_invalidSessionStatus() throws Exception {
        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.INIT_AUTH_PROCESS, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Invalid request - invalid session.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person")));

        assertErrorIsLogged("User exception: Invalid authentication state: 'INIT_AUTH_PROCESS', expected: 'LEGAL_PERSON_AUTHENTICATION_INIT'");
    }

    @Test
    void getAuthLegalPerson_xroadError_SoapFaultInResponse() throws Exception {

        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/nok-soapfault.xml")));

        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(500))
                .andExpect(jsonPath("$.status", is(500)))
                .andExpect(jsonPath("$.error", is("Internal Server Error")))
                .andExpect(jsonPath("$.message", is("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person")));

        assertErrorIsLogged("Server encountered an unexpected error: XRoad service returned a soap fault: faultcode = 'SOAP-ENV:Server', faultstring = 'Sisendparameetrid vigased: palun sisestage kas äriregistri kood, isikukood või isiku ees- ja perekonnanimi.'");
    }

    @Test
    void getAuthLegalPerson_xroadError_InvalidResponse() throws Exception {

        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "text/html; charset=UTF-8")
                        .withBody("Not found")));

        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(500))
                .andExpect(jsonPath("$.status", is(500)))
                .andExpect(jsonPath("$.error", is("Internal Server Error")))
                .andExpect(jsonPath("$.message", is("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person")));

        assertErrorIsLogged("Server encountered an unexpected error: Failed to extract data from response: https://localhost:9877/cgi-bin/consumer_proxy");
    }

    @Test
    void getAuthLegalPerson_xroadError_RequestTimesOut() throws Exception {

        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withFixedDelay(5000)
                        .withBodyFile("mock_responses/xroad/ok-single-match.xml")));

        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(502))
                .andExpect(jsonPath("$.status", is(502)))
                .andExpect(jsonPath("$.error", is("Bad Gateway")))
                .andExpect(jsonPath("$.message", is("Could not connect to business registry! Please try again later.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person")));

        assertErrorIsLogged("Service not available: Could not connect to business registry. Connection failed: Read timed out");
    }

    @Test
    void getAuthLegalPerson_noValidLegalPersonsFound() throws Exception {

        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/ok-no-match.xml")));

        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(404))
                .andExpect(jsonPath("$.status", is(404)))
                .andExpect(jsonPath("$.error", is("Not Found")))
                .andExpect(jsonPath("$.message", is("Current user has no valid legal person records in business registry")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person")));

        assertErrorIsLogged("Results not found: Current user has no valid legal person records in business registry");
    }

    @Test
    void getAuthLegalPerson_validLegalPersons_singleLegalPersonFound() throws Exception {

        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/ok-single-match.xml")));

        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(200))
                .andExpect(content().json("{'legalPersons':[{'legalName':'Acme INC OÜ','legalPersonIdentifier':'12341234'}]}"));
    }

    @Test
    void getAuthLegalPerson_validLegalPersons_multipleLegalPersonFound() throws Exception {

        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/ok-multiple-matches.xml")));

        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(200))
                .andExpect(content().json("{'legalPersons':[" +
                        "{'legalName':'Acme INC OÜ 1','legalPersonIdentifier':'11111111'}," +
                        "{'legalName':'Acme INC UÜ 2','legalPersonIdentifier':'22222222'}," +
                        "{'legalName':'Acme INC TÜ 3','legalPersonIdentifier':'33333333'}," +
                        "{'legalName':'Acme INC AS 4','legalPersonIdentifier':'44444444'}," +
                        "{'legalName':'Acme INC TÜH 5','legalPersonIdentifier':'55555555'}," +
                        "{'legalName':'Acme INC SA 6','legalPersonIdentifier':'66666666'}," +
                        "{'legalName':'Acme INC MTÜ 7','legalPersonIdentifier':'77777777'}" +
                        "]}"));
    }

    @Test
    void postAuthLegalPersonConfirm_NoSession() throws Exception {

        MockHttpSession mockHttpSession = new MockHttpSession();

        ResultActions resultActions = mock.perform(post("/auth/legal_person/confirm")
                .param("legal_person_identifier", "1234")
                .session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Your session was not found! Either your session expired or the cookie usage is limited in your browser.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person/confirm")));

        assertErrorIsLogged(String.format("User exception: The attribute '%s' was not found in session", TARA_SESSION));
    }

    @Test
    void postAuthLegalPersonConfirm_InvalidSession() throws Exception {

        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

        ResultActions resultActions = mock.perform(post("/auth/legal_person/confirm").param("legal_person_identifier", "1234").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Invalid request - invalid session.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person/confirm")));

        assertErrorIsLogged("User exception: Invalid authentication state: 'LEGAL_PERSON_AUTHENTICATION_INIT', expected: 'GET_LEGAL_PERSON_LIST'");
    }

    @Test
    void postAuthLegalPersonConfirm_MissingRequiredParam() throws Exception {

        MockHttpSession mockHttpSession = new MockHttpSession();

        ResultActions resultActions = mock.perform(post("/auth/legal_person/confirm")
                .session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Required String parameter 'legal_person_identifier' is not present")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person/confirm")));

        assertErrorIsLogged("User exception: Required String parameter 'legal_person_identifier' is not present");
    }

    @Test
    void postAuthLegalPersonConfirm_InvalidParameter_InvalidInput() throws Exception {

        MockHttpSession mockHttpSession = new MockHttpSession();

        ResultActions resultActions = mock.perform(post("/auth/legal_person/confirm")
                .param("legal_person_identifier", "<>?=`*,.")
                .session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("confirmLegalPerson.legalPersonIdentifier: invalid legal person identifier")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person/confirm")));

        assertErrorIsLogged("User exception: confirmLegalPerson.legalPersonIdentifier: invalid legal person identifier");
    }

    @Test
    void postAuthLegalPersonConfirm_InvalidParameter_notListed() throws Exception {

        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.GET_LEGAL_PERSON_LIST, getMockCredential());
        ((TaraSession) mockHttpSession.getAttribute(TARA_SESSION)).setLegalPersonList(List.of(new TaraSession.LegalPerson("Acme OÜ", "123456abcd")));

        ResultActions resultActions = mock.perform(post("/auth/legal_person/confirm")
                .param("legal_person_identifier", "9876543210")
                .session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Invalid request.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person/confirm")));

        assertErrorIsLogged("User exception: Attempted to select invalid legal person with id: '9876543210'");
    }

    @Test
    void postAuthLegalPersonConfirm_validLegalPersonIdentifier() throws Exception {

        MockHttpSession mockHttpSession = getMockHttpSession(TaraAuthenticationState.GET_LEGAL_PERSON_LIST, getMockCredential());
        ((TaraSession) mockHttpSession.getAttribute(TARA_SESSION)).setLegalPersonList(List.of(new TaraSession.LegalPerson(MOCK_LEGAL_PERSON_NAME, MOCK_LEGAL_PERSON_IDENTIFIER)));

        ResultActions resultActions = mock.perform(post("/auth/legal_person/confirm")
                .param("legal_person_identifier", MOCK_LEGAL_PERSON_IDENTIFIER)
                .session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(302))
                .andExpect(header().string("Location", "/auth/accept"));

        assertInfoIsLogged("Legal person selected: " + MOCK_LEGAL_PERSON_IDENTIFIER);
    }
}
