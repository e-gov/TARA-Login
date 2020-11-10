package ee.ria.taraauthserver.controllers;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.session.AuthState;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultHandler;

import javax.servlet.RequestDispatcher;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@Slf4j
public class LegalpersonControllerTest extends BaseTest {


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
                .andExpect(jsonPath("$.message", is("Session was not found! Either the user session has expired, server has been restarted in the middle of user transaction or corrupt/invalid cookie value was sent from the browser")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person/init")));

        assertErrorIsLogged("User exception: Session was not found! Either the user session has expired, server has been restarted in the middle of user transaction or corrupt/invalid cookie value was sent from the browser");
    }

    @Test
    void getAuthLegalPersonInit_invalidSessionStatus() throws Exception {
        MockHttpSession mockHttpSession = getMockHttpSession(AuthState.INIT_AUTH_PROCESS, getMockCredential());

        ResultActions resultActions = mock.perform(
                get("/auth/legal_person/init").session(mockHttpSession)
        ).andDo(print())
                .andDo(forwardErrorsToSpringErrorhandler(mock));

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Invalid authentication state: INIT_AUTH_PROCESS, expected: NATURAL_PERSON_AUTHENTICATION_COMPLETED")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person/init")));

        assertErrorIsLogged("User exception: Invalid authentication state: INIT_AUTH_PROCESS, expected: NATURAL_PERSON_AUTHENTICATION_COMPLETED");
    }

    @Test
    void getAuthLegalPersonInit_Ok() throws Exception {
        MockHttpSession mockHttpSession = getMockHttpSession(AuthState.NATURAL_PERSON_AUTHENTICATION_COMPLETED, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person/init").session(mockHttpSession))
                .andDo(print()).andDo(forwardErrorsToSpringErrorhandler(mock));

        // TODO validate user data

        resultActions.andExpect(status().is(200));
    }

    @Test
    void getAuthLegalPerson_noSession() throws Exception {
        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(new MockHttpSession()))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Session was not found! Either the user session has expired, server has been restarted in the middle of user transaction or corrupt/invalid cookie value was sent from the browser")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person")));

        assertErrorIsLogged("User exception: Session was not found! Either the user session has expired, server has been restarted in the middle of user transaction or corrupt/invalid cookie value was sent from the browser");
    }

    @Test
    void getAuthLegalPerson_invalidSessionStatus() throws Exception {
        MockHttpSession mockHttpSession = getMockHttpSession(AuthState.INIT_AUTH_PROCESS, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(400))
                .andExpect(jsonPath("$.status", is(400)))
                .andExpect(jsonPath("$.error", is("Bad Request")))
                .andExpect(jsonPath("$.message", is("Invalid authentication state: INIT_AUTH_PROCESS, expected: LEGAL_PERSON_AUTHENTICATION_INIT")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person")));

        assertErrorIsLogged("User exception: Invalid authentication state: INIT_AUTH_PROCESS, expected: LEGAL_PERSON_AUTHENTICATION_INIT");
    }

    @Test
    void getAuthLegalPerson_xroadError_SoapFaultInResponse() throws Exception {

        wireMockServer.stubFor(post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/nok-soapfault.xml")));

        MockHttpSession mockHttpSession = getMockHttpSession(AuthState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(500))
                .andExpect(jsonPath("$.status", is(500)))
                .andExpect(jsonPath("$.error", is("Internal Server Error")))
                .andExpect(jsonPath("$.message", is("Something went wrong internally. Please consult server logs for further details.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person")));

        assertErrorIsLogged("Server encountered an unexpected error: XRoad service returned a soap fault: faultcode = 'SOAP-ENV:Server', faultstring = 'Sisendparameetrid vigased: palun sisestage kas äriregistri kood, isikukood või isiku ees- ja perekonnanimi.'");
    }

    @Test
    void getAuthLegalPerson_xroadError_InvalidResponse() throws Exception {

        wireMockServer.stubFor(post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "text/html; charset=UTF-8")
                        .withBody("Not found")));

        MockHttpSession mockHttpSession = getMockHttpSession(AuthState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(500))
                .andExpect(jsonPath("$.status", is(500)))
                .andExpect(jsonPath("$.error", is("Internal Server Error")))
                .andExpect(jsonPath("$.message", is("Something went wrong internally. Please consult server logs for further details.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person")));

        assertErrorIsLogged("Server encountered an unexpected error: Failed to extract data from response: https://localhost:9877/cgi-bin/consumer_proxy");
    }

    @Test
    void getAuthLegalPerson_xroadError_RequestTimesOut() throws Exception {

        wireMockServer.stubFor(post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withFixedDelay(5000)
                        .withBodyFile("mock_responses/xroad/ok-single-match.xml")));

        MockHttpSession mockHttpSession = getMockHttpSession(AuthState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(502))
                .andExpect(jsonPath("$.status", is(502)))
                .andExpect(jsonPath("$.error", is("Bad Gateway")))
                .andExpect(jsonPath("$.message", is("Something went wrong internally. Please consult server logs for further details.")))
                .andExpect(jsonPath("$.path", is("/auth/legal_person")));

        assertErrorIsLogged("Service not available: Could not connect to business registry. Connection failed: Read timed out");
    }

    @Test
    void getAuthLegalPerson_noValidLegalPersonsFound() throws Exception {

        wireMockServer.stubFor(post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/ok-no-match.xml")));

        MockHttpSession mockHttpSession = getMockHttpSession(AuthState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

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

        wireMockServer.stubFor(post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/ok-single-match.xml")));

        MockHttpSession mockHttpSession = getMockHttpSession(AuthState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(200))
                .andExpect(content().json("{'legalPersons':[{'legalName':'Acme INC OÜ','legalPersonIdentifier':'12341234'}]}"));
    }

    @Test
    void getAuthLegalPerson_validLegalPersons_multipleLegalPersonFound() throws Exception {

        wireMockServer.stubFor(post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/ok-multiple-matches.xml")));

        MockHttpSession mockHttpSession = getMockHttpSession(AuthState.LEGAL_PERSON_AUTHENTICATION_INIT, getMockCredential());

        ResultActions resultActions = mock.perform(get("/auth/legal_person").session(mockHttpSession))
                .andDo(forwardErrorsToSpringErrorhandler(mock)).andDo(print());

        resultActions
                .andExpect(status().is(200))
                .andExpect(content().json("{'legalPersons':[" +
                        "{'legalName':'Acme INC OÜ 1','legalPersonIdentifier':'12341234-1'}," +
                        "{'legalName':'Acme INC UÜ 2','legalPersonIdentifier':'12341234-2'}," +
                        "{'legalName':'Acme INC TÜ 3','legalPersonIdentifier':'12341234-3'}," +
                        "{'legalName':'Acme INC AS 4','legalPersonIdentifier':'12341234-4'}," +
                        "{'legalName':'Acme INC TÜH 5','legalPersonIdentifier':'12341234-5'}," +
                        "{'legalName':'Acme INC SA 6','legalPersonIdentifier':'12341234-6'}," +
                        "{'legalName':'Acme INC MTÜ 7','legalPersonIdentifier':'12341234-7'}" +
                        "]}"));
    }

    @NotNull
    private AuthSession.AuthenticationResult getMockCredential() {
        return getMockCredential("47101010033", "Mari-Liis", "Männik", LocalDate.of(1971, 1, 1));
    }

    private AuthSession.AuthenticationResult getMockCredential(String idCode, String firstName, String lastName, LocalDate dateOfBirth) {
        AuthSession.AuthenticationResult credential = new AuthSession.AuthenticationResult();
        credential.setIdCode(idCode);
        credential.setFirstName(firstName);
        credential.setLastName(lastName);
        credential.setDateOfBirth(dateOfBirth);
        return credential;
    }

    @NotNull
    private MockHttpSession getMockHttpSession(AuthState authSessionStatus, AuthSession.AuthenticationResult credential) {
        MockHttpSession mockHttpSession = new MockHttpSession();
        AuthSession mockAuthSession = new AuthSession();
        mockAuthSession.setAuthenticationResult(credential);
        mockAuthSession.setState(authSessionStatus);
        mockHttpSession.setAttribute("session", mockAuthSession);
        return mockHttpSession;
    }

    public static ResultHandler forwardErrorsToSpringErrorhandler(MockMvc mvc) {
        return new ErrorForwardResultHandler(mvc);
    }

    @RequiredArgsConstructor
    private static class ErrorForwardResultHandler implements ResultHandler{

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
