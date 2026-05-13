package ee.ria.taraauthserver.session;

import ee.ria.taraauthserver.BaseTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@Import(TaraSessionHandlerMethodArgumentResolverIntegrationTest.TestController.class)
class TaraSessionHandlerMethodArgumentResolverIntegrationTest extends BaseTest {

    public static final String TEST_PATH = "/tara-session-handler-method-argument-resolver";
    public static final String SESSION_ID_FIELD = "sessionId";

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    void givenSessionPresent_resolvesTaraSessionArgument() {
        MockSessionFilter sessionFilter = MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .build();
        String expectedSessionId = sessionFilter.getSession().getId();

        given()
                .filter(sessionFilter)
                .when()
                .get(TEST_PATH)
                .then()
                .assertThat()
                .statusCode(200)
                .body(SESSION_ID_FIELD, equalTo(expectedSessionId));
    }

    @Controller
    static class TestController {

        @ResponseBody
        @GetMapping(value = TEST_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
        Response endpoint(TaraSession taraSession) {
            return new Response(taraSession.getSessionId());
        }

    }

    record Response(String sessionId) {}

}
