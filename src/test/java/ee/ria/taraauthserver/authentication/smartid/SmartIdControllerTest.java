package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.MockTaraSessionBuilder;
import ee.ria.taraauthserver.session.TaraSession;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static ee.ria.taraauthserver.config.properties.AuthenticationType.MOBILE_ID;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.INIT_AUTH_PROCESS;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static io.restassured.RestAssured.given;
import static java.util.List.of;

class SmartIdControllerTest extends BaseTest {

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    void smartIdTest() {

        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationTypes(of(SMART_ID)).build())
                .formParam("smartIdCode", "10101010005")
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);
    }

    protected Session createNewAuthenticationSession() {
        Session session = sessionRepository.createSession();
        TaraSession testSession = MockTaraSessionBuilder.builder()
                .sessionId(session.getId())
                .authenticationState(INIT_AUTH_PROCESS)
                .authenticationTypes(of(SMART_ID))
                .build();

        session.setAttribute(TARA_SESSION, testSession);
        sessionRepository.save(session);
        return session;
    }

}