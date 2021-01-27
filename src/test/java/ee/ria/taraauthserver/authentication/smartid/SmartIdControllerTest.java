package ee.ria.taraauthserver.authentication.smartid;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.MockSessionFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import static io.restassured.RestAssured.given;

class SmartIdControllerTest extends BaseTest {

    @Autowired
    private SessionRepository<Session> sessionRepository;

    @Test
    void smartIdTest() {
        given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository).build())
                .formParam("smartIdCode", "10101010005")
                .when()
                .post("/auth/sid/init")
                .then()
                .assertThat()
                .statusCode(200);
    }

}