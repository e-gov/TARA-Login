package ee.ria.taraauthserver.authentication.staticcontent;

import ee.ria.taraauthserver.BaseTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.nullValue;

public class StaticContentTest extends BaseTest {

    @Test
    @Tag(value = "CSRF_PROTCTION")
    void staticContent_SessionIsNotCreated() {
        given()
                .when()
                .get("/favicon.ico")
                .then()
                .assertThat()
                .statusCode(200)
                .header("Set-Cookie", nullValue());
    }
}
