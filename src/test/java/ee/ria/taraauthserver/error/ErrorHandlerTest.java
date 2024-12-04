package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.BaseTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

class ErrorHandlerTest extends BaseTest {

    @Test
    void errorHandler_knownErrorParam() {
        given()
            .queryParam("error_code", "auth_flow_timeout")
            .when()
            .get("/error-handler")
            .then()
            .assertThat()
            .statusCode(401)
            .header("Content-Type", equalTo("application/json;charset=UTF-8"))
            .body("message", equalTo(
                "Autentimiseks ettenähtud aeg lõppes. Peate autentimisprotsessi teenusepakkuja juurest uuesti alustama."));

        given()
            .header("Accept", "text/html")
            .queryParam("error_code", "auth_flow_timeout")
            .when()
            .get("/error-handler")
            .then()
            .assertThat()
            .statusCode(401)
            .header("Content-Type", equalTo("text/html;charset=UTF-8"))
            .body(containsString(
                "Autentimiseks ettenähtud aeg lõppes. Peate autentimisprotsessi teenusepakkuja juurest uuesti alustama."));
    }

    @Test
    void errorHandler_unknownErrorParam() {
        given()
            .queryParam("error_code", "unknown_param")
            .when()
            .get("/error-handler")
            .then()
            .assertThat()
            .statusCode(500)
            .header("Content-Type", equalTo("application/json;charset=UTF-8"))
            .body("message",
                equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));

        given()
            .header("Accept", "text/html")
            .queryParam("error_code", "unknown_param")
            .when()
            .get("/error-handler")
            .then()
            .assertThat()
            .statusCode(500)
            .header("Content-Type", equalTo("text/html;charset=UTF-8"))
            .body(containsString(
                "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    void errorHandler_missingErrorParam() {
        given()
            .when()
            .get("/error-handler")
            .then()
            .assertThat()
            .statusCode(400)
            .header("Content-Type", equalTo("application/json;charset=UTF-8"))
            .body("message",
                equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));

        given()
            .header("Accept", "text/html")
            .when()
            .get("/error-handler")
            .then()
            .assertThat()
            .statusCode(400)
            .header("Content-Type", equalTo("text/html;charset=UTF-8"))
            .body(containsString(
                "Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }
}