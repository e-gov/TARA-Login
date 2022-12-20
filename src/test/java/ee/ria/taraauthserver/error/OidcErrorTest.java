package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.BaseTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

public class OidcErrorTest extends BaseTest {

    @Test
    void oidc_knownErrorParam() {
        given()
                .queryParam("error", "invalid_request")
                .when()
                .get("/oidc-error")
                .then()
                .assertThat()
                .statusCode(400)
                .header("Content-Type", equalTo("application/json;charset=UTF-8"))
                .body("message", equalTo("Kliendi autentimine ebaõnnestus (võimalikud põhjused: tundmatu klient, kliendi autentimist pole kaasatud, või toetamata autentimismeetod)"));

        given()
                .header("Accept", "text/html")
                .queryParam("error", "invalid_request")
                .when()
                .get("/oidc-error")
                .then()
                .assertThat()
                .statusCode(400)
                .header("Content-Type", equalTo("text/html;charset=UTF-8"))
                .body(containsString("Kliendi autentimine ebaõnnestus (võimalikud põhjused: tundmatu klient, kliendi autentimist pole kaasatud, või toetamata autentimismeetod)"));
    }

    @Test
    void oidc_unKnownErrorParam() {
        given()
                .queryParam("error", "unknown_param")
                .when()
                .get("/oidc-error")
                .then()
                .assertThat()
                .statusCode(500)
                .header("Content-Type", equalTo("application/json;charset=UTF-8"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));

        given()
                .header("Accept", "text/html")
                .queryParam("error", "unknown_param")
                .when()
                .get("/oidc-error")
                .then()
                .assertThat()
                .statusCode(500)
                .header("Content-Type", equalTo("text/html;charset=UTF-8"))
                .body(containsString("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    void oidc_missingErrorParam() {
        given()
                .when()
                .get("/oidc-error")
                .then()
                .assertThat()
                .statusCode(400)
                .header("Content-Type", equalTo("application/json;charset=UTF-8"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));


        given()
                .header("Accept", "text/html")
                .when()
                .get("/oidc-error")
                .then()
                .assertThat()
                .statusCode(400)
                .header("Content-Type", equalTo("text/html;charset=UTF-8"))
                .body(containsString("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

}
