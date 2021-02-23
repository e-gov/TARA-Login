package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.BaseTest;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;

import static ee.ria.taraauthserver.session.MockSessionFilter.*;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

public class OidcErrorTest extends BaseTest {

    @Test
    void oidc_knownErrorParam() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .queryParam("error", "invalid_request")
                .when()
                .get("/oidc-error")
                .then()
                .assertThat()
                .statusCode(400)
                .header("Content-Type", equalTo("application/json;charset=UTF-8"))
                .body("message", equalTo("Kliendi autentimine ebaõnnestus (võimalikud põhjused: tundmatu klient, kliendi autentimist pole kaasatud, või toetamata autentimismeetod)"));

        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
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
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .queryParam("error", "unknown_param")
                .when()
                .post("/oidc-error")
                .then()
                .assertThat()
                .statusCode(500)
                .header("Content-Type", equalTo("application/json;charset=UTF-8"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));

        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .header("Accept", "text/html")
                .queryParam("error", "unknown_param")
                .when()
                .post("/oidc-error")
                .then()
                .assertThat()
                .statusCode(500)
                .header("Content-Type", equalTo("text/html;charset=UTF-8"))
                .body(containsString("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    void oidc_missingErrorParam() {
        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .when()
                .post("/oidc-error")
                .then()
                .assertThat()
                .statusCode(500)
                .header("Content-Type", equalTo("application/json;charset=UTF-8"))
                .body("message", equalTo("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));

        given()
                .filter(withoutTaraSession().sessionRepository(sessionRepository).build())
                .header("Accept", "text/html")
                .when()
                .post("/oidc-error")
                .then()
                .assertThat()
                .statusCode(500)
                .header("Content-Type", equalTo("text/html;charset=UTF-8"))
                .body(containsString("Autentimine ebaõnnestus teenuse tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

}
