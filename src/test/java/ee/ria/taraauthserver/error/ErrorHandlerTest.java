package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.MockSessionFilter;
import ee.ria.taraauthserver.session.TaraAuthenticationState;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import static ch.qos.logback.classic.Level.ERROR;
import static ee.ria.taraauthserver.config.properties.AuthenticationType.SMART_ID;
import static io.restassured.RestAssured.given;
import static java.util.List.of;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Test
    void errorHandler_invalidId_correctRedirectLink() {
        String body = given()
            .header("Accept", "text/html")
            .filter(MockSessionFilter.withTaraSession()
                .sessionRepository(sessionRepository)
                .authenticationTypes(of(SMART_ID))
                .authenticationState(TaraAuthenticationState.INIT_SID).build())
            .formParam("idCode", "12312312311")
            .when()
            .post("/auth/sid/init")
            .then()
            .assertThat()
            .statusCode(400)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + CHARSET_UTF_8)
            .extract().body().asString();

        assertTrue(body.contains("href=\"/auth/init?login_challenge=abcdefg098AAdsCC&amp;lang=et\""));
        assertStatisticsIsLoggedOnce(ERROR, "Authentication result: AUTHENTICATION_FAILED", "StatisticsLogger.SessionStatistics(service=null, clientId=openIdDemo, eidasRequesterId=null, sector=public, registryCode=10001234, legalPerson=false, country=EE, idCode=null, ocspUrl=null, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, errorCode=INTERNAL_ERROR)");
    }
}