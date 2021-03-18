package ee.ria.taraauthserver.authentication.legalperson;

import com.github.tomakehurst.wiremock.client.WireMock;
import ee.ria.taraauthserver.BaseTest;
import ee.ria.taraauthserver.session.MockSessionFilter;
import io.restassured.RestAssured;
import io.restassured.path.json.JsonPath;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.taraauthserver.session.MockTaraSessionBuilder.buildMockCredential;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_INIT;
import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.legal-person-authentication.esindus-v2-allowed-types=OÜ"})
public class LegalpersonAllowedTypesFilterConfigurableTest extends BaseTest {

    @BeforeEach
    void beforeEach() {
        RestAssured.responseSpecification = null;
    }

    @Test
    @Tag(value = "LEGAL_PERSON_BUSINESSREGISTER_RESPONSE")
    @Tag(value = "LEGAL_PERSON_AUTH_START_ENDPOINT")
    void getAuthLegalPerson_validLegalPersons_singleLegalPersonFound() {
        wireMockServer.stubFor(WireMock.post(urlEqualTo("/cgi-bin/consumer_proxy"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml; charset=UTF-8")
                        .withBodyFile("mock_responses/xroad/ok-multiple-matches.xml")));

        JsonPath response = given()
                .filter(MockSessionFilter.withTaraSession()
                        .sessionRepository(sessionRepository)
                        .authenticationState(LEGAL_PERSON_AUTHENTICATION_INIT)
                        .authenticationResult(buildMockCredential())
                        .build())
                .when()
                .get("/auth/legalperson")
                .then()
                .assertThat()
                .statusCode(200)
                .headers(EXPECTED_RESPONSE_HEADERS)
                .extract().jsonPath();

        assertThat(response.getString("legalPersons[0].legalName")).isEqualTo("Acme INC OÜ 1");
        assertThat(response.getString("legalPersons[0].legalPersonIdentifier")).isEqualTo("11111111");
    }
}
