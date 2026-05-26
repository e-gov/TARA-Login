package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.authentication.smartid.SmartIdClientFacade;
import ee.ria.taraauthserver.authentication.smartid.qrcode.AuthSidQrCodeService;
import ee.ria.taraauthserver.authentication.smartid.qrcode.SmartIdQrCodeController;
import ee.ria.taraauthserver.authentication.smartid.web2app.AuthSidWeb2AppService;
import ee.ria.taraauthserver.authentication.smartid.web2app.SmartIdWeb2AppController;
import ee.ria.taraauthserver.config.properties.SmartIdConfigurationProperties;
import ee.sk.smartid.DeviceLinkAuthenticationResponseValidator;
import ee.sk.smartid.RpChallenge;
import ee.sk.smartid.SmartIdClient;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.util.List;
import java.util.stream.Stream;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@TestPropertySource(
        locations = "classpath:application.yml",
        properties = {"tara.auth-methods.smart-id.enabled=false"})
@SpringBootTest(webEnvironment = RANDOM_PORT)
public class SidConfigurationDisabledTest extends DisabledConfigurationTest {

    private static final List<Class<?>> SID_COMMON_BEANS = List.of(
            RpChallenge.class,
            SmartIdClientFacade.class,
            SmartIdConfiguration.class,
            SmartIdConfigurationProperties.class,
            SmartIdClient.class,
            DeviceLinkAuthenticationResponseValidator.class
    );

    private static final List<Class<?>> SID_QR_CODE_BEANS = List.of(
            AuthSidQrCodeService.class,
            SmartIdQrCodeController.class
    );

    private static final List<Class<?>> SID_WEB2APP_BEANS = List.of(
            AuthSidWeb2AppService.class,
            SmartIdWeb2AppController.class
    );

    @Test
    @Tag(value = "SID_AUTH_ENABLED")
    public void whenSmartIdAuthMethodDisabled_beansNotLoaded() {
        Stream.of(SID_COMMON_BEANS, SID_QR_CODE_BEANS, SID_WEB2APP_BEANS)
                .flatMap(List::stream)
                .forEach(this::assertBeanNotInitiated);

    }
}
