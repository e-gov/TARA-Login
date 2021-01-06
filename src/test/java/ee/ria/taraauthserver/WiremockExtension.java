package ee.ria.taraauthserver;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.Options;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

@Slf4j
public class WiremockExtension extends WireMockServer implements BeforeAllCallback, AfterEachCallback {

    public WiremockExtension(Options options) {
        super(options);
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        start();
    }

    @Override
    public void afterEach(ExtensionContext context) {
        resetAll();
    }
}
