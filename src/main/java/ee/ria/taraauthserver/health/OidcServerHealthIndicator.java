package ee.ria.taraauthserver.health;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;
import org.springframework.stereotype.Component;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.net.URI;

import static java.net.URI.create;

@Component
public class OidcServerHealthIndicator extends AbstractHealthIndicator {

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private SSLContext trustContext;

    public OidcServerHealthIndicator() {
        super("Authentication service health check failed");
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) throws Exception {
        URI uri = create(authConfigurationProperties.getHydraService().getHealthUrl());
        HttpsURLConnection con = (HttpsURLConnection) uri.toURL().openConnection();
        con.setSSLSocketFactory(trustContext.getSocketFactory());
        try {
            if (con.getResponseCode() == HttpsURLConnection.HTTP_OK) {
                builder.up();
            } else {
                builder.down();
            }
        } finally {
            con.disconnect();
        }
    }
}
