package ee.ria.taraauthserver.config;

import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.rest.SmartIdConnector;
import ee.sk.smartid.rest.SmartIdRestConnector;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.SSLContext;

@Slf4j
@Configuration
@ConditionalOnProperty(value = "tara.auth-methods.smart-id.enabled", matchIfMissing = true)
public class SmartIdConfiguration {

    @Bean
    public SmartIdClient smartIdClient(SSLContext tlsTrustStore) {
        SmartIdClient smartIdClient = new SmartIdClient();
        smartIdClient.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
        smartIdClient.setRelyingPartyName("DEMO");
        smartIdClient.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        smartIdClient.setTrustSslContext(tlsTrustStore);

        return smartIdClient;
    }

}
