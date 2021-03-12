package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.utils.X509Utils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.IdCardAuthConfigurationProperties;
import static ee.ria.taraauthserver.config.properties.AuthConfigurationProperties.Ocsp;
import static java.util.List.of;
import static java.util.stream.Collectors.toList;
import static net.logstash.logback.argument.StructuredArguments.fields;
import static net.logstash.logback.argument.StructuredArguments.value;
import static org.springframework.util.CollectionUtils.isEmpty;

@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
public class OCSPConfigurationResolver {

    @Autowired
    private final IdCardAuthConfigurationProperties configurationProperties;

    public List<Ocsp> resolve(X509Certificate userCert) {
        Assert.notNull(userCert, "User certificate is missing!");
        log.debug("Determining the OCSP configuration for certificate serial number: {}", value("x509.serial_number", userCert.getSerialNumber()));
        final List<Ocsp> ocspConfiguration = new ArrayList<>();

        String issuerCN = X509Utils.getIssuerCNFromCertificate(userCert);

        Ocsp primaryConf = getOcspConfiguration(issuerCN, configurationProperties.getOcsp())
                .orElseGet(() -> getDefaultConf(userCert, issuerCN));
        log.debug("Primary ocsp configuration to verify cert issued by '{}': {}", value("x509.issuer.common_name", issuerCN), value("ocsp.conf", primaryConf));
        ocspConfiguration.add(primaryConf);

        if (!isEmpty(configurationProperties.getFallbackOcsp())) {
            List<Ocsp> secondaryConfs = configurationProperties.getFallbackOcsp()
                    .stream()
                    .filter(e -> e.getIssuerCn().stream().anyMatch(b -> b.equals(issuerCN)))
                    .collect(toList());

            secondaryConfs.forEach(secondaryConf ->
                    log.debug("Secondary ocsp configurations to verify cert issued by '{}': {}", value("x509.issuer.common_name", issuerCN),
                            fields(secondaryConf)));
            ocspConfiguration.addAll(secondaryConfs);
        }

        return ocspConfiguration;
    }

    private Ocsp getDefaultConf(X509Certificate userCert, String issuerCN) {
        String url = X509Utils.getOCSPUrl(userCert);
        Assert.notNull(url, "OCSP configuration invalid! This user certificate's issuer, issued by '" + issuerCN +
                "', has no explicitly configured OCSP nor can it be configured automatically since this certificate does not contain " +
                "the OCSP url in the AIA extension! Please check your configuration");
        Ocsp implicitConfiguration = new Ocsp();
        implicitConfiguration.setIssuerCn(of(issuerCN));
        implicitConfiguration.setUrl(url);
        log.debug("Did not find explicit config for issuer '{}' - using default configuration with AIA extension url: {} to verify cert status",
                value("x509.issuer.common_name", issuerCN), value("url.full", url));
        return implicitConfiguration;
    }

    private Optional<Ocsp> getOcspConfiguration(String issuerCN, List<Ocsp> configurations) {
        return configurations.stream().filter(
                e -> e.getIssuerCn().stream().anyMatch(b -> b.equals(issuerCN))
        ).findFirst();
    }
}
