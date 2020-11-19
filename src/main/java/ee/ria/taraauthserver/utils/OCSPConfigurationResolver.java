package ee.ria.taraauthserver.utils;

import ee.ria.taraauthserver.config.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.AuthConfigurationProperties.Ocsp;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class OCSPConfigurationResolver {

    @Autowired
    private final AuthConfigurationProperties.IdCardAuthConfigurationProperties configurationProperties;

    public List<Ocsp> resolve(X509Certificate userCert) {
        log.debug("Determining the OCSP configuration");
        Assert.notNull(userCert, "User certificate is missing!");
        final List<Ocsp> ocspConfiguration = new ArrayList<>();

        String issuerCN = X509Utils.getIssuerCNFromCertificate(userCert);

        Ocsp primaryConf = getOcspConfiguration(issuerCN, configurationProperties.getOcsp())
                .orElseGet(() -> getDefaultConf(userCert, issuerCN));
        log.debug("Primary ocsp configuration to verify cert issued by '{}': {}", issuerCN, primaryConf);
        ocspConfiguration.add(primaryConf);

        if (CollectionUtils.isNotEmpty(configurationProperties.getFallbackOcsp())) {
            log.info("SHOULD ADD FALLBACK OCSP");
            List<AuthConfigurationProperties.Ocsp> secondaryConfs = configurationProperties.getFallbackOcsp().stream().filter(
                    e -> e.getIssuerCn().stream().anyMatch(b -> b.equals(issuerCN))
            ).collect(Collectors.toList());
            log.debug("Secondary ocsp configurations to verify cert issued by '{}': {}", issuerCN, secondaryConfs);
            ocspConfiguration.addAll(secondaryConfs);
        }

        log.debug("OCSP configurations: {}", ocspConfiguration);
        return ocspConfiguration;
    }

    private Ocsp getDefaultConf(X509Certificate userCert, String issuerCN) {
        String url = X509Utils.getOCSPUrl(userCert);
        Assert.notNull(url, "OCSP configuration invalid! This user certificate's issuer, issued by '" + issuerCN +
                "', has no explicitly configured OCSP nor can it be configured automatically since this certificate does not contain " +
                "the OCSP url in the AIA extension! Please check your configuration");
        Ocsp implicitConfiguration = new Ocsp();
        implicitConfiguration.setIssuerCn(Arrays.asList(issuerCN));
        implicitConfiguration.setUrl(url);
        log.debug("Did not find explicit config for issuer '{}' - using default configuration with AIA extension url: {} to verify cert status", issuerCN, url);
        return implicitConfiguration;
    }

    private Optional<Ocsp> getOcspConfiguration(String issuerCN, List<Ocsp> configurations) {
        return configurations.stream().filter(
                e -> e.getIssuerCn().stream().anyMatch(b -> b.equals(issuerCN))
        ).findFirst();
    }
}
