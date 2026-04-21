package ee.ria.taraauthserver.utils;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.jetbrains.annotations.NotNull;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@UtilityClass
public class X509Utils {

    public String getIssuerCNFromCertificate(X509Certificate certificate) {
        try {
            return getFirstCNFromX500Name(
                    new JcaX509CertificateHolder(certificate).getIssuer()
            );
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Unable to get issuer CN from certificate", e);
        }
    }

    public String getFirstCNFromX500Name(X500Name x500Name) {
        final RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }

    public static X500Name getSubjectDN(X509Certificate certificate) {
        return X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
    }

    public String getRfc822NameSubjectAltName(X509Certificate certificate) {
        try {
            Collection<List<?>> sanFields = certificate.getSubjectAlternativeNames();

            if (sanFields == null)
                throw new IllegalArgumentException("This certificate does not contain any Subject Alternative Name fields!");

            return certificate.getSubjectAlternativeNames()
                    .stream()
                    .filter(e -> e.get(0).equals(GeneralName.rfc822Name))
                    .findFirst()
                    .map(e -> e.get(1).toString())
                    .orElse(null);
        } catch (CertificateParsingException e) {
            return null;
        }
    }

    @NotNull
    public Map<String, String> getCertificateParams(X509Certificate certificate) {
        String[] test1 = certificate.getSubjectDN().getName().split(", ");
        Map<String, String> params = new HashMap<>();
        for (String s : test1) {
            String[] t = s.split("=");
            params.put(t[0], t[1]);
        }
        return params;
    }
}
