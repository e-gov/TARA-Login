package ee.ria.taraauthserver.utils;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@UtilityClass
public class X509Utils {
    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT = "-----END CERTIFICATE-----";

    public X509Certificate toX509Certificate(String encodedCertificate) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Base64.decodeBase64(encodedCertificate
                            .replaceAll(BEGIN_CERT, "").replaceAll(END_CERT, ""))));
        } catch (CertificateException e) {
            throw new IllegalStateException("Failed to decode certificate", e);
        }
    }

    public String getIssuerCNFromCertificate(X509Certificate certificate) {
        try {
            return getFirstCNFromX500Name(
                    new JcaX509CertificateHolder(certificate).getIssuer()
            );
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Unable to get issuer CN from certificate", e);
        }
    }

    public String getSubjectCNFromCertificate(X509Certificate certificate) {
        try {
            return getFirstCNFromX500Name(
                    new JcaX509CertificateHolder(certificate).getSubject()
            );
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Unable to get subject CN from certificate", e);
        }
    }

    public String getFirstCNFromX500Name(X500Name x500Name) {
        final RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
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
                    .orElseGet(null);
        } catch (CertificateParsingException e) {
            return null;
        }
    }

    public String getOCSPUrl(X509Certificate certificate) {
        ASN1Primitive obj;
        try {
            obj = getExtensionValue(certificate, Extension.authorityInfoAccess.getId());
        } catch (IOException ex) {
            log.error("Failed to get OCSP URL", ex);
            return null;
        }

        if (obj == null) {
            return null;
        }

        AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(obj);

        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {
            if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod)
                    && accessDescription.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier) {

                DERIA5String derStr = DERIA5String.getInstance((ASN1TaggedObject) accessDescription.getAccessLocation().toASN1Primitive(), false);
                return derStr.getString();
            }
        }

        return null;
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

    private ASN1Primitive getExtensionValue(X509Certificate certificate, String oid) throws IOException {
        byte[] bytes = certificate.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return aIn.readObject();
    }
}
