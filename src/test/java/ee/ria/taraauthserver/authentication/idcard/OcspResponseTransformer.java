package ee.ria.taraauthserver.authentication.idcard;

import com.github.tomakehurst.wiremock.common.FileSource;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ResponseTransformer;
import com.github.tomakehurst.wiremock.http.Request;
import com.github.tomakehurst.wiremock.http.Response;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * WireMock response transformer that turns the mock OCSP server's stubbed 200 responses into signed
 * OCSP responses. Used by {@code BaseTest}'s {@code ocspWireMockServer} so integration tests
 * (e.g. {@code IdCardLoginControllerTest}) can drive the web-eid library's OCSP validation flow.
 *
 * <p>Extracted from the former {@code OCSPValidatorTest} (removed after OCSP validation moved into
 * the web-eid library); only this shared helper is still required.
 */
@Slf4j
@Setter
@RequiredArgsConstructor
public class OcspResponseTransformer extends ResponseTransformer {
    private final boolean applyGlobally;
    private int responseStatus;
    private CertificateStatus certificateStatus;
    private Function<DEROctetString, DEROctetString> nonceResolver;
    private Supplier<Date> thisUpdateProvider;
    private PrivateKey signerKey;
    private X509Certificate responderCertificate;

    @Override
    public Response transform(Request request, Response response, FileSource fileSource, Parameters parameters) {
        log.info("TRANSFORMING RESPONSE!");
        if (parameters != null && parameters.containsKey("ignore")) return response;
        if (response.getStatus() != 200) return response;
        byte[] responseBytes;

        try {
            OCSPReq ocspReq = new OCSPReq(request.getBody());

            if (ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce) == null) {
                throw new IllegalStateException("Nonce extension is missing from OCSP request");
            }
            if (ocspReq.getRequestList().length != 1) {
                throw new IllegalStateException("OCSP request must contain exactly one request");
            }
            DEROctetString nonce = (DEROctetString) ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue();
            validateNonceDerOctetString(nonce);

            BasicOCSPResp basicOCSPResp = mockOcspResponse(
                    ocspReq.getRequestList()[0].getCertID(),
                    this.nonceResolver.apply(nonce),
                    responderCertificate.getEncoded(),
                    parameters.getString("responderId"),
                    parameters.getString("signatureAlgorithm")
            );
            OCSPResp ocspResp = new OCSPRespBuilder().build(this.responseStatus, basicOCSPResp);
            responseBytes = ocspResp.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return Response.Builder.like(response)
                .body(responseBytes)
                .build();
    }

    @Override
    public String getName() {
        return "ocsp";
    }

    @Override
    public boolean applyGlobally() {
        return applyGlobally;
    }

    private BasicOCSPResp mockOcspResponse(CertificateID certificateID, DEROctetString nonce, byte[] responderCert, String responseId, String signatureAlgorithm) throws OCSPException, OperatorCreationException, IOException {
        RespID respID = new RespID(new X500Name(responseId));
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(respID);
        builder.addResponse(certificateID, this.certificateStatus,
                this.thisUpdateProvider.get(),
                null,
                null
        );

        if (nonce != null) {
            // web-eid's OcspCertificateRevocationChecker.checkNonce compares the whole Extension (incl. the
            // critical flag) via Extension.equals; OcspRequestBuilder builds the request nonce as non-critical,
            // so the echoed response nonce must also be non-critical, otherwise validation fails with
            // "OCSP request and response nonces differ".
            Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce);
            builder.setResponseExtensions(new Extensions(new Extension[]{extension}));
        }

        return builder.build(
                new JcaContentSignerBuilder(signatureAlgorithm).build(this.signerKey),
                new X509CertificateHolder[]{new X509CertificateHolder(responderCert)},
                Date.from(Instant.now())
        );
    }

    private static void validateNonceDerOctetString(DEROctetString nonceDerOctetString) {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(nonceDerOctetString.getOctetStream())) {
            ASN1Primitive asn1Primitive = asn1InputStream.readObject();
            if (!(asn1Primitive instanceof DEROctetString))
                throw new IllegalStateException("Nonce must be doubly wrapped in octet string");
        } catch (IOException e) {
            throw new IllegalStateException("Failed to extract an octet string from nonce octet string", e);
        }
    }
}
