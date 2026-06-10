package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.utils.TestUtils;
import eu.webeid.ocsp.exceptions.OCSPClientException;
import eu.webeid.ocsp.exceptions.UserCertificateRevokedException;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateOCSPCheckFailedException;
import eu.webeid.security.validator.ValidationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static ee.ria.taraauthserver.error.ErrorCode.IDC_OCSP_NOT_AVAILABLE;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_REVOKED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_GOOD;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_REVOKED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OcspExceptionTranslatorTest {

    private static final URI OCSP_URI = URI.create("http://ocsp.test");

    @Test
    void translateOcspRequestError_whenUserCertificateRevokedException_returnsIdcRevoked() {
        UserCertificateRevokedException exception = new UserCertificateRevokedException();

        assertThat(OcspExceptionTranslator.translateOcspRequestError(exception)).isEqualTo(IDC_REVOKED);
    }

    @Test
    void translateOcspRequestError_whenGenericException_returnsValidationErrorResultOther() {
        RuntimeException exception = new RuntimeException("OCSP request timed out");

        assertThat(OcspExceptionTranslator.translateOcspRequestError(exception)).isEqualTo(IDC_VALIDATION_ERROR_RESULT_OTHER);
    }

    @Test
    void translateOcspRequestError_whenOcspClientExceptionWithoutBody_returnsOcspNotAvailable() {
        OCSPClientException exception = new OCSPClientException("OCSP request failed", null, 503);

        assertThat(OcspExceptionTranslator.translateOcspRequestError(exception)).isEqualTo(IDC_OCSP_NOT_AVAILABLE);
    }

    @Test
    void translateOcspRequestError_whenOcspClientExceptionWithEmptyBody_returnsOcspNotAvailable() {
        OCSPClientException exception = new OCSPClientException("OCSP request failed", new byte[0], 503);

        assertThat(OcspExceptionTranslator.translateOcspRequestError(exception)).isEqualTo(IDC_OCSP_NOT_AVAILABLE);
    }

    @Test
    void translateOcspRequestError_whenOcspClientExceptionWithUnparseableBody_returnsValidationErrorResultOther() {
        OCSPClientException exception = new OCSPClientException("OCSP request failed", "not-an-ocsp-response".getBytes(), 200);

        assertThat(OcspExceptionTranslator.translateOcspRequestError(exception)).isEqualTo(IDC_VALIDATION_ERROR_RESULT_OTHER);
    }

    @Test
    void translateOcspRequestError_whenOcspClientExceptionWithRevokedResponseBody_returnsValidationErrorResultRevoked() throws Exception {
        byte[] responseBody = givenOcspResponseBytes(new RevokedStatus(new Date(), 0));
        OCSPClientException exception = new OCSPClientException("OCSP request failed", responseBody, 200);

        assertThat(OcspExceptionTranslator.translateOcspRequestError(exception)).isEqualTo(IDC_VALIDATION_ERROR_RESULT_REVOKED);
    }

    @Test
    void translateOcspCheckFailure_whenRevocationInfoListEmpty_throwsIllegalArgumentException() {
        ResilientUserCertificateOCSPCheckFailedException exception = givenOcspCheckFailedException(List.of());

        assertThatThrownBy(() -> OcspExceptionTranslator.translateOcspCheckFailure(exception))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Revocation info list cannot be empty");
    }

    @Test
    void translateOcspCheckFailure_whenLastRevocationInfoNull_throwsIllegalArgumentException() {
        ResilientUserCertificateOCSPCheckFailedException exception
                = givenOcspCheckFailedException(Arrays.asList((RevocationInfo) null));

        assertThatThrownBy(() -> OcspExceptionTranslator.translateOcspCheckFailure(exception))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Revocation info cannot be null");
    }

    @Test
    void translateOcspCheckFailure_whenOcspResponseMissing_returnsOcspNotAvailable() {
        ResilientUserCertificateOCSPCheckFailedException exception
                = givenOcspCheckFailedException(List.of(new RevocationInfo(OCSP_URI, Map.of())));

        assertThat(OcspExceptionTranslator.translateOcspCheckFailure(exception)).isEqualTo(IDC_OCSP_NOT_AVAILABLE);
    }

    @Test
    void translateOcspCheckFailure_whenOcspResponseHasWrongType_returnsOcspNotAvailable() {
        ResilientUserCertificateOCSPCheckFailedException exception = givenOcspCheckFailedException(List.of(
                new RevocationInfo(OCSP_URI, Map.of(RevocationInfo.KEY_OCSP_RESPONSE, "not-an-ocsp-response"))));

        assertThat(OcspExceptionTranslator.translateOcspCheckFailure(exception)).isEqualTo(IDC_OCSP_NOT_AVAILABLE);
    }

    @Test
    void translateOcspCheckFailure_whenCertificateStatusRevoked_returnsValidationErrorResultRevoked() throws Exception {
        OCSPResp ocspResp = givenOcspRespWithCertificateStatus(new RevokedStatus(new Date(), 0));
        ResilientUserCertificateOCSPCheckFailedException exception = givenOcspCheckFailedException(List.of(
                new RevocationInfo(OCSP_URI, Map.of(RevocationInfo.KEY_OCSP_RESPONSE, ocspResp))));

        assertThat(OcspExceptionTranslator.translateOcspCheckFailure(exception)).isEqualTo(IDC_VALIDATION_ERROR_RESULT_REVOKED);
    }

    @Test
    void translateOcspCheckFailure_whenCertificateStatusGood_returnsValidationErrorResultGood() throws Exception {
        OCSPResp ocspResp = givenOcspRespWithCertificateStatus(null);
        ResilientUserCertificateOCSPCheckFailedException exception = givenOcspCheckFailedException(List.of(
                new RevocationInfo(OCSP_URI, Map.of(RevocationInfo.KEY_OCSP_RESPONSE, ocspResp))));

        assertThat(OcspExceptionTranslator.translateOcspCheckFailure(exception)).isEqualTo(IDC_VALIDATION_ERROR_RESULT_GOOD);
    }

    @Test
    void translateOcspCheckFailure_whenCertificateStatusUnknown_returnsValidationErrorResultOther() throws Exception {
        OCSPResp ocspResp = givenOcspRespWithCertificateStatus(new UnknownStatus());
        ResilientUserCertificateOCSPCheckFailedException exception = givenOcspCheckFailedException(List.of(
                new RevocationInfo(OCSP_URI, Map.of(RevocationInfo.KEY_OCSP_RESPONSE, ocspResp))));

        assertThat(OcspExceptionTranslator.translateOcspCheckFailure(exception)).isEqualTo(IDC_VALIDATION_ERROR_RESULT_OTHER);
    }

    @Test
    void translateOcspCheckFailure_whenOcspResponseNotDecodable_returnsValidationErrorResultOther() throws Exception {
        OCSPResp ocspResp = mock(OCSPResp.class);
        when(ocspResp.getResponseObject()).thenThrow(new OCSPException("malformed response"));
        ResilientUserCertificateOCSPCheckFailedException exception = givenOcspCheckFailedException(List.of(
                new RevocationInfo(OCSP_URI, Map.of(RevocationInfo.KEY_OCSP_RESPONSE, ocspResp))));

        assertThat(OcspExceptionTranslator.translateOcspCheckFailure(exception)).isEqualTo(IDC_VALIDATION_ERROR_RESULT_OTHER);
    }

    @Test
    void translateOcspCheckFailure_whenMultipleRevocationInfos_returnsResultFromLastRevocationInfo() throws Exception {
        RevocationInfo firstWithoutResponse = new RevocationInfo(URI.create("http://ocsp1.test"), Map.of());
        OCSPResp ocspResp = givenOcspRespWithCertificateStatus(new RevokedStatus(new Date(), 0));
        RevocationInfo lastWithRevokedResponse
                = new RevocationInfo(URI.create("http://ocsp2.test"), Map.of(RevocationInfo.KEY_OCSP_RESPONSE, ocspResp));
        ResilientUserCertificateOCSPCheckFailedException exception
                = givenOcspCheckFailedException(List.of(firstWithoutResponse, lastWithRevokedResponse));

        assertThat(OcspExceptionTranslator.translateOcspCheckFailure(exception)).isEqualTo(IDC_VALIDATION_ERROR_RESULT_REVOKED);
    }

    private static byte[] givenOcspResponseBytes(CertificateStatus certificateStatus) throws Exception {
        X509Certificate certificate = TestUtils.loadCertificateFromResource("id-card/38001085718(TEST_of_ESTEID2018).pem");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        CertificateID certificateId = new CertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                new X509CertificateHolder(certificate.getEncoded()),
                certificate.getSerialNumber());
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(new RespID(new X500Name("CN=Test OCSP Responder")));
        builder.addResponse(certificateId, certificateStatus);
        BasicOCSPResp basicOcspResp = builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate()), null, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicOcspResp).getEncoded();
    }

    private static OCSPResp givenOcspRespWithCertificateStatus(CertificateStatus certificateStatus) throws Exception {
        OCSPResp ocspResp = mock(OCSPResp.class);
        BasicOCSPResp basicOcspResp = mock(BasicOCSPResp.class);
        SingleResp singleResp = mock(SingleResp.class);
        when(ocspResp.getResponseObject()).thenReturn(basicOcspResp);
        when(basicOcspResp.getResponses()).thenReturn(new SingleResp[]{singleResp});
        when(singleResp.getCertStatus()).thenReturn(certificateStatus);
        return ocspResp;
    }

    private static ResilientUserCertificateOCSPCheckFailedException givenOcspCheckFailedException(List<RevocationInfo> revocationInfoList) {
        X509Certificate certificate = TestUtils.loadCertificateFromResource("id-card/38001085718(TEST_of_ESTEID2018).pem");
        return new ResilientUserCertificateOCSPCheckFailedException(
                "User certificate OCSP check failed", new ValidationInfo(certificate, revocationInfoList));
    }
}
