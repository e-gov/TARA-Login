package ee.ria.taraauthserver.authentication.idcard;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import eu.webeid.ocsp.exceptions.OCSPClientException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;

import java.io.IOException;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OcspRequestResponseLoggerTest {

    private static final String OCSP_URL = "http://ocsp.test";
    private static final byte[] REQUEST_BYTES = "ocsp-request".getBytes();
    private static final byte[] RESPONSE_BYTES = "ocsp-response".getBytes();
    private static final String REQUEST_BASE64 = Base64.getEncoder().encodeToString(REQUEST_BYTES);
    private static final String RESPONSE_BASE64 = Base64.getEncoder().encodeToString(RESPONSE_BYTES);

    private ClientRequestLogger requestLogger;
    private OcspRequestResponseLogger ocspRequestResponseLogger;
    private OCSPReq ocspReq;
    private OCSPResp ocspResp;

    @BeforeEach
    void setUp() {
        requestLogger = mock(ClientRequestLogger.class);
        ocspRequestResponseLogger = new OcspRequestResponseLogger(requestLogger);
        ocspReq = mock(OCSPReq.class);
        ocspResp = mock(OCSPResp.class);
    }

    @Test
    void logSuccess_whenEncodingSucceeds_logsBase64EncodedRequestAsPost() throws IOException {
        givenOcspRequestEncodes();
        givenOcspResponseEncodes();

        ocspRequestResponseLogger.logSuccess(OCSP_URL, ocspReq, ocspResp);

        verify(requestLogger).logRequest(OCSP_URL, HttpMethod.POST, REQUEST_BASE64);
    }

    @Test
    void logSuccess_whenEncodingSucceeds_logsBase64EncodedResponseWithStatus200() throws IOException {
        givenOcspRequestEncodes();
        givenOcspResponseEncodes();

        ocspRequestResponseLogger.logSuccess(OCSP_URL, ocspReq, ocspResp);

        verify(requestLogger).logResponse(200, RESPONSE_BASE64);
    }

    @Test
    void logSuccess_whenResponseEncodingFails_doesNotThrow() throws IOException {
        givenOcspRequestEncodes();
        givenOcspResponseEncodingFails();

        assertThatCode(() -> ocspRequestResponseLogger.logSuccess(OCSP_URL, ocspReq, ocspResp))
                .doesNotThrowAnyException();
    }

    @Test
    void logSuccess_whenResponseEncodingFails_stillLogsRequest() throws IOException {
        givenOcspRequestEncodes();
        givenOcspResponseEncodingFails();

        ocspRequestResponseLogger.logSuccess(OCSP_URL, ocspReq, ocspResp);

        verify(requestLogger).logRequest(OCSP_URL, HttpMethod.POST, REQUEST_BASE64);
    }

    @Test
    void logSuccess_whenRequestEncodingFails_doesNotThrow() throws IOException {
        givenOcspRequestEncodingFails();
        givenOcspResponseEncodes();

        assertThatCode(() -> ocspRequestResponseLogger.logSuccess(OCSP_URL, ocspReq, ocspResp))
                .doesNotThrowAnyException();
    }

    @Test
    void logSuccess_whenRequestEncodingFails_skipsRequestLogging() throws IOException {
        givenOcspRequestEncodingFails();
        givenOcspResponseEncodes();

        ocspRequestResponseLogger.logSuccess(OCSP_URL, ocspReq, ocspResp);

        verify(requestLogger, never()).logRequest(anyString(), any(), any());
    }

    @Test
    void logSuccess_whenRequestEncodingFails_stillLogsResponse() throws IOException {
        givenOcspRequestEncodingFails();
        givenOcspResponseEncodes();

        ocspRequestResponseLogger.logSuccess(OCSP_URL, ocspReq, ocspResp);

        verify(requestLogger).logResponse(200, RESPONSE_BASE64);
    }

    @Test
    void logSuccess_whenOcspRequestMissing_logsRequestWithoutBody() throws IOException {
        givenOcspResponseEncodes();

        ocspRequestResponseLogger.logSuccess(OCSP_URL, null, ocspResp);

        verify(requestLogger).logRequest(OCSP_URL, HttpMethod.POST);
    }

    @Test
    void constructor_whenServiceAndClassToBeLoggedGiven_emitsLogsUnderGivenClassLoggerName() throws IOException {
        givenOcspRequestEncodes();
        givenOcspResponseEncodes();
        Logger classToBeLoggedLogger = (Logger) LoggerFactory.getLogger(OcspRequestResponseLoggerTest.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        classToBeLoggedLogger.addAppender(appender);

        try {
            new OcspRequestResponseLogger(ClientRequestLogger.Service.OCSP, OcspRequestResponseLoggerTest.class)
                    .logSuccess(OCSP_URL, ocspReq, ocspResp);
        } finally {
            classToBeLoggedLogger.detachAppender(appender);
        }

        assertThat(appender.list)
                .extracting(ILoggingEvent::getFormattedMessage)
                .containsExactly("OCSP request", "OCSP response: 200");
    }

    @Test
    void logFailure_whenOcspRequestMissing_logsRequestWithoutBody() throws IOException {
        givenOcspResponseEncodes();

        ocspRequestResponseLogger.logFailure(OCSP_URL, null, ocspResp, new RuntimeException("OCSP check failed"));

        verify(requestLogger).logRequest(OCSP_URL, HttpMethod.POST);
    }

    @Test
    void logFailure_whenOcspRequestPresent_logsBase64EncodedRequest() throws IOException {
        givenOcspRequestEncodes();
        OCSPClientException exception = new OCSPClientException("OCSP request failed", RESPONSE_BYTES, 503);

        ocspRequestResponseLogger.logFailure(OCSP_URL, ocspReq, null, exception);

        verify(requestLogger).logRequest(OCSP_URL, HttpMethod.POST, REQUEST_BASE64);
    }

    @Test
    void logFailure_whenOcspClientExceptionWithStatusCodeAndBody_logsThatStatusAndBody() throws IOException {
        givenOcspRequestEncodes();
        OCSPClientException exception = new OCSPClientException("OCSP request failed", RESPONSE_BYTES, 503);

        ocspRequestResponseLogger.logFailure(OCSP_URL, ocspReq, null, exception);

        verify(requestLogger).logResponse(503, RESPONSE_BASE64);
    }

    @Test
    void logFailure_whenOcspClientExceptionWithoutStatusCode_logsStatusMinusOne() throws IOException {
        givenOcspRequestEncodes();
        OCSPClientException exception = new OCSPClientException("OCSP request failed", RESPONSE_BYTES, null);

        ocspRequestResponseLogger.logFailure(OCSP_URL, ocspReq, null, exception);

        verify(requestLogger).logResponse(-1, RESPONSE_BASE64);
    }

    @Test
    void logFailure_whenOcspClientExceptionWithoutBody_logsStatusOnly() throws IOException {
        givenOcspRequestEncodes();
        OCSPClientException exception = new OCSPClientException("OCSP request failed", null, 500);

        ocspRequestResponseLogger.logFailure(OCSP_URL, ocspReq, null, exception);

        verify(requestLogger).logResponse(500);
    }

    @Test
    void logFailure_whenNonClientExceptionWithResponse_logsStatus200WithEncodedResponse() throws IOException {
        givenOcspRequestEncodes();
        givenOcspResponseEncodes();

        ocspRequestResponseLogger.logFailure(OCSP_URL, ocspReq, ocspResp, new RuntimeException("certificate revoked"));

        verify(requestLogger).logResponse(200, RESPONSE_BASE64);
    }

    @Test
    void logFailure_whenResponseEncodingFails_doesNotThrow() throws IOException {
        givenOcspRequestEncodes();
        givenOcspResponseEncodingFails();

        assertThatCode(() -> ocspRequestResponseLogger.logFailure(OCSP_URL, ocspReq, ocspResp, new RuntimeException("certificate revoked")))
                .doesNotThrowAnyException();
    }

    @Test
    void logFailure_whenResponseEncodingFails_stillLogsRequest() throws IOException {
        givenOcspRequestEncodes();
        givenOcspResponseEncodingFails();

        ocspRequestResponseLogger.logFailure(OCSP_URL, ocspReq, ocspResp, new RuntimeException("certificate revoked"));

        verify(requestLogger).logRequest(OCSP_URL, HttpMethod.POST, REQUEST_BASE64);
    }

    @Test
    void logFailure_whenResponseEncodingFails_skipsResponseLogging() throws IOException {
        givenOcspRequestEncodes();
        givenOcspResponseEncodingFails();

        ocspRequestResponseLogger.logFailure(OCSP_URL, ocspReq, ocspResp, new RuntimeException("certificate revoked"));

        verify(requestLogger, never()).logResponse(anyInt());
        verify(requestLogger, never()).logResponse(anyInt(), anyString());
    }

    @Test
    void logFailure_whenRequestEncodingFails_doesNotThrow() throws IOException {
        givenOcspRequestEncodingFails();
        OCSPClientException exception = new OCSPClientException("OCSP request failed", RESPONSE_BYTES, 503);

        assertThatCode(() -> ocspRequestResponseLogger.logFailure(OCSP_URL, ocspReq, null, exception))
                .doesNotThrowAnyException();
    }

    @Test
    void logFailure_whenRequestEncodingFails_skipsRequestLogging() throws IOException {
        givenOcspRequestEncodingFails();
        OCSPClientException exception = new OCSPClientException("OCSP request failed", RESPONSE_BYTES, 503);

        ocspRequestResponseLogger.logFailure(OCSP_URL, ocspReq, null, exception);

        verify(requestLogger, never()).logRequest(anyString(), any(), any());
    }

    @Test
    void logFailure_whenRequestEncodingFails_stillLogsResponse() throws IOException {
        givenOcspRequestEncodingFails();
        OCSPClientException exception = new OCSPClientException("OCSP request failed", RESPONSE_BYTES, 503);

        ocspRequestResponseLogger.logFailure(OCSP_URL, ocspReq, null, exception);

        verify(requestLogger).logResponse(503, RESPONSE_BASE64);
    }

    private void givenOcspRequestEncodes() throws IOException {
        when(ocspReq.getEncoded()).thenReturn(REQUEST_BYTES);
    }

    private void givenOcspResponseEncodes() throws IOException {
        when(ocspResp.getEncoded()).thenReturn(RESPONSE_BYTES);
    }

    private void givenOcspRequestEncodingFails() throws IOException {
        when(ocspReq.getEncoded()).thenThrow(new IOException("encoding failed"));
    }

    private void givenOcspResponseEncodingFails() throws IOException {
        when(ocspResp.getEncoded()).thenThrow(new IOException("encoding failed"));
    }
}
