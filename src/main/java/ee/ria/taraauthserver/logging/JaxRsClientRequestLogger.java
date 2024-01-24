package ee.ria.taraauthserver.logging;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.client.ClientResponseContext;
import jakarta.ws.rs.client.ClientResponseFilter;
import jakarta.ws.rs.ext.WriterInterceptor;
import jakarta.ws.rs.ext.WriterInterceptorContext;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.LogstashMarker;
import org.glassfish.jersey.message.MessageUtils;
import org.springframework.http.HttpStatus;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;

import static net.logstash.logback.argument.StructuredArguments.value;
import static net.logstash.logback.marker.Markers.append;

/**
 * Structured Smart-ID/Mobile-ID request logging filter
 *
 * @see ee.sk.mid.rest.MidLoggingFilter
 * @see ee.sk.smartid.rest.LoggingFilter
 */
@Slf4j
public class JaxRsClientRequestLogger implements ClientRequestFilter, ClientResponseFilter, WriterInterceptor {
    private static final String PROP_OUTPUT_STREAM = "loggingOutputStream";
    private static final String PROP_URL_FULL = "url.full";
    private static final String PROP_REQUEST_METHOD = "http.request.method";
    public static final String PROP_RESPONSE_BODY_CONTENT = "http.response.body.content";
    public static final String PROP_REQUEST_BODY_CONTENT = "http.request.body.content";
    public static final String PROP_RESPONSE_STATUS_CODE = "http.response.status_code";
    private final String LOG_REQUEST_MESSAGE;
    private final String LOG_RESPONSE_MESSAGE;

    public JaxRsClientRequestLogger(String serviceName) {
        LOG_REQUEST_MESSAGE = String.format("%s request", serviceName);
        LOG_RESPONSE_MESSAGE = String.format("%s response: {}", serviceName);
    }

    @Override
    public void filter(ClientRequestContext requestContext) {
        if (requestContext.hasEntity()) {
            wrapEntityStreamWithlog(requestContext);
        }
    }

    @Override
    public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext) throws IOException {
        if (responseContext.hasEntity()) {
            logResponseBody(requestContext, responseContext);
        }
    }

    @Override
    public void aroundWriteTo(WriterInterceptorContext context) throws IOException, WebApplicationException {
        context.proceed();
        logRequestBody(context);
    }

    private void wrapEntityStreamWithlog(ClientRequestContext requestContext) {
        OutputStream entityStream = requestContext.getEntityStream();
        LoggingOutputStream loggingOutputStream = new LoggingOutputStream(entityStream);
        requestContext.setEntityStream(loggingOutputStream);
        requestContext.setProperty(PROP_OUTPUT_STREAM, loggingOutputStream);
        requestContext.setProperty(PROP_URL_FULL, requestContext.getUri().toString());
        requestContext.setProperty(PROP_REQUEST_METHOD, requestContext.getMethod());
    }

    private void logResponseBody(ClientRequestContext requestContext, ClientResponseContext responseContext) throws IOException {
        Charset charset = MessageUtils.getCharset(responseContext.getMediaType());
        InputStream entityStream = responseContext.getEntityStream();
        byte[] bodyBytes = readInputStreamBytes(entityStream);
        responseContext.setEntityStream(new ByteArrayInputStream(bodyBytes));
        LogstashMarker marker = append(PROP_URL_FULL, requestContext.getUri().toString())
                .and(append(PROP_REQUEST_METHOD, requestContext.getMethod()))
                .and(append(PROP_RESPONSE_BODY_CONTENT, new String(bodyBytes, charset))); // NB! Do not use appendRaw. Can create elasticsearch mapping conflict.
        if (HttpStatus.valueOf(responseContext.getStatus()).is2xxSuccessful()) {
            log.info(marker, LOG_RESPONSE_MESSAGE, value(PROP_RESPONSE_STATUS_CODE, responseContext.getStatus()));
        } else {
            log.error(marker, LOG_RESPONSE_MESSAGE, value(PROP_RESPONSE_STATUS_CODE, responseContext.getStatus()));
        }
    }

    private byte[] readInputStreamBytes(InputStream entityStream) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = entityStream.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        return result.toByteArray();
    }

    private void logRequestBody(WriterInterceptorContext context) {
        LoggingOutputStream loggingOutputStream = (LoggingOutputStream) context.getProperty(PROP_OUTPUT_STREAM);
        if (loggingOutputStream != null) {
            Charset charset = MessageUtils.getCharset(context.getMediaType());
            byte[] bytes = loggingOutputStream.getBytes();
            log.info(append(PROP_URL_FULL, context.getProperty(PROP_URL_FULL))
                            .and(append(PROP_REQUEST_METHOD, context.getProperty(PROP_REQUEST_METHOD)))
                            .and(append(PROP_REQUEST_BODY_CONTENT, new String(bytes, charset))), // NB! Do not use appendRaw. Can create elasticsearch mapping conflict.
                    LOG_REQUEST_MESSAGE);
        }
    }

    public static class LoggingOutputStream extends FilterOutputStream {
        private final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        public LoggingOutputStream(OutputStream out) {
            super(out);
        }

        public void write(byte[] b) throws IOException {
            super.write(b);
            this.byteArrayOutputStream.write(b);
        }

        public void write(int b) throws IOException {
            super.write(b);
            this.byteArrayOutputStream.write(b);
        }

        public byte[] getBytes() {
            return this.byteArrayOutputStream.toByteArray();
        }
    }
}
