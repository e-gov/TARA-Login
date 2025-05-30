package ee.ria.taraauthserver.authentication.legalperson.xroad;

import ee.ria.taraauthserver.config.properties.LegalPersonProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.session.TaraSession;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import lombok.NonNull;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpMethod;
import org.springframework.util.Assert;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ee.ria.taraauthserver.logging.ClientRequestLogger.Service;
import static java.lang.String.format;
import static java.util.Arrays.stream;
import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;
import static org.apache.commons.lang3.StringUtils.join;
import static org.unbescape.xml.XmlEscape.escapeXml11;

@Slf4j
public class BusinessRegistryService {
    private static final String SOAP_REQUEST_TEMPLATE = "xtee-arireg.esindus_v2.v1.ftl";
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(Service.X_ROAD, this.getClass());
    private final Configuration templateConfiguration;
    private final LegalPersonProperties legalPersonProperties;
    private final SSLContext sslContext;
    private final String xpathFilterForEttevotjad;

    public BusinessRegistryService(@NonNull Configuration templateConfiguration,
        @NonNull LegalPersonProperties legalPersonProperties,
        @NonNull SSLContext xRoadTrustContext) {
        this.templateConfiguration = templateConfiguration;
        this.legalPersonProperties = legalPersonProperties;
        this.xpathFilterForEttevotjad = "//ettevotjad/item[" +
                "staatus = 'R' " +
                "and (" + getConditionList(legalPersonProperties.getEsindusv2AllowedTypes(), "oiguslik_vorm = '%s'") + ") " +
                "and isikud/item[" +
                "isikukood_riik = 'EST' " +
                "and fyysilise_isiku_kood = '%s' " +
                "and ainuesindusoigus_olemas = 'JAH'" +
                "]" +
                "]";
      this.sslContext = xRoadTrustContext;
    }

    public List<TaraSession.LegalPerson> executeEsindusV2Service(String idCode) {
        Assert.notNull(idCode, "idCode is required!");
        Assert.isTrue(idCode.matches("^[0-9]{11,11}$"), "idCode has invalid format! Must contain only numbers");

        String request = getEsindusV2Request(idCode, UUID.randomUUID().toString());
        NodeList response = send(request, format(xpathFilterForEttevotjad, idCode));
        if (response != null) {
            return extractResults(response);
        } else {
            return emptyList();
        }
    }

    @SneakyThrows
    private List<TaraSession.LegalPerson> extractResults(NodeList response) {
        List<TaraSession.LegalPerson> legalPersons = new ArrayList<>();
        for (int i = 0; i < response.getLength(); i++) {
            XPath xPath = XPathFactory.newInstance().newXPath();
            String idCode = (String) xPath.compile("ariregistri_kood/text()").evaluate(response.item(i), XPathConstants.STRING);
            String name = (String) xPath.compile("arinimi/text()").evaluate(response.item(i), XPathConstants.STRING);
            legalPersons.add(new TaraSession.LegalPerson(name, idCode));
        }
        return legalPersons;
    }

    protected String getEsindusV2Request(String idCode, String nonce) {
        try {
            Template template = templateConfiguration.getTemplate(SOAP_REQUEST_TEMPLATE);
            try (Writer writer = new StringWriter()) {

                Map<String, String> params = new HashMap<>();
                params.put("nonce", escapeXml11(nonce));
                params.put("serviceRoadInstance", escapeXml11(legalPersonProperties.getXRoadServiceInstance()));
                params.put("serviceMemberClass", escapeXml11(legalPersonProperties.getXRoadServiceMemberClass()));
                params.put("serviceMemberCode", escapeXml11(legalPersonProperties.getXRoadServiceMemberCode()));
                params.put("serviceSubsystemCode", escapeXml11(legalPersonProperties.getXRoadServiceSubsystemCode()));

                params.put("subsystemRoadInstance", escapeXml11(legalPersonProperties.getXRoadClientSubsystemInstance()));
                params.put("subsystemMemberClass", escapeXml11(legalPersonProperties.getXRoadClientSubsystemMemberClass()));
                params.put("subsystemMemberCode", escapeXml11(legalPersonProperties.getXRoadClientSubsystemMemberCode()));
                params.put("subsystemSubsystemCode", escapeXml11(legalPersonProperties.getXRoadClientSubsystemCode()));

                params.put("personIdCode", escapeXml11(idCode));
                template.process(params, writer);
                return writer.toString();
            }
        } catch (IOException | TemplateException e) {
            throw new IllegalStateException("Could not create SOAP request from template: " + e.getMessage(), e);
        }
    }

    protected NodeList send(String request, String filterExpression) {
        try {
            requestLogger.logRequest(legalPersonProperties.getXRoadServerUrl(), HttpMethod.POST, request);
            URL obj = new URL(legalPersonProperties.getXRoadServerUrl());
            HttpURLConnection con = (HttpURLConnection) getHttpURLConnection(obj);
            con.setReadTimeout(legalPersonProperties.getXRoadServerReadTimeoutInMilliseconds());
            con.setConnectTimeout(legalPersonProperties.getXRoadServerConnectTimeoutInMilliseconds());
            con.setRequestMethod("POST");
            con.setRequestProperty("SOAPAction", "");
            con.setRequestProperty("Content-Type", "text/xml;charset=UTF-8");
            con.setDoOutput(true);

            try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                wr.write(request.getBytes(StandardCharsets.UTF_8));
            }

            try (InputStream in = (InputStream) con.getContent()) {
                int responseCode = con.getResponseCode(); // TODO Why is response code not checked first? X-Road returns valid result with status code other than 200?
                String response = IOUtils.toString(in, StandardCharsets.UTF_8);
                requestLogger.logResponse(responseCode, response);

                DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
                builderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                builderFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                builderFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
                DocumentBuilder builder = builderFactory.newDocumentBuilder();
                Document xmlDocument = builder.parse(IOUtils.toInputStream(response, StandardCharsets.UTF_8));
                XPath xPath = XPathFactory.newInstance().newXPath();
                String faultCode = (String) xPath.compile("/Envelope/Body/Fault/faultcode/text()")
                        .evaluate(xmlDocument, XPathConstants.STRING);
                if (StringUtils.isEmpty(faultCode)) {
                    return (NodeList) xPath.compile(filterExpression).evaluate(xmlDocument, XPathConstants.NODESET);
                } else {
                    String faultstring = (String) xPath.compile("/Envelope/Body/Fault/faultstring/text()")
                            .evaluate(xmlDocument, XPathConstants.STRING);
                    throw new IllegalStateException("X-Road service returned a soap fault: faultcode = '" + faultCode
                            + "', faultstring = '" + faultstring + "'");
                }
            }
        } catch (SocketTimeoutException | ConnectException | UnknownHostException | SSLException e) {
            throw new ServiceNotAvailableException(ErrorCode.LEGAL_PERSON_X_ROAD_SERVICE_NOT_AVAILABLE, "Could not connect to business registry. Connection failed: " + e.getMessage(), e);
        } catch (XPathExpressionException | IOException | SAXException | ParserConfigurationException e) {
            throw new IllegalStateException("Failed to extract data from response: " + e.getMessage(), e);
        }
    }

    private URLConnection getHttpURLConnection(URL obj) throws IOException {
        if (obj.getProtocol().equals("https"))
            return getHttpsURLConnection(obj);
        else
            return obj.openConnection();
    }

    private HttpsURLConnection getHttpsURLConnection(URL obj) throws IOException {
        HttpsURLConnection httpsURLConnection = (HttpsURLConnection) obj.openConnection();
        httpsURLConnection.setSSLSocketFactory(sslContext.getSocketFactory());
        return httpsURLConnection;
    }

    private String getConditionList(String[] type, String parameter) {
        return join(stream(type).map(str -> format(parameter, str)).collect(toList()), " or ");
    }
}

