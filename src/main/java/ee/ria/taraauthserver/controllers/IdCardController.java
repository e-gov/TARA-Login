package ee.ria.taraauthserver.controllers;

import ee.ria.taraauthserver.config.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.*;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.utils.OCSPValidator;
import ee.ria.taraauthserver.utils.X509Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import static ee.ria.taraauthserver.utils.Constants.HEADER_SSL_CLIENT_CERT;
import static ee.ria.taraauthserver.utils.Constants.TARA_SESSION;

@Slf4j
@Controller
public class IdCardController {

    @Autowired
    private AuthConfigurationProperties.IdCardAuthConfigurationProperties configurationProperties;

    @Autowired
    OCSPValidator ocspValidator;

    @Autowired
    private SessionRepository sessionRepository;

    @GetMapping(path = {"/auth/id"})
    @ResponseBody
    public HashMap<String, String> handleRequest(HttpServletRequest request, HttpSession httpSession) {
        AuthSession authSession = (AuthSession) httpSession.getAttribute(TARA_SESSION);
        if (authSession == null)
            throw new BadRequestException("message.error.esteid.invalid-request");

        String encodedCertificate = request.getHeader(HEADER_SSL_CLIENT_CERT);
        if (encodedCertificate == null)
            throw new BadRequestException("Expected header '" + HEADER_SSL_CLIENT_CERT + "' could not be found in request");
        if (!StringUtils.hasLength(encodedCertificate))
            throw new BadRequestException("Unable to find certificate from request");

        X509Certificate certificate = X509Utils.toX509Certificate(encodedCertificate);
        validateUserCert(certificate);

        checkCertStatus(certificate);

        HashMap<String, String> map = new HashMap<>();
        map.put("status", "COMPLETED");
        return map;
    }

    private void validateUserCert(X509Certificate x509Certificate) {
        try {
            x509Certificate.checkValidity();
        } catch (CertificateNotYetValidException e) {
            throw new UserAuthenticationFailedException(
                    "message.idc.certnotyetvalid",
                    "User certificate is not yet valid", e);
        } catch (CertificateExpiredException e) {
            throw new UserAuthenticationFailedException(
                    "message.idc.certexpired",
                    "User certificate is expired", e);
        }
    }

    private void checkCertStatus(X509Certificate certificate) {
        if (configurationProperties.isOcspEnabled()) {
            try {
                ocspValidator.checkCert(certificate);
            } catch (OCSPServiceNotAvailableException exception) {
                throw new ExternalServiceHasFailedException(
                        "message.idc.error.ocsp.not.available",
                        "OCSP service is currently not available, please try again later",
                        exception);
            } catch (OCSPValidationException exception) {
                throw new UserAuthenticationFailedException(
                        String.format("message.idc.%s", exception.getStatus().name().toLowerCase()),
                        exception.getMessage(),
                        exception);
            }
        }
    }

}
