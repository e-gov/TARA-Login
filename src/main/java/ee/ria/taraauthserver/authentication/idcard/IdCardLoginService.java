package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.config.properties.AuthConfigurationProperties;
import ee.ria.taraauthserver.error.ErrorCode;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.logging.ClientRequestLogger;
import ee.ria.taraauthserver.logging.StatisticsLogger;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.EstonianIdCodeUtil;
import ee.ria.taraauthserver.utils.X509Utils;
import ee.sk.mid.MidNationalIdentificationCodeValidator;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateOCSPCheckFailedException;
import eu.webeid.resilientocsp.exceptions.ResilientUserCertificateRevokedException;
import eu.webeid.security.authtoken.WebEidAuthToken;
import eu.webeid.security.challenge.ChallengeNonceStore;
import eu.webeid.security.exceptions.AuthTokenException;
import eu.webeid.security.exceptions.CertificateExpiredException;
import eu.webeid.security.exceptions.CertificateNotYetValidException;
import eu.webeid.security.validator.ValidationInfo;
import eu.webeid.security.validator.revocationcheck.RevocationInfo;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_EXPIRED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_FORBIDDEN;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_CERT_NOT_YET_VALID;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_REVOKED;
import static ee.ria.taraauthserver.error.ErrorCode.IDC_VALIDATION_ERROR_RESULT_OTHER;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static net.logstash.logback.argument.StructuredArguments.value;

@Slf4j
@Service
@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
public class IdCardLoginService {

    public static final String CN_SERIALNUMBER = "SERIALNUMBER";
    public static final String CN_GIVEN_NAME = "GIVENNAME";
    public static final String CN_SURNAME = "SURNAME";

    private final AuthConfigurationProperties.IdCardAuthConfigurationProperties configurationProperties;
    private final AuthConfigurationProperties.FilterForEidasProxy filterForEidasProxy;
    private final ChallengeNonceStore nonceStore;
    private final StatisticsLogger statisticsLogger;
    private final AuthTokenValidatorResolver authTokenValidatorResolver;
    private final OcspRequestResponseLogger ocspRequestResponseLogger;

    @Autowired
    public IdCardLoginService(AuthConfigurationProperties.IdCardAuthConfigurationProperties configurationProperties,
                              AuthConfigurationProperties.FilterForEidasProxy filterForEidasProxy,
                              ChallengeNonceStore nonceStore,
                              StatisticsLogger statisticsLogger,
                              AuthTokenValidatorResolver authTokenValidatorResolver) {
        this(configurationProperties, filterForEidasProxy, nonceStore, statisticsLogger, authTokenValidatorResolver,
                new OcspRequestResponseLogger(ClientRequestLogger.Service.OCSP, IdCardLoginService.class));
    }

    public void attemptLogin(IdCardLoginController.WebEidData data, TaraSession taraSession) {
        String nonce;
        try {
            nonce = nonceStore.getAndRemove().getBase64EncodedNonce();
        } catch (AuthTokenException e) {
            throw new BadRequestException(INVALID_REQUEST, e.getMessage(), e);
        }

        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_CHECK_ESTEID_CERT);
        SessionUtils.getHttpSession().setAttribute(TARA_SESSION, taraSession);
        ValidationInfo validationInfo = handleTokenValidation(data.getAuthToken(), nonce, taraSession);
        processOcspValidationResults(validationInfo, taraSession);

        boolean isOcspEnabled = configurationProperties.getOcsp().isEnabled();
        if (!isOcspEnabled) {
            log.info("Skipping OCSP validation because OCSP is disabled.");
        }

        String eidasClientId = filterForEidasProxy.getClientId();
        X509Certificate certificate = validationInfo.subjectCertificate();
        if (taraSession.getOriginalClient().getClientId().equals(eidasClientId)) {
            validateIdCardValidForEidasAuthentication(certificate);
        }
        if (!isOcspEnabled) {
            updateAuthenticationResult(taraSession, certificate, null);
        }
        taraSession.setState(NATURAL_PERSON_AUTHENTICATION_COMPLETED);
    }

    private ValidationInfo handleTokenValidation(WebEidAuthToken authToken, String nonce, TaraSession taraSession) {
        try {
            return authTokenValidatorResolver.resolve(taraSession.getOriginalClient()).validate(authToken, nonce);
        } catch (CertificateExpiredException e) {
            throw new BadRequestException(IDC_CERT_EXPIRED, e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            throw new BadRequestException(IDC_CERT_NOT_YET_VALID, e.getMessage(), e);
        } catch (ResilientUserCertificateRevokedException e) {
            processOcspValidationResults(e.getValidationInfo(), taraSession);
            throw new BadRequestException(IDC_REVOKED, e.getMessage(), e);
        } catch (ResilientUserCertificateOCSPCheckFailedException e) {
            processOcspValidationResults(e.getValidationInfo(), taraSession);
            throw new BadRequestException(OcspExceptionTranslator.translateOcspCheckFailure(e), e.getMessage(), e);
        } catch (AuthTokenException e) {
            throw new BadRequestException(IDC_VALIDATION_ERROR_RESULT_OTHER, e.getMessage(), e);
        }
    }

    private void validateIdCardValidForEidasAuthentication(X509Certificate certificate) {
        List<ASN1ObjectIdentifier> certificatePolicyOids = X509Utils.getCertificatePolicyOids(certificate);

        boolean allowed = certificatePolicyOids.stream()
                .anyMatch(filterForEidasProxy.getAllowedPolicyOids()::contains);

        if (!allowed) {
            throw new BadRequestException(IDC_CERT_FORBIDDEN, "eIDAS authentication with given certificate policy OID is forbidden");
        }
    }

    void updateAuthenticationResult(TaraSession taraSession, X509Certificate certificate, String validatingOcspConfUrl) {
        Map<String, String> params = X509Utils.getCertificateParams(certificate);
        String idCode = EstonianIdCodeUtil.getEstonianIdCode(params.get(CN_SERIALNUMBER));
        TaraSession.IdCardAuthenticationResult authenticationResult = (TaraSession.IdCardAuthenticationResult) taraSession.getAuthenticationResult();
        List<String> certificatePolicyOids = X509Utils.getCertificatePolicyOids(certificate).stream()
                .map(ASN1ObjectIdentifier::getId)
                .toList();

        if (taraSession.isEmailScopeRequested()) {
            String email = X509Utils.getRfc822NameSubjectAltName(certificate);
            authenticationResult.setEmail(email);
        }
        authenticationResult.setErrorCode(null);
        authenticationResult.setOcspUrl(validatingOcspConfUrl);
        authenticationResult.setCertificatePolicyOids(certificatePolicyOids);
        authenticationResult.setFirstName(params.get(CN_GIVEN_NAME));
        authenticationResult.setLastName(params.get(CN_SURNAME));
        authenticationResult.setIdCode(idCode);
        authenticationResult.setCountry("EE");
        authenticationResult.setDateOfBirth(MidNationalIdentificationCodeValidator.getBirthDate(idCode));
        authenticationResult.setAcr(configurationProperties.getLevelOfAssurance());
        authenticationResult.setSubject(authenticationResult.getCountry() + authenticationResult.getIdCode());
        SessionUtils.getHttpSession().setAttribute(TARA_SESSION, taraSession);
    }

    void processOcspValidationResults(ValidationInfo validationInfo, TaraSession taraSession) {
        X509Certificate certificate = validationInfo.subjectCertificate();
        log.info("OCSP certificate info: Serialnumber=<{}>, SubjectDN=<{}>, issuerDN=<{}>",
                value("x509.serial_number", certificate.getSerialNumber().toString(16)),
                value("x509.subject.distinguished_name", certificate.getSubjectX500Principal().getName()),
                value("x509.issuer.distinguished_name", certificate.getIssuerX500Principal().getName()));

        int requestCount = 0;
        Iterator<RevocationInfo> iterator = validationInfo.revocationInfoList().iterator();
        while(iterator.hasNext()) {
            requestCount++;
            RevocationInfo revocationInfo = iterator.next();
            OcspResponseAttributes ocspResponseAttributes = OcspResponseAttributes.parse(revocationInfo, requestCount, !iterator.hasNext());
            if (ocspResponseAttributes.error() == null) {
                if (!ocspResponseAttributes.lastRequest()) {
                    throw new IllegalStateException("Only the last response can be successful");
                }
                updateAuthenticationResult(taraSession, certificate, ocspResponseAttributes.ocspUrl());
                statisticsLogger.logExternalTransaction(taraSession, ocspResponseAttributes.toOcspInfo());
                ocspRequestResponseLogger.logSuccess(ocspResponseAttributes.ocspUrl(), ocspResponseAttributes.ocspRequest(), ocspResponseAttributes.ocspResponse());
            } else {
                ErrorCode errorCode = OcspExceptionTranslator.translateOcspRequestError(ocspResponseAttributes.error());
                TaraSession.IdCardAuthenticationResult authenticationResult = (TaraSession.IdCardAuthenticationResult) taraSession.getAuthenticationResult();
                updateAuthenticationResult(taraSession, certificate, ocspResponseAttributes.ocspUrl());
                authenticationResult.setErrorCode(errorCode);
                statisticsLogger.logExternalTransaction(taraSession, ocspResponseAttributes.error(), ocspResponseAttributes.toOcspInfo());
                ocspRequestResponseLogger.logFailure(ocspResponseAttributes.ocspUrl(), ocspResponseAttributes.ocspRequest(), ocspResponseAttributes.ocspResponse(), ocspResponseAttributes.error());
            }
        }
    }
}
