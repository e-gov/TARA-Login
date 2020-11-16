package ee.ria.taraauthserver.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import ee.ria.taraauthserver.config.AuthConfigurationProperties;
import ee.ria.taraauthserver.config.AuthenticationType;
import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.error.ErrorMessages;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.utils.ValidNationalIdNumber;
import ee.sk.mid.*;
import ee.sk.mid.exception.*;
import ee.sk.mid.rest.dao.MidSessionStatus;
import ee.sk.mid.rest.dao.request.MidAuthenticationRequest;
import ee.sk.mid.rest.dao.response.MidAuthenticationResponse;
import lombok.Data;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.MediaType;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpSession;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotAllowedException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;

import static ee.ria.taraauthserver.session.AuthState.*;

@Slf4j
@Validated
@Controller
public class AuthMidController {

    @Autowired
    private MidClient midClient;

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    private AuthConfigurationProperties authConfigurationProperties;

    @Autowired
    private AuthConfigurationProperties.MidAuthConfigurationProperties midAuthConfigurationProperties;

    private Map<String, MidLanguage> midLanguages = Map.of(
            "et", MidLanguage.EST,
            "en", MidLanguage.ENG,
            "ru", MidLanguage.RUS);

    @PostMapping(value = "/auth/mid/init", produces = MediaType.TEXT_HTML_VALUE)
    public String authMidInit(@Validated @ModelAttribute(value = "credential") MidRequestBody requestParameters, Model model, HttpSession httpSession) {

        requestParameters.telephoneNumber = "+372" + requestParameters.telephoneNumber;

        Session session = sessionRepository.findById(httpSession.getId());
        if (session == null)
            throw new BadRequestException("message.mid-rest.error.internal-error");
        AuthSession authSession = session.getAttribute("session");
        validateAuthSession(authSession);
        log.info("AuthSession: " + authSession);

        MidAuthenticationHashToSign authenticationHash = MidAuthenticationHashToSign.generateRandomHashOfType(MidHashType.valueOf(midAuthConfigurationProperties.getHashType()));
        String verificationCode = authenticationHash.calculateVerificationCode();

        MidAuthenticationResponse response = createMidAuthSession(requestParameters, authenticationHash, authSession);

        CompletableFuture<MidSessionStatus> future = startPollingForMidSessionStatus(response);
        future.thenApply(midSessionStatus -> {
            if (StringUtils.equalsIgnoreCase("COMPLETE", midSessionStatus.getState())) {
                if (StringUtils.equalsIgnoreCase("OK", midSessionStatus.getResult())) {
                    try {
                        MidAuthenticationResult midAuthenticationResult = getMidAuthenticationResult(authenticationHash, future);
                        String idCode = midAuthenticationResult.getAuthenticationIdentity().getIdentityCode();
                        authSession.setState(AUTHENTICATION_SUCCESS);
                        AuthSession.MidAuthenticationResult authenticationResult = new AuthSession.MidAuthenticationResult();

                        authenticationResult.setIdCode(midAuthenticationResult.getAuthenticationIdentity().getIdentityCode());
                        authenticationResult.setCountry(midAuthenticationResult.getAuthenticationIdentity().getCountry());
                        authenticationResult.setFirstName(midAuthenticationResult.getAuthenticationIdentity().getGivenName());
                        authenticationResult.setLastName(midAuthenticationResult.getAuthenticationIdentity().getSurName());
                        authenticationResult.setPhoneNumber(requestParameters.getTelephoneNumber());
                        authenticationResult.setSubject(requestParameters.getTelephoneNumber());
                        authenticationResult.setDateOfBirth(getDateOfBirthFromIdCode(idCode));
                        authenticationResult.setAmr(AuthenticationType.MobileID);
                        authenticationResult.setAcr(midAuthConfigurationProperties.getLevelOfAssurance());

                        authSession.setAuthenticationResult(authenticationResult);
                        session.setAttribute("session", authSession);
                        sessionRepository.save(session);
                    } catch (Exception e) {
                        log.info(e.getMessage());
                        log.info("EXCEPTION: " + e);
                    }
                }
            }
            return authSession;

        }).exceptionally(e -> {
            if (e.getCause() instanceof javax.ws.rs.BadRequestException) {
                setSessionStateFailed(session, authSession, e.getMessage());
            }
            if (e.getCause() instanceof javax.ws.rs.NotAuthorizedException) {
                setSessionStateFailed(session, authSession, e.getMessage());
            }
            if (e.getCause() instanceof MidSessionNotFoundException) {

                setSessionStateFailed(session, authSession, e.getMessage());
            }
            if (e.getCause() instanceof NotAllowedException) {
                setSessionStateFailed(session, authSession, e.getMessage());
            }
            if (e.getCause() instanceof InternalServerErrorException) {
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_INTERNAL_ERROR.getMessage());
                setSessionStateFailed(session, authSession, e.getMessage());
            }
            if (e.getCause() instanceof MidNotMidClientException) {
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.NOT_MID_CLIENT.getMessage());
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorStatus(400);
                setSessionStateFailed(session, authSession, e.getMessage());
            }
            if (e.getCause() instanceof MidSessionTimeoutException) {
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_TRANSACTION_EXPIRED.getMessage());
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorStatus(500);
                setSessionStateFailed(session, authSession, e.getMessage());
            }
            if (e.getCause() instanceof MidUserCancellationException) {
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_USER_CANCEL.getMessage());
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorStatus(400);
                setSessionStateFailed(session, authSession, e.getMessage());
            }
            if (e.getCause() instanceof MidInvalidUserConfigurationException) {
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_HASH_MISMATCH.getMessage());
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorStatus(500);
                setSessionStateFailed(session, authSession, e.getMessage());
            }
            if (e.getCause() instanceof MidPhoneNotAvailableException) {
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_PHONE_ABSENT.getMessage());
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorStatus(400);
                setSessionStateFailed(session, authSession, e.getMessage());
            }
            if (e.getCause() instanceof MidDeliveryException) {
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_DELIVERY_ERROR.getMessage());
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorStatus(400);
                setSessionStateFailed(session, authSession, e.getMessage());
            }
            if (e.getCause() instanceof MidInternalErrorException) {
                ((AuthSession.MidAuthenticationResult) authSession.getAuthenticationResult()).setErrorMessage(ErrorMessages.MID_INTERNAL_ERROR.getMessage());
                setSessionStateFailed(session, authSession, e.getMessage());
            }
            return null;
        }).thenAcceptAsync(s -> {
        });

        session.setAttribute("session", authSession);
        sessionRepository.save(session);

        model.addAttribute("mobileIdVerificationCode", verificationCode);
        return "midLoginCode";
    }

    private void setSessionStateFailed(Session session, AuthSession authSession, String message) {
        log.info("Mid polling failed: " + message);
        authSession.setState(AUTHENTICATION_FAILED);
        session.setAttribute("session", authSession);
        sessionRepository.save(session);
    }

    private LocalDate getDateOfBirthFromIdCode(String idCode) {
        String firstNumber = idCode.substring(0, 1);
        String century = "";
        if (firstNumber.equals("1") || firstNumber.equals("2"))
            century = "18";
        if (firstNumber.equals("3") || firstNumber.equals("4"))
            century = "19";
        if (firstNumber.equals("5") || firstNumber.equals("6"))
            century = "20";
        if (firstNumber.equals("7") || firstNumber.equals("8"))
            century = "21";
        String year = century + idCode.substring(1, 3);
        String month = idCode.substring(3, 5);
        String day = idCode.substring(5, 7);

        return LocalDate.of(Integer.parseInt(year), Integer.parseInt(month), Integer.parseInt(day));
    }

    private void validateAuthSession(AuthSession authSession) {

        if (authSession == null || authSession.getState() != INIT_AUTH_PROCESS || !authSession.getAllowedAuthMethods().contains(AuthenticationType.MobileID))
            throw new BadRequestException("message.mid-rest.error.internal-error");
        authSession.setState(INIT_MID);
    }

    private MidAuthenticationResponse createMidAuthSession(MidRequestBody requestParameters, MidAuthenticationHashToSign authenticationHash, AuthSession authSession) {
        String translatedShortName = authSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getShortName();

        if (authSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getNameTranslations() != null) {
            Map<String, String> serviceNameTranslations = authSession.getLoginRequestInfo().getClient().getMetaData().getOidcClient().getNameTranslations();
            Locale locale = LocaleContextHolder.getLocale();
            if (serviceNameTranslations.containsKey(locale.getLanguage()))
                translatedShortName = serviceNameTranslations.get(locale.getLanguage());
        }


        MidAuthenticationRequest midRequest = MidAuthenticationRequest.newBuilder()
                .withPhoneNumber(requestParameters.getTelephoneNumber())
                .withNationalIdentityNumber(requestParameters.getIdCode())
                .withHashToSign(authenticationHash)
                .withLanguage(getMidLanguage(authSession))
                .withDisplayText(translatedShortName)
                .withDisplayTextFormat(isServiceNameUsingSpecialCharacters(translatedShortName) ? MidDisplayTextFormat.UCS2 : MidDisplayTextFormat.GSM7)
                .build();

        try {
            log.info("mid request: " + midRequest.toString());
            MidAuthenticationResponse response = midClient.getMobileIdConnector().authenticate(midRequest);
            log.info("mid response: " + response.toString());
            authSession.setState(POLL_MID_STATUS);
            AuthSession.MidAuthenticationResult midAuthenticationResult = new AuthSession.MidAuthenticationResult();
            authSession.setAuthenticationResult(midAuthenticationResult);
            midAuthenticationResult.setMidSessionId(response.getSessionID());
            return response;
        } catch (MidInternalErrorException e) {
            log.error("Mid authentication failed: " + e.getMessage());
            throw new RuntimeException(ErrorMessages.MID_INTERNAL_ERROR.getMessage());
        } catch (MidException | NotAllowedException e) {
            log.error("Mid authentication failed: " + e.toString());
            throw new RuntimeException(ErrorMessages.MID_ERROR_GENERAL.getMessage());
        }
    }

    private static boolean isServiceNameUsingSpecialCharacters(String serviceName) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile("[а-яА-ЯЁё]", java.util.regex.Pattern.CASE_INSENSITIVE);
        String[] specialCharacters = {"Õ", "Š", "Ž", "š", "ž", "õ", "Ą", "Č", "Ę", "Ė", "Į", "Š", "Ų", "Ū", "Ž", "ą", "č", "ę", "ė", "į", "š", "ų", "ū", "ž"};
        Matcher m = p.matcher(serviceName);
        boolean isSpecialCharacterIncluded = m.find();
        return Arrays.stream(specialCharacters).anyMatch(serviceName::contains) || isSpecialCharacterIncluded;
    }

    @NotNull
    private CompletableFuture<MidSessionStatus> startPollingForMidSessionStatus(MidAuthenticationResponse response) {
        CompletableFuture<MidSessionStatus> future
                = CompletableFuture.supplyAsync(() -> midClient.getSessionStatusPoller().fetchFinalSessionStatus(response.getSessionID(),
                "/authentication/session/" + response.getSessionID()));

        return future;
    }

    private MidAuthenticationResult getMidAuthenticationResult(MidAuthenticationHashToSign authenticationHash, CompletableFuture<MidSessionStatus> future) {
        try {
            MidAuthentication authentication = midClient.createMobileIdAuthentication(future.get(), authenticationHash);
            MidAuthenticationResponseValidator validator = new MidAuthenticationResponseValidator(getMidTrustStore());
            return validator.validate(authentication);
        } catch (Exception e) {
            e.printStackTrace();
            throw new IllegalStateException("Internal server error when validating mid authentication result.", e);
        }
    }

    public KeyStore getMidTrustStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        InputStream is = getClass().getClassLoader().getResourceAsStream(midAuthConfigurationProperties.getTruststorePath());
        KeyStore trustStore = KeyStore.getInstance(midAuthConfigurationProperties.getTruststoreType());
        trustStore.load(is, midAuthConfigurationProperties.getTruststorePassword().toCharArray());
        return trustStore;
    }

    private MidLanguage getMidLanguage(AuthSession authSession) {
        if (authSession.getLoginRequestInfo().getOidcContext().getUiLocales() == null)
            return midLanguages.get(authConfigurationProperties.getDefaultLocale());
        return midLanguages.get(authSession.getLoginRequestInfo().getOidcContext().getUiLocales().get(0));
    }

    @Data
    @ToString
    public static class MidRequestBody {

        @NotBlank(message = "message.mid-rest.error.invalid-identity-code")
        @Size(max = 11, message = "message.mid-rest.error.invalid-identity-code")
        @ValidNationalIdNumber(message = "message.mid-rest.error.invalid-identity-code")
        @JsonProperty("id_code")
        private String idCode;
        @NotBlank(message = "message.mid-rest.error.invalid-phone-number")
        @Pattern(regexp = "\\d{8,15}", message = "message.mid-rest.error.invalid-phone-number")
        private String telephoneNumber;
    }
}
