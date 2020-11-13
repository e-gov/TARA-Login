package ee.ria.taraauthserver.controllers;

import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.error.ErrorMessages;
import ee.ria.taraauthserver.error.NotFoundException;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.session.AuthState;
import ee.ria.taraauthserver.utils.SessionUtils;
import ee.ria.taraauthserver.xroad.BusinessRegistryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static ee.ria.taraauthserver.utils.SessionUtils.assertSessionInState;
import static ee.ria.taraauthserver.utils.SessionUtils.updateSession;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
@ConditionalOnProperty(value = "tara.legal-person-authentication.enabled", matchIfMissing = true)
public class LegalpersonController {

    @Autowired
    private final BusinessRegistryService eBusinessRegistryService;

    @GetMapping(value="/auth/legal_person/init")
    public String initLegalPerson(Model model, HttpServletRequest request) {
        AuthSession authSession = SessionUtils.getAuthSession();
        assertSessionInState(authSession, AuthState.NATURAL_PERSON_AUTHENTICATION_COMPLETED);

        if (!List.of(authSession.getLoginRequestInfo().getClient().getScope().split(" ")).contains("legalperson"))
            throw new BadRequestException(ErrorMessages.INVALID_REQUEST, String.format("client '%s' is not authorized to use scope 'legalperson'", authSession.getLoginRequestInfo().getClient().getClientId()));

        if (!authSession.getLoginRequestInfo().getRequestedScopes().contains("legalperson"))
            throw new BadRequestException(ErrorMessages.INVALID_REQUEST, "scope 'legalperson' was not requested in the initial OIDC authentication request");

        model.addAttribute("idCode", authSession.getAuthenticationResult().getIdCode());
        model.addAttribute("firstName", authSession.getAuthenticationResult().getFirstName());
        model.addAttribute("lastName", authSession.getAuthenticationResult().getLastName());
        model.addAttribute("dateOfBirth", authSession.getAuthenticationResult().getDateOfBirth());

        model.addAttribute("login_challenge", authSession.getLoginRequestInfo().getChallenge());

        authSession.setState(AuthState.LEGAL_PERSON_AUTHENTICATION_INIT);
        updateSession(authSession);

        return "legalPersonView";
    }

    @GetMapping(value="/auth/legal_person", produces = {MediaType.APPLICATION_JSON_VALUE})
    public ModelAndView fetchLegalPersonsList(HttpServletRequest request, HttpSession httpSession) {
        AuthSession authSession = SessionUtils.getAuthSession();

        assertSessionInState(authSession, AuthState.LEGAL_PERSON_AUTHENTICATION_INIT);
        Assert.notNull(authSession.getAuthenticationResult(), "Authentication credentials missing from session!");

        List<AuthSession.LegalPerson> legalPersons = eBusinessRegistryService.executeEsindusV2Service(authSession.getAuthenticationResult().getIdCode());
        authSession.setLegalPersonList(legalPersons);
        if (CollectionUtils.isEmpty(legalPersons)) {
            throw new NotFoundException("Current user has no valid legal person records in business registry");
        } else {
            authSession.setLegalPersonList(legalPersons);
            authSession.setState(AuthState.GET_LEGAL_PERSON_LIST);
            updateSession(authSession);
            return new ModelAndView(new MappingJackson2JsonView(), Collections.singletonMap("legalPersons", legalPersons));
        }
    }

    @PostMapping("/auth/legal_person/confirm")
    public String confirmLegalPerson(
            @RequestParam(name = "legal_person_identifier")
            @Size(max = 50)
            @Pattern(regexp = "[A-Za-z0-9]{1,}", message = "only characters and numbers allowed")
                    String legalPersonIdentifier) {
        AuthSession authSession = SessionUtils.getAuthSession();
        assertSessionInState(authSession, AuthState.GET_LEGAL_PERSON_LIST);
        List<AuthSession.LegalPerson> legalPersons = authSession.getLegalPersonList();
        Assert.notNull(legalPersons, "Legal person list was not found!");
        Assert.isTrue(!legalPersons.isEmpty(), "No list of authorized legal persons was found!");

        Optional<AuthSession.LegalPerson> selectedLegalPerson = legalPersons.stream().filter(e -> e.getLegalPersonIdentifier().equals(legalPersonIdentifier)).findFirst();
        if (selectedLegalPerson.isPresent()) {
            authSession.setSelectedLegalPerson(selectedLegalPerson.get());
            authSession.setState(AuthState.LEGAL_PERSON_AUTHENTICATION_COMPLETED);
            updateSession(authSession);
            log.info("Legal person selected: {}", legalPersonIdentifier);
            return "redirect:/auth/accept"; // TODO forward instead of redirect?
        } else {
            throw new BadRequestException(ErrorMessages.INVALID_REQUEST, String.format("Attempted to select invalid legal person with id: '%s'", legalPersonIdentifier));
        }
    }
}
