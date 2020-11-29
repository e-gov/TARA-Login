package ee.ria.taraauthserver.authentication.legalperson;

import ee.ria.taraauthserver.error.Exceptions.BadRequestException;
import ee.ria.taraauthserver.error.Exceptions.NotFoundException;
import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.utils.SessionUtils;
import ee.ria.taraauthserver.authentication.legalperson.xroad.BusinessRegistryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
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

import static ee.ria.taraauthserver.config.properties.TaraScope.LEGALPERSON;
import static ee.ria.taraauthserver.error.ErrorTranslationCodes.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.utils.SessionUtils.assertSessionInState;
import static ee.ria.taraauthserver.utils.SessionUtils.updateSession;
import static java.lang.String.format;
import static org.springframework.util.Assert.isTrue;
import static org.springframework.util.Assert.notNull;
import static org.springframework.util.CollectionUtils.isEmpty;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
@ConditionalOnProperty(value = "tara.legal-person-authentication.enabled", matchIfMissing = true)
public class LegalpersonController {

    @Autowired
    private final BusinessRegistryService eBusinessRegistryService;

    @GetMapping(value="/auth/legal_person/init")
    public String initLegalPerson(Model model) {
        TaraSession taraSession = SessionUtils.getAuthSession();
        assertSessionInState(taraSession, NATURAL_PERSON_AUTHENTICATION_COMPLETED);

        if (!isLegalpersonScopeAllowed(taraSession))
            throw new BadRequestException(INVALID_REQUEST, format("client '%s' is not authorized to use scope '%s'",
                    taraSession.getLoginRequestInfo().getClient().getClientId(), LEGALPERSON.getFormalName()));

        if (!isLegalpersonScopeRequested(taraSession))
            throw new BadRequestException(INVALID_REQUEST,
                    format("scope '%s' was not requested in the initial OIDC authentication request", LEGALPERSON.getFormalName()));

        model.addAttribute("idCode", taraSession.getAuthenticationResult().getIdCode());
        model.addAttribute("firstName", taraSession.getAuthenticationResult().getFirstName());
        model.addAttribute("lastName", taraSession.getAuthenticationResult().getLastName());
        model.addAttribute("dateOfBirth", taraSession.getAuthenticationResult().getDateOfBirth());
        model.addAttribute("login_challenge", taraSession.getLoginRequestInfo().getChallenge());

        taraSession.setState(LEGAL_PERSON_AUTHENTICATION_INIT);
        updateSession(taraSession);

        return "legalPersonView";
    }

    @GetMapping(value="/auth/legal_person", produces = {MediaType.APPLICATION_JSON_VALUE})
    public ModelAndView fetchLegalPersonsList(HttpServletRequest request, HttpSession httpSession) {
        TaraSession taraSession = SessionUtils.getAuthSession();

        assertSessionInState(taraSession, LEGAL_PERSON_AUTHENTICATION_INIT);
        notNull(taraSession.getAuthenticationResult(), "Authentication credentials missing from session!");

        List<TaraSession.LegalPerson> legalPersons = eBusinessRegistryService.executeEsindusV2Service(taraSession.getAuthenticationResult().getIdCode());

        if (isEmpty(legalPersons)) {
            throw new NotFoundException("Current user has no valid legal person records in business registry");
        } else {
            taraSession.setLegalPersonList(legalPersons);
            taraSession.setState(GET_LEGAL_PERSON_LIST);
            updateSession(taraSession);
            return new ModelAndView(new MappingJackson2JsonView(), Collections.singletonMap("legalPersons", legalPersons));
        }
    }

    @PostMapping("/auth/legal_person/confirm")
    public String confirmLegalPerson(
            @RequestParam(name = "legal_person_identifier")
            @Size(max = 50)
            @Pattern(regexp = "[a-zA-Z0-9-_]{1,}", message = "invalid legal person identifier")
                    String legalPersonIdentifier) {
        TaraSession taraSession = SessionUtils.getAuthSession();
        assertSessionInState(taraSession, GET_LEGAL_PERSON_LIST);
        List<TaraSession.LegalPerson> legalPersons = taraSession.getLegalPersonList();
        notNull(legalPersons, "Invalid state. Legal person list was not found!");
        isTrue(!legalPersons.isEmpty(), "Invalid state. No list of authorized legal persons was found!");

        Optional<TaraSession.LegalPerson> selectedLegalPerson = getLegalperson(legalPersonIdentifier, legalPersons);
        if (selectedLegalPerson.isPresent()) {
            taraSession.setSelectedLegalPerson(selectedLegalPerson.get());
            taraSession.setState(LEGAL_PERSON_AUTHENTICATION_COMPLETED);
            updateSession(taraSession);
            log.info("Legal person selected: {}", legalPersonIdentifier);
            return "redirect:/auth/accept";
        } else {
            throw new BadRequestException(INVALID_REQUEST, format("Attempted to select invalid legal person with id: '%s'", legalPersonIdentifier));
        }
    }

    private Optional<TaraSession.LegalPerson> getLegalperson(String legalPersonIdentifier, List<TaraSession.LegalPerson> legalPersons) {
        return legalPersons.stream().filter(e -> e.getLegalPersonIdentifier().equals(legalPersonIdentifier)).findFirst();
    }

    private boolean isLegalpersonScopeAllowed(TaraSession taraSession) {
        return List.of(taraSession.getLoginRequestInfo().getClient().getScope().split(" ")).contains(LEGALPERSON.getFormalName());
    }

    private boolean isLegalpersonScopeRequested(TaraSession taraSession) {
        return taraSession.getLoginRequestInfo().getRequestedScopes().contains(LEGALPERSON.getFormalName());
    }
}
