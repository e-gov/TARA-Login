package ee.ria.taraauthserver.authentication.legalperson;

import ee.ria.taraauthserver.authentication.legalperson.xroad.BusinessRegistryService;
import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.NotFoundException;
import ee.ria.taraauthserver.session.SessionUtils;
import ee.ria.taraauthserver.session.TaraSession;
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
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.ModelAndView;

import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static ee.ria.taraauthserver.config.properties.TaraScope.LEGALPERSON;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_LEGAL_PERSON;
import static ee.ria.taraauthserver.error.ErrorCode.INVALID_REQUEST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.GET_LEGAL_PERSON_LIST;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.LEGAL_PERSON_AUTHENTICATION_INIT;
import static ee.ria.taraauthserver.session.TaraAuthenticationState.NATURAL_PERSON_AUTHENTICATION_COMPLETED;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static java.lang.String.format;
import static java.util.Map.of;
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

    @GetMapping(value = "/auth/legalperson/init")
    public ModelAndView initLegalPerson(Model model, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, NATURAL_PERSON_AUTHENTICATION_COMPLETED);

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

        return new ModelAndView("legalPersonView");
    }


    @GetMapping(value = "/auth/legalperson", produces = {MediaType.APPLICATION_JSON_VALUE})
    @ResponseBody
    public Map<String, List<TaraSession.LegalPerson>> fetchLegalPersonsList(@SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, LEGAL_PERSON_AUTHENTICATION_INIT);
        notNull(taraSession.getAuthenticationResult(), "Authentication credentials missing from session!");
        List<TaraSession.LegalPerson> legalPersons = eBusinessRegistryService.executeEsindusV2Service(taraSession.getAuthenticationResult().getIdCode());

        if (isEmpty(legalPersons)) {
            throw new NotFoundException("Current user has no valid legal person records in business registry");
        } else {
            taraSession.setLegalPersonList(legalPersons);
            taraSession.setState(GET_LEGAL_PERSON_LIST);
            return of("legalPersons", legalPersons);
        }
    }

    @PostMapping("/auth/legalperson/confirm")
    public String confirmLegalPerson(
            @RequestParam(name = "legal_person_identifier")
            @Size(max = 50)
            @Pattern(regexp = "[a-zA-Z0-9-_]{1,}", message = "invalid legal person identifier")
                    String legalPersonIdentifier, @SessionAttribute(value = TARA_SESSION, required = false) TaraSession taraSession) {
        SessionUtils.assertSessionInState(taraSession, GET_LEGAL_PERSON_LIST);
        List<TaraSession.LegalPerson> legalPersons = taraSession.getLegalPersonList();
        notNull(legalPersons, "Invalid state. Legal person list was not found!");
        isTrue(!legalPersons.isEmpty(), "Invalid state. No list of authorized legal persons was found!");

        Optional<TaraSession.LegalPerson> selectedLegalPerson = getLegalperson(legalPersonIdentifier, legalPersons);
        if (selectedLegalPerson.isPresent()) {
            log.info("Legal person confirmed");
            taraSession.setSelectedLegalPerson(selectedLegalPerson.get());
            taraSession.setState(LEGAL_PERSON_AUTHENTICATION_COMPLETED);
            return "forward:/auth/accept";
        } else {
            throw new BadRequestException(INVALID_LEGAL_PERSON, format("Attempted to select invalid legal person with id: '%s'", legalPersonIdentifier));
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
