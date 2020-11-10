package ee.ria.taraauthserver.controllers;

import ee.ria.taraauthserver.error.BadRequestException;
import ee.ria.taraauthserver.error.NotFoundException;
import ee.ria.taraauthserver.session.AuthSession;
import ee.ria.taraauthserver.session.AuthState;
import ee.ria.taraauthserver.utils.SessionUtils;
import ee.ria.taraauthserver.xroad.EBusinessRegistryService;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
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
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.time.ZoneId;
import java.util.Collections;
import java.util.List;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
@ConditionalOnProperty(value = "tara.legal-person-authentication.enabled", matchIfMissing = true)
public class LegalpersonController {

    @Autowired
    private final EBusinessRegistryService eBusinessRegistryService;

    @GetMapping(value="/auth/legal_person/init")
    public String initLegalPerson(Model model) {
        AuthSession authSession = SessionUtils.getAuthSession();
        if (authSession == null ) {
            throw new BadRequestException("Session was not found! Either the user session has expired, server has been restarted in the middle of user transaction or corrupt/invalid cookie value was sent from the browser");
        }

        if (authSession.getState() != AuthState.NATURAL_PERSON_AUTHENTICATION_COMPLETED) {
            throw new BadRequestException("Invalid authentication state: " + authSession.getState() + ", expected: " + AuthState.NATURAL_PERSON_AUTHENTICATION_COMPLETED);
        }

        model.addAttribute("idCode", authSession.getAuthenticationResult().getIdCode());
        model.addAttribute("firstName", authSession.getAuthenticationResult().getFirstName());
        model.addAttribute("lastName", authSession.getAuthenticationResult().getLastName());
        model.addAttribute("dateOfBirth", authSession.getAuthenticationResult().getDateOfBirth());

        authSession.setState(AuthState.LEGAL_PERSON_AUTHENTICATION_INIT);

        return "legalPersonView";
    }

    @GetMapping(value="/auth/legal_person", produces = {MediaType.APPLICATION_JSON_VALUE})
    public ModelAndView fetchLegalPersonsList(HttpServletRequest request, HttpSession httpSession) {
        AuthSession authSession = SessionUtils.getAuthSession();
        if (authSession == null ) {
            throw new BadRequestException("Session was not found! Either the user session has expired, server has been restarted in the middle of user transaction or corrupt/invalid cookie value was sent from the browser");
        }

        if (authSession.getState() != AuthState.LEGAL_PERSON_AUTHENTICATION_INIT) {
            throw new BadRequestException("Invalid authentication state: " + authSession.getState() + ", expected: " + AuthState.LEGAL_PERSON_AUTHENTICATION_INIT);
        }

        Assert.notNull(authSession.getAuthenticationResult(), "Authentication credentials missing from session!");

        List<EELegalPerson> legalPersons = eBusinessRegistryService.executeEsindusV2Service(authSession.getAuthenticationResult().getIdCode());

        if (CollectionUtils.isEmpty(legalPersons)) {
            throw new NotFoundException("Current user has no valid legal person records in business registry");
        } else {
            request.getSession().setAttribute("legalPersons", legalPersons);
            return new ModelAndView(new MappingJackson2JsonView(), Collections.singletonMap("legalPersons", legalPersons));
        }
    }

    @PutMapping("/auth/legalperson/confirm")
    public ModelAndView confirmLegalPersonSelection(@RequestParam(name = "legal_person_identifier") String legalPersonIdentifier) {

        // TODO check state
        // TODO check id

        // TODO set state AUTHENTICATION_SUCCESS

        return new ModelAndView(new MappingJackson2JsonView(), Collections.singletonMap("selection_confirmed", true));
    }

    @ToString
    @EqualsAndHashCode
    @RequiredArgsConstructor
    @Getter
    public static class EELegalPerson implements Serializable {
        private final String legalName;
        private final String legalPersonIdentifier;
    }
}
