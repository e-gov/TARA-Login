package ee.ria.taraauthserver.error;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolationException;
import java.io.IOException;
import java.util.Collections;

@Slf4j
@ControllerAdvice
public
class ErrorHandler {

    @ExceptionHandler({BadRequestException.class, ConstraintViolationException.class, MissingServletRequestParameterException.class})
    public ModelAndView handleBadRequestException(Exception ex, HttpServletResponse response) throws IOException {
        log.error("User exception: {}", ex.getMessage(), ex);
        if (isValidMessage(ex.getMessage()))
            return new ModelAndView("error", Collections.singletonMap("TARA_ERROR_MESSAGE", ex.getMessage()), HttpStatus.BAD_REQUEST);
        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        return new ModelAndView();
    }

    @ExceptionHandler({BindException.class})
    public ModelAndView handleBindException(BindException ex, HttpServletResponse response) throws IOException {
        log.error("User exception: {}", ex.getMessage(), ex);
        BindingResult result = ex.getBindingResult();
        if (result.hasFieldErrors())
            if (isValidMessage(result.getFieldError().getDefaultMessage()))
                return new ModelAndView("error", Collections.singletonMap("TARA_ERROR_MESSAGE", result.getFieldError().getDefaultMessage()), HttpStatus.BAD_REQUEST);
        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        return new ModelAndView();
    }

    @ExceptionHandler({HttpClientErrorException.class})
    public ModelAndView handleHttpClientErrorException(HttpClientErrorException ex, HttpServletResponse response) throws IOException {
        log.error("HTTP client exception: {}", ex.getMessage(), ex);
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return new ModelAndView();
    }

    @ExceptionHandler({Exception.class})
    public ModelAndView handleAll(Exception ex, HttpServletResponse response) throws Exception {
        log.error("Server encountered an unexpected error: {}", ex.getMessage(), ex);
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return new ModelAndView();
    }

    private boolean isValidMessage(String message) {
        for (ErrorMessages errorMessage : ErrorMessages.values())
            if (errorMessage.getMessage().equals(message))
                return true;
        return false;
    }
}
