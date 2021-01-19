package ee.ria.taraauthserver.error;

import ee.ria.taraauthserver.error.exceptions.BadRequestException;
import ee.ria.taraauthserver.error.exceptions.NotFoundException;
import ee.ria.taraauthserver.error.exceptions.ServiceNotAvailableException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolationException;
import java.io.IOException;

@Slf4j
@ControllerAdvice
public class ErrorHandler {

    @ExceptionHandler({BadRequestException.class, BindException.class, ConstraintViolationException.class, MissingServletRequestParameterException.class})
    public ModelAndView handleBindException(Exception ex, HttpServletResponse response) throws IOException {
        log.error("User exception: {}", ex.getMessage(), ex);
        response.setContentType("application/json;charset=UTF-8");
        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        return new ModelAndView();
    }

    @ExceptionHandler({HttpClientErrorException.class})
    public ModelAndView handleHttpClientErrorException(HttpClientErrorException ex, HttpServletResponse response) throws IOException {
        log.error("HTTP client exception: {}", ex.getMessage(), ex);
        response.setContentType("application/json;charset=UTF-8");
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return new ModelAndView();
    }

    @ExceptionHandler({ServiceNotAvailableException.class})
    public ModelAndView handleDownstreamServiceErrors(Exception ex, HttpServletResponse response) throws IOException {
        log.error("Service not available: {}", ex.getMessage(), ex);
        response.setContentType("application/json;charset=UTF-8");
        response.sendError(HttpServletResponse.SC_BAD_GATEWAY);
        return new ModelAndView();
    }

    @ExceptionHandler({NotFoundException.class})
    public ModelAndView handleNotFound(Exception ex, HttpServletResponse response) throws IOException {
        log.error("Results not found: {}", ex.getMessage(), ex);
        response.setContentType("application/json;charset=UTF-8");
        response.sendError(HttpServletResponse.SC_NOT_FOUND);
        return new ModelAndView();
    }

    @ExceptionHandler({Exception.class})
    public ModelAndView handleAll(Exception ex, HttpServletResponse response) throws IOException {
        log.error("Server encountered an unexpected error: {}", ex.getMessage(), ex);
        response.setContentType("application/json;charset=UTF-8");
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return new ModelAndView();
    }
}
