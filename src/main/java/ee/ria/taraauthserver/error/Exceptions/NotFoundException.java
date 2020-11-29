package ee.ria.taraauthserver.error.Exceptions;

public class NotFoundException extends RuntimeException {

    public NotFoundException(String message) {
        super(message);
    }

    public NotFoundException(String message, Exception e) {
        super(message, e);
    }

}
