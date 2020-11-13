package ee.ria.taraauthserver.error;

public class BadRequestException extends TaraException {

    public BadRequestException(String debugMessage) {
        super(null, debugMessage);
    }

    public BadRequestException(ErrorMessages messageCode, String debugMessage) {
        super(messageCode, debugMessage, null);
    }
}
