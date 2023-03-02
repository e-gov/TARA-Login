package ee.ria.taraauthserver.security;

public class SessionCreationNotAllowedException extends RuntimeException {

    public SessionCreationNotAllowedException() {
        super("Session creation not allowed");
    }
}
