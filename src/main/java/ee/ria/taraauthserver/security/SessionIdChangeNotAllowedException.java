package ee.ria.taraauthserver.security;

public class SessionIdChangeNotAllowedException extends RuntimeException {

    public SessionIdChangeNotAllowedException() {
        super("Session ID change not allowed");
    }
}
