package ee.ria.taraauthserver.error.exceptions;


import ee.ria.taraauthserver.session.TaraSession;
import lombok.Getter;

@Getter
public class InvalidLoginRequestException extends RuntimeException {

    private final TaraSession.LoginRequestInfo loginRequestInfo;

    public InvalidLoginRequestException(String message, TaraSession.LoginRequestInfo loginRequestInfo) {
        super(message);
        this.loginRequestInfo = loginRequestInfo;
    }

}
