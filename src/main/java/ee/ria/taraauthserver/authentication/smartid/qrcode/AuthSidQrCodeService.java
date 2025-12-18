package ee.ria.taraauthserver.authentication.smartid.qrcode;

import ee.ria.taraauthserver.session.TaraSession;
import ee.ria.taraauthserver.session.update.CancelSmartIdQrCodeAuthenticationSessionUpdate;
import ee.ria.taraauthserver.session.update.InitSmartIdQrCodeAuthenticationSessionUpdate;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;

@Slf4j
@Service
@ConditionalOnProperty(
        value = {
                "tara.auth-methods.smart-id.enabled",
                "tara.auth-methods.smart-id.qr-code.enabled"
        },
        havingValue = "true"
)
@RequiredArgsConstructor
public class AuthSidQrCodeService {

    private final SessionRepository<Session> sessionRepository;

    public void startAuthentication(@NonNull TaraSession session) {
        session.accept(new InitSmartIdQrCodeAuthenticationSessionUpdate());
        updateSession(session);
    }

    public void cancelAuthentication(@NonNull TaraSession session) {
        session.accept(new CancelSmartIdQrCodeAuthenticationSessionUpdate());
        updateSession(session);
    }

    private void updateSession(TaraSession taraSession) {
        Session session = sessionRepository.findById(taraSession.getSessionId());
        if (session == null) {
            throw new IllegalStateException("Session \"%s\" not found".formatted(taraSession.getSessionId()));
        }
        session.setAttribute(TARA_SESSION, taraSession);
        sessionRepository.save(session);
    }

}
