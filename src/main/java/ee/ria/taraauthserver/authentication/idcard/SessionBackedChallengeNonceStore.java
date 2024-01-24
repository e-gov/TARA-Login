package ee.ria.taraauthserver.authentication.idcard;

import ee.ria.taraauthserver.session.TaraSession;
import eu.webeid.security.challenge.ChallengeNonce;
import eu.webeid.security.challenge.ChallengeNonceStore;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
@Service
@RequiredArgsConstructor
public class SessionBackedChallengeNonceStore implements ChallengeNonceStore {
    private final ObjectFactory<HttpSession> httpSessionFactory;

    @Override
    public void put(ChallengeNonce challengeNonce) {
        currentSession().setWebEidChallengeNonce(challengeNonce);
    }

    @Override
    public ChallengeNonce getAndRemoveImpl() {
        TaraSession taraSession = currentSession();
        final ChallengeNonce challengeNonce = taraSession.getWebEidChallengeNonce();
        taraSession.setWebEidChallengeNonce(null);
        return challengeNonce;
    }

    private TaraSession currentSession() {
        return (TaraSession) httpSessionFactory.getObject().getAttribute(TaraSession.TARA_SESSION);
    }

}
