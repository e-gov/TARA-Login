package ee.ria.taraauthserver.authentication.idcard;

import eu.webeid.security.challenge.ChallengeNonce;
import eu.webeid.security.challenge.ChallengeNonceStore;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;

@ConditionalOnProperty(value = "tara.auth-methods.id-card.enabled")
@Service
@RequiredArgsConstructor
public class SessionBackedChallengeNonceStore implements ChallengeNonceStore {

    private static final String CHALLENGE_NONCE_KEY = "nonce";

    @NonNull
    final ObjectFactory<HttpSession> httpSessionFactory;

    @Override
    public void put(ChallengeNonce challengeNonce) {
        currentSession().setAttribute(CHALLENGE_NONCE_KEY, challengeNonce);
    }

    @Override
    public ChallengeNonce getAndRemoveImpl() {
        final ChallengeNonce challengeNonce = (ChallengeNonce) currentSession().getAttribute(CHALLENGE_NONCE_KEY);
        currentSession().removeAttribute(CHALLENGE_NONCE_KEY);
        return challengeNonce;
    }

    private HttpSession currentSession() {
        return httpSessionFactory.getObject();
    }

}
