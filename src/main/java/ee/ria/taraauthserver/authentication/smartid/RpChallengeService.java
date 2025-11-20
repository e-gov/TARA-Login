package ee.ria.taraauthserver.authentication.smartid;

import ee.sk.smartid.RpChallenge;
import ee.sk.smartid.RpChallengeGenerator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(value = "tara.auth-methods.smart-id.enabled")
public class RpChallengeService {

    public RpChallenge getRpChallenge() {
        return RpChallengeGenerator.generate();
    }
}
