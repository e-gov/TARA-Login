package ee.ria.taraauthserver.session;

import lombok.Data;
import lombok.experimental.Delegate;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.LogstashMarker;
import org.apache.ignite.Ignite;
import org.apache.ignite.binary.BinaryObject;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.session.MapSession;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Component;

import javax.cache.Cache;
import java.io.Serializable;
import java.time.Duration;

import static ee.ria.taraauthserver.session.TaraAuthenticationState.*;
import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static net.logstash.logback.marker.Markers.append;
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * @see ee.ria.taraauthserver.config.SessionConfiguration
 */
@Slf4j
@Component
public class IgniteSessionRepository implements SessionRepository<Session> {
    private static final Logger statisticsLog = getLogger("statistics");

    @Autowired
    @Qualifier("sessionCache")
    private Cache<String, BinaryObject> sessionCache;

    @Autowired
    private Ignite ignite;

    @Value("${spring.session.timeout}")
    private Duration sessionTimeout;

    @Override
    public IgniteSession createSession() {
        IgniteSession igniteSession = new IgniteSession();
        igniteSession.setMaxInactiveInterval(sessionTimeout);
        return igniteSession;
    }

    @Override
    public void save(Session session) {
        IgniteSession igniteSession = (IgniteSession) session;
        if (igniteSession.isChanged()) {
            igniteSession.setChanged(false);
            auditLog(session);
            BinaryObject binaryObject = ignite.binary().toBinary(session);
            sessionCache.put(session.getId(), binaryObject);
        }
    }

    private void auditLog(Session session) {
        TaraSession taraSession = session.getAttribute(TARA_SESSION);
        if (taraSession != null) {
            LogstashMarker marker = append(TARA_SESSION, taraSession);
            if (AUTHENTICATION_SUCCESS == taraSession.getState() || AUTHENTICATION_FAILED == taraSession.getState() ||
                    AUTHENTICATION_CANCELED == taraSession.getState()) {
                statisticsLog.info(marker, "Authentication result: {}", taraSession.getState());
            }
            log.info(marker, "Saving session with state: {}", defaultIfNull(taraSession.getState(), "NOT_SET"));
        }
    }

    @Override
    public Session findById(String id) {
        BinaryObject binaryObject = sessionCache.get(id);
        if (binaryObject != null) {
            Session session = binaryObject.deserialize();
            if (session.isExpired()) {
                deleteById(id);
                return null;
            } else {
                return session;
            }
        } else {
            return null;
        }
    }

    @Override
    public void deleteById(String id) {
        sessionCache.remove(id);
        log.info("Session is removed from cache: {}", id);
    }

    @Data
    static final class IgniteSession implements Session, Serializable {
        private static final long serialVersionUID = 7160779239673823561L;
        private boolean changed;

        @Delegate(excludes = SetAttribute.class)
        private final MapSession mapSession = new MapSession();

        public void setAttribute(String attributeName, Object attributeValue) {
            setChanged(true);
            mapSession.setAttribute(attributeName, attributeValue);
        }

        interface SetAttribute {
            void setAttribute(String attributeName, Object attributeValue);
        }
    }
}
