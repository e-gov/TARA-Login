package ee.ria.taraauthserver.session;

import lombok.Data;
import lombok.experimental.Delegate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.session.MapSession;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Component;

import javax.cache.Cache;
import java.io.Serializable;
import java.time.Duration;

import static ee.ria.taraauthserver.session.TaraSession.TARA_SESSION;
import static javax.management.Query.value;
import static net.logstash.logback.marker.Markers.append;

/**
 * @see ee.ria.taraauthserver.config.SessionConfiguration
 */
@Slf4j
@Component
public class IgniteSessionRepository implements SessionRepository<Session> {
    public static final String DEFAULT_SESSION_MAP_NAME = "spring:session:sessions";

    @Autowired
    private Cache<String, Session> sessionCache;

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
            if(log.isDebugEnabled()) {
                log.debug(append(TARA_SESSION, session.getAttribute(TARA_SESSION)), "Save session: {}", session.getId());
            }
            sessionCache.put(session.getId(), session);
        }
    }

    @Override
    public Session findById(String id) {
        Session session = sessionCache.get(id);
        if (session != null && session.isExpired()) {
            deleteById(id);
            return null;
        } else {
            return session;
        }
    }

    @Override
    public void deleteById(String id) {
        sessionCache.remove(id);
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
