package ee.ria.taraauthserver.session;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.session.MapSession;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Component;

import javax.cache.Cache;
import java.time.Duration;

@Slf4j
@Component
public class IgniteSessionRepository implements SessionRepository<Session> {
    public static final String DEFAULT_SESSION_MAP_NAME = "spring:session:sessions";

    @Autowired
    private Cache<String, Session> sessionCache;

    @Value("${spring.session.timeout}")
    private Duration sessionTimeout;

    @Override
    public MapSession createSession() {
        MapSession mapSession = new MapSession();
        mapSession.setMaxInactiveInterval(sessionTimeout);
        return mapSession;
    }

    @Override
    public void save(Session session) {
        sessionCache.put(session.getId(), session);
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
}
