package ee.ria.taraauthserver.health;

import org.apache.ignite.Ignite;
import org.apache.ignite.binary.BinaryObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;
import org.springframework.stereotype.Component;

import javax.cache.Cache;

@Component
public class IgniteHealthIndicator extends AbstractHealthIndicator {

    @Autowired
    private Ignite ignite;

    @Autowired
    @Qualifier("sessionCache")
    private Cache<String, BinaryObject> sessionCache;

    public IgniteHealthIndicator() {
        super("Authentication service health check failed");
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {

        if (ignite.cluster().state().active()) {
            builder.up();
        } else {
            builder.down();
        }
    }
}