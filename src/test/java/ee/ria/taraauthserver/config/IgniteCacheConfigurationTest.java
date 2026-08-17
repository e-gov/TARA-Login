package ee.ria.taraauthserver.config;

import ee.ria.taraauthserver.BaseTest;
import org.apache.ignite.Ignite;
import org.apache.ignite.configuration.CacheConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static ee.ria.taraauthserver.config.IgniteCacheConfiguration.ALERTS_CACHE_NAME;
import static ee.ria.taraauthserver.config.IgniteCacheConfiguration.EIDAS_RELAY_STATE_CACHE_NAME;
import static ee.ria.taraauthserver.config.IgniteCacheConfiguration.SESSION_CACHE_NAME;
import static org.apache.ignite.cache.CacheMode.PARTITIONED;
import static org.apache.ignite.cache.CacheWriteSynchronizationMode.PRIMARY_SYNC;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IgniteCacheConfigurationTest extends BaseTest {

    @Autowired
    private Ignite ignite;

    @Test
    void whenNoIgniteCachePropertiesConfiguredThenCachesUseDefaultDurability() {
        assertDefaultDurability(SESSION_CACHE_NAME);
        assertDefaultDurability(EIDAS_RELAY_STATE_CACHE_NAME);
        assertDefaultDurability(ALERTS_CACHE_NAME);
    }

    private void assertDefaultDurability(String cacheName) {
        CacheConfiguration<?, ?> configuration = ignite.cache(cacheName).getConfiguration(CacheConfiguration.class);
        assertEquals(PARTITIONED, configuration.getCacheMode());
        assertEquals(0, configuration.getBackups());
        assertEquals(PRIMARY_SYNC, configuration.getWriteSynchronizationMode());
        assertTrue(configuration.isReadFromBackup());
    }
}
