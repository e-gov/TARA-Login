package ee.ria.taraauthserver.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.apache.ignite.cache.CacheMode;
import org.apache.ignite.cache.CacheWriteSynchronizationMode;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import static org.apache.ignite.cache.CacheMode.PARTITIONED;
import static org.apache.ignite.cache.CacheWriteSynchronizationMode.PRIMARY_SYNC;

@Data
@Validated
@ConfigurationProperties(prefix = "tara.ignite")
public class IgniteCacheProperties {

    @Valid
    @NotNull
    private CacheProperties sessionCache = new CacheProperties();

    @Valid
    @NotNull
    private CacheProperties eidasRelayStateCache = new CacheProperties();

    @Valid
    @NotNull
    private CacheProperties alertsCache = new CacheProperties();

    @Data
    public static class CacheProperties {

        @NotNull
        private CacheMode cacheMode = PARTITIONED;

        @Min(0)
        @Max(3)
        private int backups = 0;

        @NotNull
        private CacheWriteSynchronizationMode writeSynchronizationMode = PRIMARY_SYNC;

        private boolean readFromBackup = true;
    }
}
