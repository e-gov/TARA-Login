package ee.ria.taraauthserver.config.properties;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
@Validated
@ConfigurationProperties(prefix = "tara.alerts")
public class AlertsConfigurationProperties {

    @NotNull
    private String hostUrl;

    private int connectionTimeoutMilliseconds = 3000;

    private int readTimeoutMilliseconds = 3000;

    private int refreshAlertsIntervalInMilliseconds;

    private int alertsCacheDurationInSeconds = 86400;

    private StaticAlert staticAlert;

    @Data
    public static class StaticAlert {
        private List<MessageTemplate> messageTemplates = new ArrayList<>();
    }

    @Builder
    @Data
    public static class Alert implements Serializable {
        @JsonProperty("start_time")
        private OffsetDateTime startTime;
        @JsonProperty("end_time")
        private OffsetDateTime endTime;
        @JsonProperty("login_alert")
        private LoginAlert loginAlert;
        @JsonIgnore
        private String defaultMessage;
        @JsonIgnore
        private boolean loadedFromConf;

        public void setLoginAlert(LoginAlert loginAlert) {
            this.loginAlert = loginAlert;
            this.defaultMessage = getAlertMessage("et");
        }

        public boolean isActive() {
            return getLoginAlert().isEnabled()
                    && getStartTime().isBefore(OffsetDateTime.now())
                    && getEndTime().isAfter(OffsetDateTime.now());
        }

        public boolean isValidFor(AuthenticationType authenticationType) {
            String scope = authenticationType.getScope().getFormalName();
            return loginAlert
                    .getAuthMethods()
                    .stream()
                    .anyMatch(m -> m.equals(scope));
        }

        public String getAlertMessage(String locale) {
            return loginAlert.getMessageTemplates().stream()
                    .filter(m -> m.getLocale().equals(locale))
                    .map(MessageTemplate::getMessage)
                    .findFirst()
                    .orElse(defaultMessage);
        }
    }

    @Builder
    @Data
    public static class LoginAlert {
        @Getter
        @JsonProperty("enabled")
        private boolean enabled;
        @JsonProperty("message_templates")
        private List<MessageTemplate> messageTemplates;
        @JsonProperty("auth_methods")
        private List<String> authMethods;
    }

    @Data
    @NoArgsConstructor
    public static class MessageTemplate {
        @JsonProperty("message")
        private String message;
        @JsonProperty("locale")
        private String locale;
    }
}
