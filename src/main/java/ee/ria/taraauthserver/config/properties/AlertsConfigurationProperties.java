package ee.ria.taraauthserver.config.properties;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.time.LocalDate;
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

    private int alertsCacheDurationInSeconds = 3600;

    @Data
    @RequiredArgsConstructor
    public static class Alert implements Serializable {
        @JsonProperty("start_time")
        LocalDate startTime;
        @JsonProperty("end_time")
        LocalDate endTime;
        @JsonProperty("login_page_notification_settings")
        LoginPageNotificationSettings loginPageNotificationSettings;
    }

    @Data
    public static class LoginPageNotificationSettings {
        @JsonProperty("notify_clients_on_tara_login_page")
        boolean notifyClientsOnTaraLoginPage;
        @JsonProperty("notification_text")
        String notificationText;
        @JsonProperty("display_only_for_authmethods")
        List<String> authMethods;
    }

}
