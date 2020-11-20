package ee.ria.taraauthserver.config.properties;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum AuthenticationType {
    IDCard("idcard", "id-card", TaraScope.IDCARD),
    MobileID("mID", "mobile-id", TaraScope.MID);

    private final String amrName;
    private final String propertyName;
    private final TaraScope scope;
}
