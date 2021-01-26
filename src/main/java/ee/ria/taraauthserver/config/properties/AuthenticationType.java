package ee.ria.taraauthserver.config.properties;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum AuthenticationType {
    ID_CARD("idcard", "id-card", TaraScope.IDCARD),
    MOBILE_ID("mID", "mobile-id", TaraScope.MID),
    SMART_ID("sid", "smart-id", TaraScope.SID);

    private final String amrName;
    private final String propertyName;
    private final TaraScope scope;
}
