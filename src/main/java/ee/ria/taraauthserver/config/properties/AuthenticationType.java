package ee.ria.taraauthserver.config.properties;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;
import java.util.stream.Collectors;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;

@Getter
@AllArgsConstructor
public enum AuthenticationType {
    WEBAUTHN("webauthn", "webauthn", TaraScope.WEBAUTHN),
    ID_CARD("idcard", "id-card", TaraScope.IDCARD),
    MOBILE_ID("mID", "mobile-id", TaraScope.MID),
    SMART_ID("smartid", "smart-id", TaraScope.SMARTID),
    EIDAS("eidas", "eidas", TaraScope.EIDAS),
    MOJEID("mojeid", "mojeid", TaraScope.EIDAS),
    EPARAKSTS_MOBILE("eparaksts-mobile", "eparaksts-mobile", TaraScope.EIDAS),
    EPARAKSTS_CARD("eparaksts-card", "eparaksts-card", TaraScope.EIDAS),
    FREJA_ID("freja-eid", "freja-eid", TaraScope.EIDAS);

    private final String amrName;
    private final String propertyName;
    private final TaraScope scope;

    public static List<String> getFormalNames() {
        return stream(AuthenticationType.values())
                .map(a -> a.getScope().getFormalName())
                .collect(Collectors.toList());
    }

    private static final Map<String, AuthenticationType> amrNameMap;

    static {
        amrNameMap = new HashMap<>();

        for (AuthenticationType at : AuthenticationType.values()) {
            amrNameMap.put(at.amrName, at);
        }
    }

    public static AuthenticationType findByAmrName(String amrName) {
        return amrNameMap.get(amrName);
    }
}
