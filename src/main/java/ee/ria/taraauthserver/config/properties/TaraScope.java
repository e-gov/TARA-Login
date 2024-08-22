package ee.ria.taraauthserver.config.properties;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum TaraScope {
    OPENID("openid"),
    IDCARD("idcard"),
    MID("mid"),
    SMARTID("smartid"),
    EIDAS("eidas"),
    EIDASONLY("eidasonly"),
    PHONE("phone"),
    EMAIL("email"),
    LEGALPERSON("legalperson");

    private final String formalName;

    public static TaraScope getScope(String value) {
        for (TaraScope v : values())
            if (v.formalName.equals(value))
                return v;
        return null;
    }
}
