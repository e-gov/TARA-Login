package ee.ria.taraauthserver.config.properties;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

import static java.util.List.of;

@Getter
@AllArgsConstructor
public enum TaraScope {
    OPENID("openid"),
    IDCARD("idcard"),
    MID("mid"),
    SMARTID("smartid"),
    LEGALPERSON("legalperson");

    public static final List<TaraScope> SUPPORTS_AUTHENTICATION_METHOD_SELECTION = of(IDCARD, MID, SMARTID);

    private final String formalName;

    public static TaraScope getScope(String value) {
        for (TaraScope v : values())
            if (v.formalName.equals(value))
                return v;
        return null;
    }
}
