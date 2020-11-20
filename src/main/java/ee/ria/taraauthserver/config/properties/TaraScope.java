package ee.ria.taraauthserver.config.properties;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Getter
@AllArgsConstructor
public enum TaraScope {

    OPENID("openid"),
    IDCARD("idcard"),
    MID("mid"),
    LEGALPERSON("legalperson");

    public static final List<TaraScope> SUPPORTS_AUTHENTICATION_METHOD_SELECTION = Collections.unmodifiableList(Arrays.asList(IDCARD, MID));

    private String formalName;

    public static TaraScope getScope(String value) {
        for (TaraScope v : values())
            if (v.formalName.equals(value))
                return v;

        throw new IllegalArgumentException();
    }
}
