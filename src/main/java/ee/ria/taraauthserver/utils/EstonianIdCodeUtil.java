package ee.ria.taraauthserver.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class EstonianIdCodeUtil {

    public static final String ESTONIAN_ID_CODE_REGEX = "[1-6][0-9]{2}((0[1-9])|(1[0-2]))((0[1-9])|([1-2][0-9])|(3[0-1]))[0-9]{4}";
    public static final String GENERIC_ESTONIAN_ID_CODE_REGEX = "(|EE|PNOEE-)(" + ESTONIAN_ID_CODE_REGEX + ")";

    public static String getEstonianIdCode(String idCode) {
        final Matcher matcher = Pattern.compile(GENERIC_ESTONIAN_ID_CODE_REGEX).matcher(idCode);

        if (matcher.matches()) {
            return matcher.group(2);
        } else {
            throw new IllegalArgumentException("Invalid Estonian identity code");
        }
    }

    private EstonianIdCodeUtil() {
    }

}
