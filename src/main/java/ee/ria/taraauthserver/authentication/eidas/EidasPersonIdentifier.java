package ee.ria.taraauthserver.authentication.eidas;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class EidasPersonIdentifier {

    public static final Pattern PERSON_IDENTIFIER_PATTERN = Pattern.compile("^([A-Z]{2})/([A-Z]{2})/(.+)$");

    private final String countryCode;
    private final String destinationCountryCode;
    private final String idCode;

    public static EidasPersonIdentifier parse(String samlAttributeValue) {
        Matcher matcher = PERSON_IDENTIFIER_PATTERN.matcher(samlAttributeValue);
        if (matcher.matches()) {
            return new EidasPersonIdentifier(
                    matcher.group(1),
                    matcher.group(2),
                    matcher.group(3));
        } else {
            throw new IllegalArgumentException("The person identifier has invalid format! <" + samlAttributeValue + ">");
        }
    }

}
