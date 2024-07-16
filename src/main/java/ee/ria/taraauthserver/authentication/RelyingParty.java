package ee.ria.taraauthserver.authentication;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Getter
@ToString
@EqualsAndHashCode
public class RelyingParty {

    @NonNull
    private final String name;

    @NonNull
    private final String uuid;

    public static Optional<RelyingParty> of(String name, String uuid) {
        if (name == null && uuid == null) {
            return Optional.empty();
        }
        if (name == null || uuid == null) {
            log.error("Failed to construct RelyingParty with incomplete arguments");
            return Optional.empty();
        }
        return Optional.of(new RelyingParty(name, uuid));
    }

}
