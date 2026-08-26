package ee.ria.taraauthserver.authentication.eudi;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The wallet's answer from the Digital Credentials API, forwarded to eudiplo.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record WalletResponse(
        @JsonProperty("response") String response,
        @JsonProperty("error") String error) {

    @Override
    public String toString() {
        return "WalletResponse[response=%s, error=%s]".formatted(response == null ? null : "<redacted>", error);
    }
}
