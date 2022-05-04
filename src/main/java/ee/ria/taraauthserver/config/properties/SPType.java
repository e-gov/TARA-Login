package ee.ria.taraauthserver.config.properties;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum SPType {
    @JsonProperty("private")
    PRIVATE("private"),
    @JsonProperty("public")
    PUBLIC("public");

    private String value;

    SPType(String value) {
        this.value = value;
    }

    public String toString() {
        return value;
    }
}
