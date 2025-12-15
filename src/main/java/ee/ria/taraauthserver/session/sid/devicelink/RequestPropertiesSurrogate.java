package ee.ria.taraauthserver.session.sid.devicelink;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RequestPropertiesSurrogate implements Serializable {
    private Boolean shareMdClientIpAddress;
}
