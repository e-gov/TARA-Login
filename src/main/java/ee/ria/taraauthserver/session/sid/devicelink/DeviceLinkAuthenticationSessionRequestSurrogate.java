package ee.ria.taraauthserver.session.sid.devicelink;

import ee.sk.smartid.SignatureProtocol;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DeviceLinkAuthenticationSessionRequestSurrogate implements Serializable {
    private String relyingPartyUUID;
    private String relyingPartyName;
    private String certificateLevel;
    private SignatureProtocol signatureProtocol;
    private AcspV2SignatureProtocolParametersSurrogate signatureProtocolParameters;
    private String interactions;
    private RequestPropertiesSurrogate requestProperties;
    private Set<String> capabilities;
    private String initialCallbackUrl;
}
