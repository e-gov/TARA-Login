package ee.ria.taraauthserver.session.sid.devicelink;

import ee.sk.smartid.rest.dao.AcspV2SignatureProtocolParameters;
import ee.sk.smartid.rest.dao.DeviceLinkAuthenticationSessionRequest;
import ee.sk.smartid.rest.dao.RequestProperties;
import ee.sk.smartid.rest.dao.SignatureAlgorithmParameters;
import lombok.experimental.UtilityClass;

// Converts record DeviceLinkAuthenticationSessionRequest into class
// DeviceLinkAuthenticationSessionRequestSurrogate, so that Spring Boot
// is able to store it in Ignite session data.
@UtilityClass
public class DeviceLinkAuthenticationSessionMapper {

    // Methods for converting records to surrogate objects:

    public static DeviceLinkAuthenticationSessionRequestSurrogate toSurrogate(
            DeviceLinkAuthenticationSessionRequest rec) {
        if (rec == null) {
            return null;
        }
        return new DeviceLinkAuthenticationSessionRequestSurrogate(
                rec.relyingPartyUUID(),
                rec.relyingPartyName(),
                rec.certificateLevel(),
                rec.signatureProtocol(),
                toSurrogate(rec.signatureProtocolParameters()),
                rec.interactions(),
                toSurrogate(rec.requestProperties()),
                rec.capabilities(),
                rec.initialCallbackUrl()
        );
    }

    private static AcspV2SignatureProtocolParametersSurrogate toSurrogate(
            AcspV2SignatureProtocolParameters rec) {
        if (rec == null) {
            return null;
        }
        return new AcspV2SignatureProtocolParametersSurrogate(
                rec.rpChallenge(),
                rec.signatureAlgorithm(),
                toSurrogate(rec.signatureAlgorithmParameters())
        );
    }

    private static SignatureAlgorithmParametersSurrogate toSurrogate(SignatureAlgorithmParameters rec) {
        if (rec == null) {
            return null;
        }
        return new SignatureAlgorithmParametersSurrogate(rec.hashAlgorithm());
    }

    private static RequestPropertiesSurrogate toSurrogate(RequestProperties rec) {
        if (rec == null) {
            return null;
        }
        return new RequestPropertiesSurrogate(rec.shareMdClientIpAddress());
    }

    // Methods for converting surrogate objects to records:

    public static DeviceLinkAuthenticationSessionRequest toRecord(
            DeviceLinkAuthenticationSessionRequestSurrogate surrogate) {
        if (surrogate == null) {
            return null;
        }
        return new DeviceLinkAuthenticationSessionRequest(
                surrogate.getRelyingPartyUUID(),
                surrogate.getRelyingPartyName(),
                surrogate.getCertificateLevel(),
                surrogate.getSignatureProtocol(),
                toRecord(surrogate.getSignatureProtocolParameters()),
                surrogate.getInteractions(),
                toRecord(surrogate.getRequestProperties()),
                surrogate.getCapabilities(),
                surrogate.getInitialCallbackUrl()
        );
    }

    private static AcspV2SignatureProtocolParameters toRecord(AcspV2SignatureProtocolParametersSurrogate surrogate) {
        if (surrogate == null) {
            return null;
        }
        return new AcspV2SignatureProtocolParameters(
                surrogate.getRpChallenge(),
                surrogate.getSignatureAlgorithm(),
                toRecord(surrogate.getSignatureAlgorithmParameters())
        );
    }

    private static SignatureAlgorithmParameters toRecord(SignatureAlgorithmParametersSurrogate surrogate) {
        if (surrogate == null) {
            return null;
        }
        return new SignatureAlgorithmParameters(surrogate.getHashAlgorithm());
    }

    private static RequestProperties toRecord(RequestPropertiesSurrogate surrogate) {
        if (surrogate == null) {
            return null;
        }
        return new RequestProperties(surrogate.getShareMdClientIpAddress());
    }
}

