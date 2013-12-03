package eu.europa.ec.markt.dss.signature;

import java.io.InputStream;

import eu.europa.ec.markt.dss.exception.DSSException;

public abstract class SignatureProfile {

    /**
     * Returns the canonicalized <ds:SignedInfo> XML segment under the form of InputStream
     * 
     * @param document
     * @param params The set of parameters relating to the structure and process of the creation or extension of the
     *            electronic signature.
     * @return
     */
    public abstract InputStream getSignedInfoStream(DSSDocument document, SignatureParameters params);

    /**
     * Adds the signature value to the signature
     * 
     * @param document - document to sign
     * @param params The set of parameters relating to the structure and process of the creation or extension of the
     *            electronic signature.
     * @param signatureValue
     * @return The canonicalized <ds:SignedInfo> XML segment
     */
    public abstract DSSDocument signDocument(DSSDocument document, SignatureParameters params, byte[] signatureValue) throws DSSException;

    public static SignatureProfile getProfile() {
        return null;
    }
}
