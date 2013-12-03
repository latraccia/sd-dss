/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature;

import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.codec.binary.Hex;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation.SignatureForm;

/**
 * Parameters for a Signature creation/extension
 *
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class SignatureParameters {

    private Date signingDate;
    private SignatureTokenConnection signingToken;
    private DSSPrivateKeyEntry privateKeyEntry;
    private List<X509Certificate> certificateChain = new ArrayList<X509Certificate>();
    private X509Certificate signingCertificate;
    private Policy signaturePolicy;
    ProfileParameters context;
    private String claimedSignerRole;
    private SignatureForm signatureForm;
    private SignatureFormat signatureFormat;
    private SignaturePackaging signaturePackaging;

    // TODO 20130614 by meyerfr: I changed the encryptionAlgo and digestAlgo by using the ones provided by the
    // signatureAlgo to have them inline
    // what i do not understand is: why is there another digest-algorithm (signingCertificateDigestMethod)?
    // could you please add some more javadoc?

    private SignatureAlgorithm signatureAlgo = SignatureAlgorithm.RSA_SHA1;
    private EncryptionAlgorithm encryptionAlgo = signatureAlgo.getEncryptionAlgo();
    private DigestAlgorithm digestAlgo = signatureAlgo.getDigestAlgo();
    /*
     * The digest method used to create the digest of the signer's certificate.
     */
    private DigestAlgorithm signingCertificateDigestMethod = DigestAlgorithm.SHA1;

    private boolean asicComment = false;

    private String reason;
    private String contactInfo;
    private String location;
    private String deterministicId;

    public SignatureParameters() {

    }

    private DSSDocument originalDocument;

    /**
     * Copy constructor (used by ASiC)
     */
    protected SignatureParameters(SignatureParameters source) {

        // TODO 20130624 by meyerfr: some class attributes are missing!

        asicComment = source.asicComment;
        signingDate = source.signingDate;
        signingToken = source.signingToken;
        privateKeyEntry = source.privateKeyEntry;
        signingCertificate = source.signingCertificate;
        certificateChain = source.certificateChain;
        signaturePolicy = source.signaturePolicy;
        claimedSignerRole = source.claimedSignerRole;
        signatureFormat = source.signatureFormat;
        signaturePackaging = source.signaturePackaging;
        encryptionAlgo = source.encryptionAlgo;
        digestAlgo = source.digestAlgo;
        reason = source.reason;
        contactInfo = source.contactInfo;
        location = source.location;
        deterministicId = source.deterministicId;
        // This is a simple copy of reference and not of the object content!
        context = source.context;
    }

    public SignatureParameters copy() {
        return new SignatureParameters(this);
    }

    public boolean isAsicComment() {
        return asicComment;
    }

    public void setAsicComment(boolean asicComment) {
        this.asicComment = asicComment;
    }

    public Policy getSignaturePolicy() {
        if (signaturePolicy == null) {
            signaturePolicy = new Policy();
        }
        return signaturePolicy;
    }

    public static class Policy {

        private String id;

        private DigestAlgorithm digestAlgo;

        private byte[] digestValue;

        private List<String> commitmentTypeIndication;

        /**
         * Get the signature policy (EPES)
         *
         * @return
         */
        public String getId() {
            return id;
        }

        /**
         * Set the signature policy (EPES)
         *
         * @param id
         */
        public void setId(String id) {
            this.id = id;
        }

        /**
         * Return the hash algorithm for the signature policy
         *
         * @return
         */
        public DigestAlgorithm getDigestAlgo() {
            return digestAlgo;
        }

        /**
         * Set the hash algorithm for the explicit signature policy
         *
         * @param digestAlgo
         */
        public void setDigestAlgo(DigestAlgorithm digestAlgo) {
            this.digestAlgo = digestAlgo;
        }

        /**
         * Get the hash value of the explicit signature policy
         *
         * @return
         */
        public byte[] getHashValue() {
            return digestValue;
        }

        /**
         * Set the hash value of implicit signature policy
         *
         * @param hashValue
         */
        public void setHashValue(byte[] hashValue) {
            this.digestValue = hashValue;
        }

        public List<String> getCommitmentTypeIndications() {
            return commitmentTypeIndication;
        }

        public void setCommitmentTypeIndications(List<String> commitmentTypeIndication) {
            this.commitmentTypeIndication = commitmentTypeIndication;
        }

    }

    public DSSDocument getOriginalDocument() {
        return originalDocument;
    }

    public void setOriginalDocument(DSSDocument document) {
        this.originalDocument = document;
    }

    /**
     * TODO: Change the text<br>
     * The ID of xades:SignedProperties is contained in the signed content of the xades Signature. We must create this ID
     * in a deterministic way. The signingDate and signingCertificate are mandatory in the more basic level of signature,
     * we use them as "seed" for generating the ID.
     *
     * @return
     */
    public String getDeterministicId() {

        if (deterministicId != null) {
            return deterministicId;
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(Long.toString(getSigningDate().getTime()).getBytes());
            digest.update(getSigningCertificate().getEncoded());
            deterministicId = "id" + Hex.encodeHexString(digest.digest());
            return deterministicId;
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException("Certificate encoding exception");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public ProfileParameters getContext() {
        if (context == null) {
            context = new ProfileParameters();
        }
        return context;
    }

    public SignatureForm getSignatureForm() {
        return signatureForm;
    }

    public void setSignatureForm(SignatureForm signatureForm) {
        this.signatureForm = signatureForm;
    }

    /**
     * Get the signing certificate
     *
     * @return the value
     */
    public X509Certificate getSigningCertificate() {
        return signingCertificate;
    }

    /**
     * Set the signing certificate
     *
     * @param signingCertificate the value
     */
    public void setSigningCertificate(X509Certificate signingCertificate) {
        deterministicId = null;
        this.signingCertificate = signingCertificate;
    }

    /**
     * Set the signing date
     *
     * @param signingDate the value
     */
    public void setSigningDate(Date signingDate) {
        deterministicId = null;
        this.signingDate = signingDate;
    }

    /**
     * Get the signing date
     *
     * @return the value
     */
    public Date getSigningDate() {
        return signingDate;
    }

    /**
     * Set the certificate chain
     *
     * @return the value
     */
    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    /**
     * Get the certificate chain
     *
     * @param certificateChain the value
     */
    public void setCertificateChain(List<X509Certificate> certificateChain) {
        this.certificateChain = certificateChain;
    }

    /**
     * @param certificateChain the value
     */
    public void setCertificateChain(Certificate... certificateChain) {
        if (certificateChain == null) {
            return;
        }

        List<X509Certificate> list = new ArrayList<X509Certificate>();
        for (Certificate c : certificateChain) {
            list.add((X509Certificate) c);
        }
        this.certificateChain = list;
    }

    public void setPrivateKeyEntry(DSSPrivateKeyEntry privateKeyEntry) {
        this.privateKeyEntry = privateKeyEntry;
        this.signingCertificate = privateKeyEntry.getCertificate();
        final String encryptionAlgoName = this.signingCertificate.getPublicKey().getAlgorithm();
        this.encryptionAlgo = EncryptionAlgorithm.forName(encryptionAlgoName);
        this.signatureAlgo = SignatureAlgorithm.getAlgorithm(this.encryptionAlgo, this.digestAlgo);
        setCertificateChain(privateKeyEntry.getCertificateChain());
    }

    /**
     * Returns the private key entry
     *
     * @return the value
     */
    public DSSPrivateKeyEntry getPrivateKeyEntry() {
        return privateKeyEntry;
    }

    /**
     * Returns the connection through available API to the SSCD (SmartCard, MSCAPI, PKCS#12)
     *
     * @return the value
     */
    public SignatureTokenConnection getSigningToken() {
        return signingToken;
    }

    /**
     * Sets the connection through available API to the SSCD (SmartCard, MSCAPI, PKCS#12)
     *
     * @param signingToken the value
     */
    public void setSigningToken(SignatureTokenConnection signingToken) {
        this.signingToken = signingToken;
    }

    /**
     * Get the signature policy (EPES)<br>
     *
     * @return the value
     * @deprecated Use {@link #getSignaturePolicy()}
     */
    @Deprecated
    public String getSignaturePolicyId() {
        return getSignaturePolicy().getId();
    }

    /**
     * Set the signature policy (EPES)
     *
     * @param signaturePolicyId the value
     * @deprecated Use {@link #getSignaturePolicy()}
     */
    @Deprecated
    public void setSignaturePolicyId(String signaturePolicyId) {
        getSignaturePolicy().setId(signaturePolicyId);
    }

    /**
     * Get claimed role
     *
     * @return the value
     */
    public String getClaimedSignerRole() {
        return claimedSignerRole;
    }

    /**
     * Set claimed role
     *
     * @param claimedSignerRole the value
     */
    public void setClaimedSignerRole(String claimedSignerRole) {
        this.claimedSignerRole = claimedSignerRole;
    }

    /**
     * Get signature format: XAdES_BES, XAdES_EPES, XAdES_T ../.. CAdES_BES...
     *
     * @return the value
     */
    public SignatureFormat getSignatureFormat() {
        return signatureFormat;
    }

    /**
     * Set signature format
     *
     * @param signatureFormat the value
     * @deprecated Use the {@link SignatureFormat} enumeration instead
     */
    @Deprecated
    public void setSignatureFormat(String signatureFormat) {
        setSignatureFormat(SignatureFormat.valueByName(signatureFormat));
    }

    /**
     * Set signature format
     *
     * @param signatureFormat the value
     */
    public void setSignatureFormat(SignatureFormat signatureFormat) {
        this.signatureFormat = signatureFormat;
    }

    /**
     * Get Signature packaging
     *
     * @return the value
     */
    public SignaturePackaging getSignaturePackaging() {
        return signaturePackaging;
    }

    /**
     * Set Signature packaging
     *
     * @param signaturePackaging the value
     */
    public void setSignaturePackaging(SignaturePackaging signaturePackaging) {
        this.signaturePackaging = signaturePackaging;
    }

    /**
     * Return the hash algorithm for the signature policy
     *
     * @return the value
     * @deprecated Use {@link #getSignaturePolicy()}
     */
    @Deprecated
    public String getSignaturePolicyHashAlgo() {
        final DigestAlgorithm algo = getSignaturePolicy().getDigestAlgo();
        return (algo == null) ? null : algo.getName();
    }

    /**
     * Set the hash algorithm for the explicit signature policy<br>
     *
     * @param signaturePolicyHashAlgo the value
     * @deprecated Use {@link #getSignaturePolicy()}
     */
    @Deprecated
    public void setSignaturePolicyHashAlgo(String signaturePolicyHashAlgo) {
        getSignaturePolicy().setDigestAlgo(DigestAlgorithm.forName(signaturePolicyHashAlgo));
    }

    /**
     * Get the hash value of the explicit signature policy<br>
     *
     * @return the value
     * @deprecated Use {@link #getSignaturePolicy()}
     */
    @Deprecated
    public byte[] getSignaturePolicyHashValue() {
        return getSignaturePolicy().getHashValue();
    }

    /**
     * Set the hash value of implicit signature policy<br>
     *
     * @param signaturePolicyHashValue the value
     * @deprecated Use {@link #getSignaturePolicy()}
     */
    @Deprecated
    public void setSignaturePolicyHashValue(byte[] signaturePolicyHashValue) {
        getSignaturePolicy().setHashValue(signaturePolicyHashValue);
    }

    /**
     * @return the digest algorithm
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgo;
    }

    /**
     * @param digestAlgorithm the digest algorithm to set
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        digestAlgo = digestAlgorithm;
        signatureAlgo = SignatureAlgorithm.getAlgorithm(signatureAlgo.getEncryptionAlgo(), digestAlgorithm);
    }

    /**
     * @return the encryption algorithm
     */
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgo;
    }

    /**
     * @param encryptionAlgorithm the encryption algorithm to set
     */
    public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        encryptionAlgo = encryptionAlgorithm;
        signatureAlgo = SignatureAlgorithm.getAlgorithm(encryptionAlgo, signatureAlgo.getDigestAlgo());
    }

    /**
     * Gets the signature algorithm.
     *
     * @return the value
     */
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgo;
    }

    /**
     * Sets the signature algorithm.
     *
     * @param signatureAlgorithm
     * @deprecated use {@link #setEncryptionAlgorithm(EncryptionAlgorithm)} and
     *             {@link #setDigestAlgorithm(DigestAlgorithm)}
     */
    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        signatureAlgo = signatureAlgorithm;
        digestAlgo = signatureAlgo.getDigestAlgo();
        encryptionAlgo = signatureAlgo.getEncryptionAlgo();
    }

    public void setSigningCertificateDigestMethod(DigestAlgorithm signingCertificateDigestMethod) {
        this.signingCertificateDigestMethod = signingCertificateDigestMethod;
    }

    public DigestAlgorithm getSigningCertificateDigestMethod() {
        return signingCertificateDigestMethod;
    }

    /**
     * @return the reason
     */
    public String getReason() {
        return reason;
    }

    /**
     * @param reason the reason to set
     */
    public void setReason(String reason) {
        this.reason = reason;
    }

    /**
     * @return the contactInfo
     */
    public String getContactInfo() {
        return contactInfo;
    }

    /**
     * @param contactInfo the contactInfo to set
     */
    public void setContactInfo(String contactInfo) {
        this.contactInfo = contactInfo;
    }

    /**
     * @return the location
     */
    public String getLocation() {
        return location;
    }

    /**
     * @param location the location to set
     */
    public void setLocation(String location) {
        this.location = location;
    }

    /**
     * @return the commitmentTypeIndication
     * @deprecated Use getSignaturePolicy()
     */
    @Deprecated
    public List<String> getCommitmentTypeIndication() {
        return getSignaturePolicy().getCommitmentTypeIndications();
    }

    /**
     * @param commitmentTypeIndication the commitmentTypeIndication to set
     * @deprecated Use {@link #getSignaturePolicy()}
     */
    public void setCommitmentTypeIndication(List<String> commitmentTypeIndication) {
        getSignaturePolicy().setCommitmentTypeIndications(commitmentTypeIndication);
    }
}
