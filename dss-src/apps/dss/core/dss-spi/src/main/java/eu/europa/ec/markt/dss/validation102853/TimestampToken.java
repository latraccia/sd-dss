/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.validation102853;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * SignedToken containing a TimeStamp.
 *
 * @version $Revision: 1824 $ - $Date: 2013-03-28 15:57:23 +0100 (Thu, 28 Mar 2013) $
 */

public class TimestampToken extends Token {

    private final TimeStampToken timeStamp;

    private TimestampType timeStampType;

    private int dssId;

    private CAdESCertificateSource wrappedSource;

    private X500Principal issuerX500Principal;

    private String signedData = "";

    private Boolean signedDataIntact = null;

    private String signedDataMessage = "";

    private List<TimestampReference> timestampedReferences;

    /**
     * Defines for archive timestamp its type.
     */
    private ArchiveTimestampType archiveTimestampType;

    /**
     * This attribute is used for XAdES timestamps. It indicates the canonicalization method used before creating the digest.
     */
    private String canonicalizationMethod;

    static {

        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Constructor with an indication of the time-stamp type The default constructor for TimestampToken.
     */
    public TimestampToken(TimeStampToken timeStamp, TimestampType type, CertificatePool certPool) {

        this.timeStamp = timeStamp;
        this.timeStampType = type;
        this.extraInfo = new TokenValidationExtraInfo();
        wrappedSource = new CAdESCertificateSource(timeStamp.toCMSSignedData(), certPool);
        Collection<CertificateToken> certs = wrappedSource.getCertificates();
        for (CertificateToken certToken : certs) {

            if (timeStamp.getSID().match(certToken.getCertificate())) {

                isSignedBy(certToken);
                break;
            }
        }
    }

    @Override
    public int getDSSId() {
        return dssId;
    }

    /**
     * Lets to set the DSS id of this token. It is use when checking the digest of covered data (archive timestamp).
     *
     * @param dssId
     */
    public void setDSSId(int dssId) {
        this.dssId = dssId;
    }

    @Override
    public String getAbbreviation() {

        return timeStampType.name() + ": " + DSSUtils.formatInternal(timeStamp.getTimeStampInfo().getGenTime());
    }

    public X500Principal getIssuerX500Principal() {

        return issuerX500Principal;
    }

    @Override
    public boolean isSignedBy(CertificateToken issuerToken) {

        if (this.issuerToken != null) {

            return this.issuerToken.equals(issuerToken);
        }
        try {

            signatureInvalidityReason = "";
            signatureIntact = false;
            JcaSimpleSignerInfoVerifierBuilder verifierBuilder = new JcaSimpleSignerInfoVerifierBuilder();
            SignerInformationVerifier verifier = verifierBuilder.build(issuerToken.getCertificate());
            timeStamp.validate(verifier);
            signatureIntact = true;
            this.issuerToken = issuerToken;

            issuerX500Principal = issuerToken.getCertificate().getSubjectX500Principal();
            algoUsedToSignToken = issuerToken.getSignatureAlgo();
            algoOIDUsedToSignToken = issuerToken.getSignatureAlgoOID();
        } catch (TSPValidationException e) {

            signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
        } catch (TSPException e) {

            signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
        } catch (OperatorCreationException e) {

            signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
        }
        return signatureIntact;
    }

    /**
     * Checks if the TimeStampToken matches the signed data.
     *
     * @param data
     * @return true if the data are verified by the TimeStampToken
     */
    public boolean matchData(byte[] data) {

        try {

            signedData = DSSUtils.base64Encode(data);
            //          System.out.println("signed da --> " + signedData);
            String hashAlgorithm = timeStamp.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId();
            MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
            byte[] computedDigest = digest.digest(data);
            // System.out.println("Signature --> " + DSSUtils.base64Encode(computedDigest));
            byte[] timestampDigest = timeStamp.getTimeStampInfo().getMessageImprintDigest();
            // System.out.println("Timestamp --> " + DSSUtils.base64Encode(timestampDigest));
            signedDataIntact = Arrays.equals(computedDigest, timestampDigest);
        } catch (NoSuchAlgorithmException e) {

            signedDataIntact = false;
            signedDataMessage = "NoSuchAlgorithmException: " + e.getMessage();
        }
        return signedDataIntact;
    }

    /**
     * Retrieves the type of the timestamp token. See {@link TimestampType}
     *
     * @return
     */
    public TimestampType getTimeStampType() {

        return timeStampType;
    }

    /**
     * Retrieves the timestamp generation time.
     *
     * @return
     */
    public Date getGenerationTime() {

        return timeStamp.getTimeStampInfo().getGenTime();
    }

    /**
     * Retrieves the encoded signed data digest value.
     *
     * @return
     */
    public DigestAlgorithm getSignedDataDigestAlgo() {

        String oid = timeStamp.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId();
        return DigestAlgorithm.forOID(oid);
    }

    /**
     * Retrieves the encoded signed data digest value.
     *
     * @return
     */
    public String getEncodedSignedDataDigestValue() {

        return DSSUtils.base64Encode(timeStamp.getTimeStampInfo().getMessageImprintDigest());
    }

    /**
     * This method is used to set the timestamped references. The reference is the digest value of the certificate or of
     * the revocation data. The same references can be timestamped by different timestamps.
     *
     * @param timestampedReferences
     */
    public void setTimestampedReferences(List<TimestampReference> timestampedReferences) {

        this.timestampedReferences = timestampedReferences;
    }

    /**
     * This method either dictates that the data is intact or not intact.
     *
     * @return
     */
    public Boolean isSignedDataIntact() {

        if (signedDataIntact == null) {

            throw new DSSException("Invoke matchData(byte[] data) method before!");
        }
        return signedDataIntact;
    }

    /**
     * This method either dictates that the data is found or not found.
     *
     * @return
     */
    public Boolean isSignedDataFound() {

        return signedData != null;
    }

    /**
     * Retrieves data supposed to be signed. Call {@link #matchData(byte[])} to check if the signature is OK.
     *
     * @return
     */
    public String getSignedData() {

        return signedData;
    }

    /**
     * This method returns the digest value of timestamped references.
     *
     * @return
     */
    public List<TimestampReference> getTimestampedReferences() {

        return timestampedReferences;
    }

    public ArchiveTimestampType getArchiveTimestampType() {
        return archiveTimestampType;
    }

    public void setArchiveTimestampType(ArchiveTimestampType archiveTimestampType) {
        this.archiveTimestampType = archiveTimestampType;
    }

    public String getCanonicalizationMethod() {
        return canonicalizationMethod;
    }

    public void setCanonicalizationMethod(String canonicalizationMethod) {
        this.canonicalizationMethod = canonicalizationMethod;
    }

    @Override
    public String toString(String indentStr) {

        try {

            StringBuffer out = new StringBuffer();
            out.append(indentStr).append("TimestampToken[signedBy=").append(issuerToken == null ? "?" : issuerToken.getDSSIdAsString());
            out.append(", generated: ").append(DSSUtils.formatInternal(timeStamp.getTimeStampInfo().getGenTime()));
            out.append(" / ").append(timeStampType).append('\n');
            if (signatureIntact) {

                indentStr += "\t";
                out.append(indentStr).append("Timestamp's signature validity: VALID").append('\n');
                indentStr = indentStr.substring(1);
            } else {

                if (!signatureInvalidityReason.isEmpty()) {

                    indentStr += "\t";
                    out.append(indentStr).append("Timestamp's signature validity: INVALID").append(" - ").append(signatureInvalidityReason)
                          .append('\n');
                    indentStr = indentStr.substring(1);
                }
            }
            indentStr += "\t";
            if (signedDataIntact != null) {

                if (signedDataIntact) {

                    out.append(indentStr).append("Timestamp MATCHES the signed data.").append('\n');
                } else {

                    out.append(indentStr).append("Timestamp DOES NOT MATCH the signed data.").append('\n');
                    if (!signedDataMessage.isEmpty()) {

                        out.append(indentStr).append("- ").append(signedDataMessage).append('\n');
                    }
                }
            }
            indentStr = indentStr.substring(1);
            if (issuerToken != null) {

                indentStr += "\t";
                out.append(issuerToken.toString(indentStr)).append('\n');
                indentStr = indentStr.substring(1);
                out.append(indentStr);
            }
            out.append("]");
            return out.toString();
        } catch (Exception e) {

            return toString();
        }
    }
}