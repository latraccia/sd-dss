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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.OID;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

/**
 * Whenever the signature validation process encounters an {@link X509Certificate} a certificateToken is created.<br>
 * This class encapsulates some frequently used information: a certificate comes from a certain context (Trusted List,
 * CertStore, Signature), has revocation data... To expedite the processing of such information, they are kept in cache.
 *
 * @version $Revision: 1837 $ - $Date: 2013-03-14 21:07:50 +0100 (Thu, 14 Mar 2013) $
 */

public class CertificateToken extends Token {

    private static final Logger LOG = Logger.getLogger(CertificateToken.class.getName());

    /**
     * Encapsulated X509 certificate.
     */
    private X509Certificate cert;

    /**
     * This array contains the different sources for this certificate.
     */
    private List<CertificateSourceType> sources = new ArrayList<CertificateSourceType>();

    /**
     * If the certificate is part of the trusted list then the the serviceInfo represents the associated trusted service
     * provider service. Same certificate can be a part of multiple services.
     */
    private List<ServiceInfo> associatedTSPS = new ArrayList<ServiceInfo>();

    /**
     * DSS unique id based on the issuer distinguish name and serial number of encapsulated X509Certificate.
     */
    private int dssId;

    /**
     * The default algorithm used to compute the digest value of this certificate
     */
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;

    /**
     * Base 64 encoded digest value of this certificate computed for a given digest algorithm.
     */
    private Map<DigestAlgorithm, String> digests;

    /**
     * OCSP or CRL revocation data for this token.
     * TODO: to be converted to the List to handle more than one revocation information.
     */
    private RevocationToken revocationToken;

    /**
     * Indicates if the certificate is self-signed. This attribute stays null till the first call to
     * {@link #isSelfSigned()} function.
     */
    private Boolean selfSigned;

    /**
     * Extra information collected during the validation process.
     */
    protected CertificateTokenValidationExtraInfo extraInfo;

    /**
     * This method returns an instance of {@link CertificateToken}.
     *
     * @param cert <code>X509Certificate</code>
     * @param id   DSS unique certificate identifier
     * @return
     */
    static CertificateToken newInstance(X509Certificate cert, int id) {

        return new CertificateToken(cert, id);
    }

    /**
     * Creates a CertificateToken wrapping the provided X509Certificate. A certificate must come from a source like:
     * trusted store, trusted list, signature...
     *
     * @param cert X509Certificate
     * @param id   DSS internal id (unique certificate's identifier)
     */
    protected CertificateToken(X509Certificate cert, int id) {

        this.dssId = id;
        this.cert = cert;
        this.issuerX500Principal = cert.getIssuerX500Principal();
        this.algoOIDUsedToSignToken = cert.getSigAlgOID();
        this.algoUsedToSignToken = cert.getSigAlgName();

        super.extraInfo = this.extraInfo = new CertificateTokenValidationExtraInfo();
    }

    /**
     * This method adds the source type of the certificate (what is its origin). Each source is present only once.
     *
     * @param certSourceType
     */
    public void addSourceType(final CertificateSourceType certSourceType) {

        if (certSourceType != null) {

            if (!sources.contains(certSourceType)) {

                sources.add(certSourceType);
            }
        }
    }

    /**
     * This method adds the associated trusted service information.
     *
     * @param serviceInfo
     */
    public void addServiceInfo(final ServiceInfo serviceInfo) {

        if (serviceInfo != null) {

            if (!associatedTSPS.contains(serviceInfo)) {

                associatedTSPS.add(serviceInfo);
            }
        }
    }

    /**
     * Returns a DSS unique certificate token identifier based on the issuer distinguish name and serial number.
     */
    public int getDSSId() {

        return dssId;
    }

    /**
     * Returns a string representation of the unique DSS certificate token identifier.
     */
    public String getDSSIdAsString() {

        if (dssId == 0) {

            return "[" + cert.getSubjectX500Principal().getName(X500Principal.CANONICAL) + "]";
        }
        return "[" + dssId + "]";
    }

    @Override
    public String getAbbreviation() {

        return getDSSIdAsString();
    }

    /**
     * @param revocationToken This is the reference to the CertificateStatus. The object type is used because of the organisation
     *                        of module.
     */
    public void setRevocationToken(RevocationToken revocationToken) {

        this.revocationToken = revocationToken;
    }

    /**
     * Returns the certificate revocation revocationToken object.
     */
    public RevocationToken getRevocationToken() {

        return revocationToken;
    }

    /**
     * Returns the public key associated with the certificate.<br>
     *
     * To get the encryption algorithm used with this public key call getAlgorithm() method.<br>
     * RFC 2459:<br>
     * 4.1.2.7 Subject Public Key Info
     *
     * This field is used to carry the public key and identify the algorithm with which the key is used. The algorithm is
     * identified using the AlgorithmIdentifier structure specified in section 4.1.1.2. The object identifiers for the
     * supported algorithms and the methods for encoding the public key materials (public key and parameters) are
     * specified in section 7.3.
     *
     * @return
     */
    public PublicKey getPublicKey() {

        return cert.getPublicKey();
    }

    /**
     * Returns .
     *
     * @return
     */
    public Date getNotAfter() {

        return cert.getNotAfter();
    }

    /**
     * Returns .
     *
     * @return
     */
    public Date getNotBefore() {

        return cert.getNotBefore();
    }

    /**
     * Checks if the certificate is expired today.
     *
     * @return
     */
    public boolean isExpired() {

        return cert.getNotAfter().before(new Date());
    }

    /**
     * Checks if the certificate is provided by the trusted source.
     *
     * @return
     */
    public boolean isTrusted() {

        return sources.contains(CertificateSourceType.TRUSTED_LIST) || sources.contains(CertificateSourceType.TRUSTED_STORE);
    }

    /**
     * Checks if the certificate is self-signed.
     *
     * @return
     */
    public boolean isSelfSigned() {

        if (selfSigned == null) {

            final String n1 = cert.getSubjectX500Principal().getName(X500Principal.CANONICAL);
            final String n2 = cert.getIssuerX500Principal().getName(X500Principal.CANONICAL);
            selfSigned = n1.equals(n2);
        }
        return selfSigned;
    }

    /**
     * Compares a given one-off id with this of the wrapped certificate.
     *
     * @param id The DSS validation process one-off certificate's id
     * @return
     */
    public boolean equals(int id) {

        return this.dssId == id;
    }

    @Override
    public int hashCode() {

        return dssId;
    }

    @Override
    public boolean equals(Object obj) {

        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        }
        return dssId == ((CertificateToken) obj).dssId;
    }

    /**
     * Gets the enclosed X509 Certificate.
     *
     * @return
     */
    public X509Certificate getCertificate() {

        return cert;
    }

    /**
     * Gets information about the context in which this certificate token was created (TRUSTED_LIST, TRUSTED_STORE, ...).
     * This method does not guarantee that the token is trusted or not.
     *
     * @return
     */
    public List<CertificateSourceType> getSource() {

        return sources;
    }

    /**
     * Gets information about the trusted context of the certificate. See {@link ServiceInfo} for more information.
     *
     * @return
     */
    public List<ServiceInfo> getAssociatedTSPS() {

        if (isTrusted()) {

            return associatedTSPS;
        }
        return null;
    }

    /**
     * Gets the serialNumber value from the encapsulated certificate. The serial number is an integer assigned by the
     * certification authority to each certificate. It must be unique for each certificate issued by a given CA.
     *
     * @return
     */
    public BigInteger getSerialNumber() {

        return cert.getSerialNumber();
    }

    /**
     * Returns the subject (subject distinguished name) value from the certificate as an X500Principal. If the subject
     * value is empty, then the getName() method of the returned X500Principal object returns an empty string ("").
     *
     * @return
     */
    public X500Principal getSubjectX500Principal() {

        return cert.getSubjectX500Principal();
    }

    @Override
    public boolean isSignedBy(CertificateToken issuerToken) {

        signatureIntact = false;
        signatureInvalidityReason = "";
        try {

            cert.verify(issuerToken.getCertificate().getPublicKey());
            signatureIntact = true;
            if (!isSelfSigned()) {
                this.issuerToken = issuerToken;
            }
        } catch (InvalidKeyException e) {

            signatureInvalidityReason = "InvalidKeyException - on incorrect key.";
        } catch (CertificateException e) {

            signatureInvalidityReason = "InvalidKeyException -  on encoding errors.";
        } catch (NoSuchAlgorithmException e) {

            signatureInvalidityReason = "InvalidKeyException - on unsupported signature algorithms.";
        } catch (SignatureException e) {

            signatureInvalidityReason = "InvalidKeyException - on signature errors.";
        } catch (NoSuchProviderException e) { // if there's no default provider.
         /*
          * This should never happens. The provider BouncyCastle is supposed to be installed. No special treatment for
          * this exception
          */
            throw new RuntimeException(e);
        }
        return signatureIntact;
    }

    /**
     * Indicates that a X509Certificates corresponding private key is used by an authority to sign OCSP-Responses.<br>
     * http://www.ietf.org/rfc/rfc3280.txt <br>
     * {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) keyPurpose(3)
     * ocspSigning(9)}<br>
     * OID: 1.3.6.1.5.5.7.3.9
     *
     * @return
     */
    public boolean isOCSPSigning() {

        try {

            List<String> keyPurposes = cert.getExtendedKeyUsage();
            if (keyPurposes != null && keyPurposes.contains(OID._1_3_6_1_5_5_7_3_9.getName())) {

                return true;
            }
        } catch (CertificateParsingException e) {

            LOG.warning(e.getMessage());
        }
        // Responder's certificate not valid for signing OCSP responses.
        return false;
    }

    /**
     * Indicates if the revocation data should be checked for an OCSP signing certificate.<br>
     * http://www.ietf.org/rfc/rfc2560.txt?number=2560<br>
     * A CA may specify that an OCSP client can trust a responder for the lifetime of the responder's certificate. The CA
     * does so by including the extension id-pkix-ocsp-nocheck. This SHOULD be a non-critical extension. The value of the
     * extension should be NULL.
     *
     * @return
     */
    public boolean hasIdPkixOcspNoCheckExtension() {

        byte[] extensionValue = cert.getExtensionValue(OID._1_3_6_1_5_5_7_48_1_5.getName());
        try {

            if (extensionValue != null) {

                DERObject derObject = toDERObject(extensionValue);
                if (derObject instanceof DEROctetString) {

                    DEROctetString derOctetString = (DEROctetString) derObject;
                    byte[] data = derOctetString.getOctets();
                    return data.length == 0;
                }
            }
        } catch (Exception e) {

        }
        return false;
    }

    /**
     * Indicates if this certificate has an CRL extension expiredCertOnCRL.
     *
     * @return
     */
    public boolean hasExpiredCertOnCRLExtension() {

        byte[] extensionValue = cert.getExtensionValue(OID._2_5_29_60.getName());
        try {

            if (extensionValue != null) {

                DERObject derObject = toDERObject(extensionValue);
                if (derObject instanceof DEROctetString) {

                    DEROctetString derOctetString = (DEROctetString) derObject;
                    byte[] data = derOctetString.getOctets();
                    return data.length == 0;
                }
            }
        } catch (Exception e) {

        }
        return false;
    }

    private DERObject toDERObject(byte[] data) throws IOException {

        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
        DERObject object = asnInputStream.readObject();
        asnInputStream.close();
        return object;
    }

    /**
     * Returns the object managing the validation extra info.
     *
     * @return
     */
    CertificateTokenValidationExtraInfo extraInfo() {

        return extraInfo;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Returns the encoded base 64 digest value of the certificate for a given algorithm. Can return null if the
     * algorithm is unknown.
     *
     * @param digestAlgorithm
     * @return
     */
    public String getDigestValue(final DigestAlgorithm digestAlgorithm) {

        String encoded = null;
        if (digests == null) {

            digests = new HashMap<DigestAlgorithm, String>();
            encoded = digests.get(digestAlgorithm);
            if (encoded == null) {

                try {

                    final MessageDigest digest = MessageDigest.getInstance(digestAlgorithm.getName());
                    digest.update(cert.getEncoded());
                    encoded = DSSUtils.base64Encode(digest.digest());
                    digests.put(digestAlgorithm, encoded);
                } catch (CertificateEncodingException e) {
                    throw new DSSException("Error when computing the digest of the certificate.", e);
                } catch (NoSuchAlgorithmException e) {
                    throw new DSSException("Error when computing the digest of the certificate.", e);
                }
            }
        }
        return encoded;
    }

    public CertificateToken getTrustAnchor() {

        CertificateToken issuerCertToken = getIssuerToken();
        while (issuerCertToken != null) {

            if (issuerCertToken.isTrusted()) {

                return issuerCertToken;
            }
            issuerCertToken = issuerCertToken.getIssuerToken();
        }
        return null;
    }

    @Override
    public String toString(String indentStr) {

        try {

            final StringBuffer out = new StringBuffer();
            out.append(indentStr).append("CertificateToken[\n");
            indentStr += "\t";

            String issuerAsString = "";
            if (issuerToken == null) {

                if (isSelfSigned()) {

                    issuerAsString = "[SELF-SIGNED]";
                } else {
                    issuerAsString = getIssuerX500Principal().toString();
                }
            } else {

                issuerAsString = issuerToken.getDSSIdAsString();
            }
            String certSource = "UNKNOWN";
            if (sources.size() > 0) {

                certSource = sources.get(0).name();
            }
            out.append(indentStr).append(getDSSIdAsString()).append("<--").append(issuerAsString).append(", source=").append(certSource);
            out.append(", serial=" + cert.getSerialNumber()).append('\n');
            // Validity period
            final String certStartDate = DSSUtils.formatInternal(cert.getNotBefore());
            final String certEndDate = DSSUtils.formatInternal(cert.getNotAfter());
            out.append(indentStr).append("Validity period: ").append(certStartDate).append(" - ").append(certEndDate).append('\n');
            if (sources.contains(CertificateSourceType.TRUSTED_LIST)) {

                for (ServiceInfo si : associatedTSPS) {

                    out.append(indentStr).append("Service Info:\n");
                    indentStr += "\t";
                    out.append(si.toString(indentStr));
                    indentStr = indentStr.substring(1);
                }
            }
            out.append(indentStr).append("Signature algorithm: ").append(algoUsedToSignToken == null ? "?" : algoUsedToSignToken).append('\n');
            if (isTrusted()) {

                out.append(indentStr).append("Signature verification is not needed (from TSL)\n");
            } else {

                if (signatureIntact) {

                    out.append(indentStr).append("Signature validity: VALID").append('\n');
                } else {

                    if (!signatureInvalidityReason.isEmpty()) {

                        out.append(indentStr).append("Signature validity: INVALID").append(" - ").append(signatureInvalidityReason).append('\n');
                    }
                }
            }
            if (revocationToken != null) {

                out.append(indentStr).append("Revocation data[\n");
                indentStr += "\t";
                out.append(indentStr).append("Status: ").append(revocationToken.getStatus()).append(" / ").append(revocationToken.getIssuingTime())
                      .append(" / issuer's certificate ").append(revocationToken.getIssuerToken().getDSSIdAsString()).append('\n');
                indentStr = indentStr.substring(1);
                out.append(indentStr).append("]\n");
            } else {

                if (isSelfSigned()) {

                    out.append(indentStr).append("Verification of revocation data is not necessary in the case of a SELF-SIGNED certificate.\n");
                } else if (isTrusted()) {

                    out.append(indentStr).append("Verification of revocation data is not necessary in the case of a TRUSTED certificate.\n");
                } else {

                    out.append(indentStr).append("There is no revocation data available!\n");
                }
            }
            if (issuerToken != null) {

                out.append(indentStr).append("Issuer certificate[\n");
                indentStr += "\t";
                if (issuerToken.isSelfSigned()) {

                    out.append(indentStr).append(issuerToken.getDSSIdAsString()).append(" SELF-SIGNED");
                } else {

                    out.append(issuerToken.toString(indentStr));
                }
                out.append('\n');
                indentStr = indentStr.substring(1);
                out.append(indentStr).append("]\n");
            }
            for (String info : this.extraInfo.getValidationInfo()) {

                out.append(indentStr).append("- ").append(info).append('\n');
            }
            indentStr = indentStr.substring(1);
            out.append(indentStr).append("]");
            return out.toString();
        } catch (Exception e) {

            return e.getMessage();
        }
    }

    public int superHashCode() {

        return super.hashCode();
    }
}
