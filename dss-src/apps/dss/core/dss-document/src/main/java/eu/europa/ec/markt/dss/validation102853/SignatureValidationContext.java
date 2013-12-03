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

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.RemoteCertificateSource;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation.crl.CRLSource;
import eu.europa.ec.markt.dss.validation.https.CommonsHttpDataLoader;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPSource;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

/**
 * During the validation of a signature, the software retrieves different X509 artifacts like Certificate, CRL and OCSP
 * Response. The SignatureValidationContext is a "cache" for one validation request that contains every object retrieved
 * so far.
 *
 * @version $Revision: 1839 $ - $Date: 2013-04-04 17:40:51 +0200 (Thu, 04 Apr 2013) $
 */

public class SignatureValidationContext implements ValidationContext {

    private static final Logger LOG = Logger.getLogger(SignatureValidationContext.class.getName());

    private final Set<CertificateToken> processedCertificates = new HashSet<CertificateToken>();
    private final Set<RevocationToken> processedRevocations = new HashSet<RevocationToken>();
    private final Set<TimestampToken> processedTimestamps = new HashSet<TimestampToken>();

    /**
     * The certificate pool which encapsulates all certificates used during the validation process and extracted from all used sources
     */
    protected CertificatePool validationCertPool;

    protected AdvancedSignature signature;

    /*
     * The token representing the certificate to be validated (the signing certificate).
     */
    protected CertificateToken certToValidate;

    private final Map<Token, Boolean> tokensToProcess = new HashMap<Token, Boolean>();

    // External OCSP source.
    private OCSPSource ocspSource;

    // External CRL source.
    private CRLSource crlSource;

    /**
     * In the case of the source which has no or has an empty <code>CertificatePool</code> the request to check if the given certificate is
     * known by this source must be forwarded each time to another source.
     */
    private RemoteCertificateSource remoteTrustedCertSource;

    // CRLs from the signature.
    private CRLSource signCRLSource;

    // OCSP from the signature.
    private OCSPSource signOCSPSource;

    // Enclosed signature timestamps.
    private List<TimestampToken> sigTimestamps;

    // Timestamped data for sigTimestamp.
    private byte[] timestampData;

    // Enclosed SignAndRefs timestamps.
    private List<TimestampToken> sigAndRefsTimestamps;

    // Timestamped data for sigAndRefs timestamp.
    private byte[] sigAndRefsTimestampData;

    // The digest value of the certification path references and the revocation status references.
    private List<TimestampReference> timestampedReferences;

    // Enclosed RefsOnly timestamps.
    private List<TimestampToken> refsOnlyTimestamps;

    // Timestamped data for refsOnly timestamp.
    byte[] refsOnlyTimestampData;

    // Enclosed Archive timestamps.
    private List<TimestampToken> archiveTimestamps;

    // Timestamped data for archive timestamp.
    private byte[] archiveTimestampData;

    /**
     * This constructor is used when the whole signature need to be validated.
     *
     * @param signature
     * @param certVerifier       The trusted certificates verifier (using the TSL as list of trusted certificates).
     * @param validationCertPool
     */
    public SignatureValidationContext(final AdvancedSignature signature, final CertificateVerifier certVerifier,
                                      final CertificatePool validationCertPool) {

        if (signature == null) {

            throw new DSSException("The signature to validate cannot be null.");
        }
        if (certVerifier == null) {

            throw new DSSException("The certificate verifier cannot be null.");
        }
        if (validationCertPool == null) {

            throw new DSSException("The certificate pool cannot be null.");
        }
        this.crlSource = certVerifier.getCrlSource();
        this.ocspSource = certVerifier.getOcspSource();
        TrustedCertificateSource trustedCertSource = certVerifier.getTrustedCertSource();
        if (trustedCertSource instanceof RemoteCertificateSource) {

            this.remoteTrustedCertSource = (RemoteCertificateSource) certVerifier.getTrustedCertSource();
        }

        this.signCRLSource = signature.getCRLSource();
        this.signOCSPSource = signature.getOCSPSource();

        this.sigTimestamps = signature.getSignatureTimestamps();
        this.timestampData = signature.getSignatureTimestampData();

        this.sigAndRefsTimestamps = signature.getTimestampsX1();
        this.sigAndRefsTimestampData = signature.getTimestampX1Data();

        this.refsOnlyTimestamps = signature.getTimestampsX2();
        this.refsOnlyTimestampData = signature.getTimestampX2Data();

        this.timestampedReferences = signature.getTimestampedReferences();

        // this variable need to be preserved for archive timestamp data computation.
        this.signature = signature;
        this.archiveTimestamps = signature.getArchiveTimestamps();
        // The archiveTimestampData cannot be built before the validation of the signature; the references are not
        // available yet.
        // this.archiveTimestampData = signature.getArchiveTimestampData(0, null);

        this.validationCertPool = validationCertPool;
        if (LOG.isLoggable(Level.INFO)) {

            LOG.info("+ New ValidationContext created.");
        }
    }

    /**
     * This constructor is used when only a certificate need to be validated.
     *
     * @param certVerifier The trusted certificates verifier (using the TSL as list of trusted certificates).
     */
    public SignatureValidationContext(final CertificateVerifier certVerifier) {

        if (certVerifier == null) {

            throw new DSSException("The certificate verifier cannot be null.");
        }

        this.crlSource = certVerifier.getCrlSource();
        this.ocspSource = certVerifier.getOcspSource();
        final TrustedCertificateSource trustedCertSource = certVerifier.getTrustedCertSource();
        if (trustedCertSource instanceof RemoteCertificateSource) {

            this.remoteTrustedCertSource = (RemoteCertificateSource) trustedCertSource;
        }
        validationCertPool = new CertificatePool();

        if (LOG.isLoggable(Level.INFO)) {

            LOG.info("+ New ValidationContext created for a certificate.");
        }
    }

    /**
     * This function sets the signing certificate to be validated.
     *
     * @param certToValidate
     */
    @Override
    public void setCertificateToValidate(final CertificateToken certToValidate) {

        this.certToValidate = certToValidate;
        addNotYetVerifiedCertificateToken(this.certToValidate);
    }

    /**
     * @return
     */
    private Token getNotYetVerifiedToken() {

        for (final Entry<Token, Boolean> entry : tokensToProcess.entrySet()) {

            if (entry.getValue() == null) {

                entry.setValue(true);
                return entry.getKey();
            }
        }
        return null;
    }

    /**
     * This method returns the issuer certificate (the certificate which was used to sign the token) of the given token.
     *
     * @param token
     * @return
     * @throws DSSException
     */
    private CertificateToken getIssuerCertificate(final Token token) throws DSSException {

        if (token.isTrusted()) {

            return null;
        }
        if (token.getIssuerToken() != null) {

            /**
             * The signer's certificate have been found already. This can happen in the case of:<br>
             * - multiple signatures that use the same certificate,<br>
             * - OCSPRespTokens (the issuer certificate is known from the beginning)
             */
            return token.getIssuerToken();
        }
        final X500Principal issuerX500Principal = token.getIssuerX500Principal();
        CertificateToken issuerCertificateToken = getIssuerFromPool(token, issuerX500Principal);

        // If the remote source is defined the retrieval of the issuer certificate must be done to know if it is trusted certificate.
        if (remoteTrustedCertSource != null && (issuerCertificateToken == null || (issuerCertificateToken != null && !issuerCertificateToken
              .isTrusted()))) {

            final CertificateToken remoteIssuerCertificateToken = getIssuerFromRemotePool(token, issuerX500Principal);
            if (remoteIssuerCertificateToken != null) {

                issuerCertificateToken = remoteIssuerCertificateToken;
            }
        }
        if (issuerCertificateToken == null && token instanceof CertificateToken) {

            issuerCertificateToken = getIssuerFromAIA((CertificateToken) token);
        }
        if (issuerCertificateToken == null) {

            token.extraInfo().infoTheSigningCertNotFound();
        }
        if (issuerCertificateToken != null && !issuerCertificateToken.isTrusted() && !issuerCertificateToken.isSelfSigned()) {

            // The full chain is retrieved
            getIssuerCertificate(issuerCertificateToken);
        }
        return issuerCertificateToken;
    }

    /**
     * Get the issuer's certificate from Authority Information Access through id-ad-caIssuers extension.
     *
     * @param token
     * @return
     */
    private CertificateToken getIssuerFromAIA(final CertificateToken token) {

        final X509Certificate cert;
        try {

            if (LOG.isLoggable(Level.INFO)) {

                LOG.info(String.format("Retrieving for the certificate %s its issuer using AIA.", token.getAbbreviation()));
            }
            cert = DSSUtils.loadIssuerCertificate(token.getCertificate(), new CommonsHttpDataLoader());
            if (cert != null) {

                final CertificateToken issuerCertToken = validationCertPool.getInstance(cert, CertificateSourceType.AIA);
                if (token.isSignedBy(issuerCertToken)) {

                    return issuerCertToken;
                }
            }
        } catch (DSSException e) {

            LOG.warning(e.getMessage());
        }
        return null;
    }

    private CertificateToken getIssuerFromRemotePool(final Token token, final X500Principal issuerX500Principal) {

        System.out.println("GET ISSUER FROM REMOTE: ======================>" + issuerX500Principal.toString());
        if (remoteTrustedCertSource != null) {

            final List<CertificateToken> certificateTokens = remoteTrustedCertSource.get(issuerX500Principal);
            System.out.println("---> RETURNED REMOTE CERTIFICATEs: " + certificateTokens.size());
            for (final CertificateToken remoteCertificateToken : certificateTokens) {

                System.out.println("---> RETURNED REMOTE CERTIFICATE: " + remoteCertificateToken.getAbbreviation());
                final X509Certificate x509Certificate = remoteCertificateToken.getCertificate();
                final CertificateToken issuerCertToken = validationCertPool.getInstance(x509Certificate, CertificateSourceType.TRUSTED_LIST);
                final List<ServiceInfo> remoteServiceInfoList = remoteCertificateToken.getAssociatedTSPS();
                for (final ServiceInfo serviceInfo : remoteServiceInfoList) {

                    issuerCertToken.addServiceInfo(serviceInfo);
                }
                System.out.println("LOCAL CERTIFICATE: " + issuerCertToken.getAbbreviation());
                if (token.isSignedBy(issuerCertToken)) {

                    return issuerCertToken;
                }
            }
        }
        return null;
    }

    /**
     * This function retrieves the issuer certificate from the validation pool of certificates and checks if the token was well signed by
     * the retrieved certificate.
     *
     * @param token               token for which the issuer have to be found
     * @param issuerX500Principal issuer's subject distinguished name
     * @return the corresponding <code>CertificateToken</code> or null if not found
     */
    private CertificateToken getIssuerFromPool(final Token token, final X500Principal issuerX500Principal) {

        final List<CertificateToken> issuerCertList = validationCertPool.get(issuerX500Principal);
        for (final CertificateToken issuerCertToken : issuerCertList) {

            // We keep the first issuer that signs the certificate
            if (token.isSignedBy(issuerCertToken)) {

                return issuerCertToken;
            }
        }
        return null;
    }

    /**
     * @param token
     */
    private boolean addNotYetVerifiedToken(final Token token) {

        if (token == null) {

            return false;
        }
        if (tokensToProcess.containsKey(token)) {

            if (LOG.isLoggable(Level.INFO)) {
                LOG.info("Token was already in the list " + token.getClass().getSimpleName() + ":" + token.getAbbreviation());
            }
            return false;
        }
        tokensToProcess.put(token, null);
        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("+ New " + token.getClass().getSimpleName() + " to check: " + token.getAbbreviation());
        }
        return true;
    }

    /**
     * @param revocationToken
     */
    private void addNotYetVerifiedRevocationToken(final RevocationToken revocationToken) {

        if (addNotYetVerifiedToken(revocationToken)) {

            processedRevocations.add(revocationToken);
        }
    }

    /**
     * @param certToken
     */
    private void addNotYetVerifiedCertificateToken(final CertificateToken certToken) {

        if (addNotYetVerifiedToken(certToken)) {

            processedCertificates.add(certToken);
        }
    }

    /**
     * @param timestampToken
     */
    private void addNotYetVerifiedTimestampToken(final TimestampToken timestampToken) {

        if (addNotYetVerifiedToken(timestampToken)) {

            processedTimestamps.add(timestampToken);
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.validation102853.ValidationContext#validate(java.util.Date,
     * eu.europa.ec.markt.dss.validation102853.CertificateSource, eu.europa.ec.markt.dss.validation.crl.CRLSource,
     * eu.europa.ec.markt.dss.validation.ocsp.OCSPSource)
     */
    @Override
    public void validate() throws DSSException {

        runValidation();

        if (signature == null) {

            // Only a certificate is validated
            return;
        }
      /*
       * This validates the signature timestamp tokensToProcess present in the signature.
       */
        for (final Token token : sigTimestamps) {

            final TimestampToken timestampToken = (TimestampToken) token;
            // System.out.println(timestampToken);
            timestampToken.matchData(timestampData);

            addNotYetVerifiedTimestampToken(timestampToken);
            runValidation();
        }

      /*
       * This validates the SigAndRefs timestamp tokensToProcess present in the signature.
       */
        for (final Token token : sigAndRefsTimestamps) {

            final TimestampToken timestampToken = (TimestampToken) token;
            timestampToken.matchData(sigAndRefsTimestampData);

            addNotYetVerifiedTimestampToken(timestampToken);
            runValidation();
        }

      /*
       * This validates the RefsOnly timestamp tokensToProcess present in the signature.
       */
        for (final Token token : refsOnlyTimestamps) {

            final TimestampToken timestampToken = (TimestampToken) token;
            timestampToken.matchData(refsOnlyTimestampData);

            addNotYetVerifiedTimestampToken(timestampToken);
            runValidation();
        }

      /*
       * This validates the archive timestamp tokensToProcess present in the signature.
       */
        for (final TimestampToken timestampToken : archiveTimestamps) {

            archiveTimestampData = signature.getArchiveTimestampData(timestampToken);

            timestampToken.matchData(archiveTimestampData);

            addNotYetVerifiedTimestampToken(timestampToken);
            runValidation();
        }
    }

    /*
     * Executes validation process for not yet validated tokensToProcess.
     */
    private void runValidation() throws DSSException {

        final Token token = getNotYetVerifiedToken();
        if (token == null) {

            return;
        }
      /*
       * Gets the issuer certificate (the issuer of the CertificateToken or the signing certificate of other tokensToProcess) and
       * checks the signature of the token
       */
        final CertificateToken issuerCertToken = getIssuerCertificate(token);
        if (issuerCertToken != null && !token.isSelfSigned() && !token.isTrusted()) {

            addNotYetVerifiedCertificateToken(issuerCertToken);
        }
        if (token instanceof CertificateToken) {

            final RevocationToken revocationToken = getRevocationData((CertificateToken) token);
            addNotYetVerifiedRevocationToken(revocationToken);
        }
        runValidation();
    }

    /**
     * Retrieves the revocation data from signature (if exists) or from the online sources.
     *
     * @param certToken
     * @return
     */
    private RevocationToken getRevocationData(final CertificateToken certToken) {

        if (certToken.isSelfSigned() || certToken.isTrusted()) {

            return null;
        }
        if (certToken.isOCSPSigning() && certToken.hasIdPkixOcspNoCheckExtension()) {

            certToken.extraInfo().add("OCSP check not needed: id-pkix-ocsp-nocheck extension present.");
            return null;
        }
        final CertificateToken issuerCertToken = certToken.getIssuerToken();
        if (issuerCertToken == null) {

            return null;
        }
        RevocationToken revocationToken = null;
        final boolean isCertExpired = certToken.isExpired();
        final boolean hasExpiredCertOnCRLExtension = isCertExpired && issuerCertToken.hasExpiredCertOnCRLExtension();
        Date expiredCertsRevocationInfo = null;

        final CertificateToken trustAnchor = certToken.getTrustAnchor();
        if (trustAnchor != null) {

            final List<ServiceInfo> serviceInfoList = trustAnchor.getAssociatedTSPS();
            for (final ServiceInfo serviceInfo : serviceInfoList) {

                final Date date = serviceInfo.getExpiredCertsRevocationInfo();
                if (expiredCertsRevocationInfo == null) {

                    expiredCertsRevocationInfo = date;
                    break;
                }
                if (date != null && date.before(expiredCertsRevocationInfo)) {

                    expiredCertsRevocationInfo = date;
                }
            }
            if (expiredCertsRevocationInfo != null && expiredCertsRevocationInfo.after(certToken.getNotAfter())) {

                expiredCertsRevocationInfo = null;
            }
        }
        if (!isCertExpired || hasExpiredCertOnCRLExtension || expiredCertsRevocationInfo != null) {

            if (hasExpiredCertOnCRLExtension) {

                certToken.extraInfo().add("Certificate is expired but the issuer certificate has ExpiredCertOnCRL extension.");
            }
            if (expiredCertsRevocationInfo != null) {

                certToken.extraInfo()
                      .add("Certificate is expired but the TSL extension 'expiredCertsRevocationInfo' is present: " + expiredCertsRevocationInfo);
            }
            if (LOG.isLoggable(Level.INFO)) {

                LOG.info("Verification OCSPAndCRL with ON-LINE services for " + certToken.getDSSIdAsString());
            }
            final OCSPAndCRLCertificateVerifier onlineVerifier = new OCSPAndCRLCertificateVerifier(crlSource, ocspSource, validationCertPool);
            revocationToken = onlineVerifier.check(certToken);
        }
        if (revocationToken == null) {

            if (LOG.isLoggable(Level.INFO)) {

                LOG.info("Verification OCSPAndCRL with OFF-LINE services for " + certToken.getDSSIdAsString());
            }
            final OCSPAndCRLCertificateVerifier offlineVerifier = new OCSPAndCRLCertificateVerifier(signCRLSource, signOCSPSource,
                  validationCertPool);
            revocationToken = offlineVerifier.check(certToken);
        }
        return revocationToken;
    }

    @Override
    public Set<CertificateToken> getProcessedCertificates() {

        return Collections.unmodifiableSet(processedCertificates);
    }

    @Override
    public Set<RevocationToken> getProcessedRevocations() {

        return Collections.unmodifiableSet(processedRevocations);
    }

    @Override
    public Set<TimestampToken> getProcessedTimestamps() {

        return Collections.unmodifiableSet(processedTimestamps);
    }

    @Override
    public List<TimestampToken> getTimestampTokens() {

        return Collections.unmodifiableList(sigTimestamps);
    }

    @Override
    public List<TimestampToken> getSigAndRefsTimestamps() {

        return Collections.unmodifiableList(sigAndRefsTimestamps);
    }

    @Override
    public List<TimestampToken> getRefsOnlyTimestamps() {

        return Collections.unmodifiableList(refsOnlyTimestamps);
    }

    @Override
    public List<TimestampToken> getArchiveTimestamps() {

        return Collections.unmodifiableList(archiveTimestamps);
    }

    /**
     * Returns certificate and revocation references.
     *
     * @return
     */
    public List<TimestampReference> getTimestampedReferences() {
        return timestampedReferences;
    }

    /**
     * This method returns the human readable representation of the ValidationContext.
     *
     * @param indentStr
     * @return
     */

    public String toString(String indentStr) {

        try {

            final StringBuilder builder = new StringBuilder();
            builder.append(indentStr).append("ValidationContext[").append('\n');
            indentStr += "\t";
            // builder.append(indentStr).append("Validation time:").append(validationDate).append('\n');
            builder.append(indentStr).append("Certificates[").append('\n');
            indentStr += "\t";
            for (CertificateToken certToken : processedCertificates) {

                builder.append(certToken.toString(indentStr));
            }
            indentStr = indentStr.substring(1);
            builder.append(indentStr).append("],\n");
            indentStr = indentStr.substring(1);
            builder.append(indentStr).append("],\n");
            return builder.toString();
        } catch (Exception e) {

            return super.toString();
        }
    }

    @Override
    public String toString() {

        return toString("");
    }
}
