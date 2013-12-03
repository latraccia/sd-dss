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

package eu.europa.ec.markt.dss.validation;

import java.io.IOException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.SingleResp;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation.certificate.CompositeCertificateSource;
import eu.europa.ec.markt.dss.validation.crl.CRLSource;
import eu.europa.ec.markt.dss.validation.crl.ListCRLSource;
import eu.europa.ec.markt.dss.validation.https.CommonsHttpDataLoader;
import eu.europa.ec.markt.dss.validation.ocsp.ListOCSPSource;
import eu.europa.ec.markt.dss.validation.ocsp.OCSPSource;
import eu.europa.ec.markt.dss.validation.tsl.ServiceInfo;
import eu.europa.ec.markt.dss.validation.x509.CRLToken;
import eu.europa.ec.markt.dss.validation.x509.CertificateToken;
import eu.europa.ec.markt.dss.validation.x509.OCSPRespToken;
import eu.europa.ec.markt.dss.validation.x509.RevocationData;
import eu.europa.ec.markt.dss.validation.x509.SignedToken;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;

/**
 * During the validation of a certificate, the software retrieves different X509 artifacts like Certificate, CRL and
 * OCSP Response. The ValidationContext is a "cache" for one validation request that contains every object retrieved so
 * far.
 *
 * @version $Revision: 2922 $ - $Date: 2013-11-11 13:57:58 +0100 (lun., 11 nov. 2013) $
 */

public class ValidationContext {

    private static final Logger LOG = Logger.getLogger(ValidationContext.class.getName());

    private final List<BasicOCSPResp> neededOCSPResp = new ArrayList<BasicOCSPResp>();

    private final List<X509CRL> neededCRL = new ArrayList<X509CRL>();

    private final List<CertificateAndContext> neededCertificates = new ArrayList<CertificateAndContext>();

    /*
     * Certificate to be validated
     */
    private final X509Certificate certificate;

    /*
      *
      */
    private final Map<SignedToken, RevocationData> revocationInfo = new HashMap<SignedToken, RevocationData>();

    private CertificateSource trustedListCertificatesSource;

    private OCSPSource ocspSource;

    private CRLSource crlSource;

    private final Date _validationDate;

    /**
     * The default constructor for ValidationContextV2.
     *
     * @param certificate The certificate that will be validated.
     */
    public ValidationContext(X509Certificate certificate, Date validationDate) {

        this.certificate = certificate;
        this._validationDate = validationDate;
        if (certificate != null) {

            if (LOG.isLoggable(Level.INFO)) {

                LOG.info("+ New ValidationContext created for '" + CertificateIdentifier.getId(certificate) + "' at " + validationDate.toString());
            }
            CertificateAndContext certificateAndContext = new CertificateAndContext(certificate);
            certificateAndContext.setCertificateSource(CertificateSourceType.OTHER);
            addNotYetVerifiedToken(new CertificateToken(certificateAndContext));
        }
    }

    /**
     * Return the certificate for which this ValidationContext has been created
     *
     * @return the certificate
     */
    public X509Certificate getCertificate() {

        return certificate;
    }

    /**
     * @return the validationDate
     */
    public Date getValidationDate() {

        return _validationDate;
    }

    /**
     * @param trustedListCertificatesSource the trustedListCertificatesSource to set
     */
    public void setTrustedListCertificatesSource(CertificateSource trustedListCertificatesSource) {

        this.trustedListCertificatesSource = trustedListCertificatesSource;
    }

    /**
     * @param crlSource the crlSource to set
     */
    public void setCrlSource(CRLSource crlSource) {

        this.crlSource = crlSource;
    }

    /**
     * @param ocspSource the ocspSource to set
     */
    public void setOcspSource(OCSPSource ocspSource) {

        this.ocspSource = ocspSource;
    }

    SignedToken getNotYetVerifiedToken() {

        for (Entry<SignedToken, RevocationData> e : revocationInfo.entrySet()) {

            if (e.getValue() == null) {

                // LOG.info("=== Get token to validate " + e.getKey());
                return e.getKey();
            }
        }
        return null;
    }

    /**
     * @param signedToken
     * @param optionalSource
     * @param validationDate
     * @return
     * @throws IOException An error occurs when accessing the CertificateSource
     */
    CertificateAndContext getIssuerCertificate(SignedToken signedToken, CertificateSource optionalSource, Date validationDate) throws IOException {

        X500Principal signerSubjectName = signedToken.getSignerSubjectName();
        if (signerSubjectName == null) {

            return null;
        }
        final CompositeCertificateSource source = new CompositeCertificateSource(trustedListCertificatesSource, optionalSource);
        List<CertificateAndContext> certs = source.getCertificateBySubjectName(signerSubjectName);
        if (certs == null || certs.isEmpty()) {

            if (signedToken instanceof CertificateToken) {

                CertificateToken certToken = (CertificateToken) signedToken;
                CertificateAndContext issuerCertAndContext = getIssuerFromAIA(certToken, signerSubjectName);
                if (issuerCertAndContext == null) {

                    return null;
                }
                certs.add(issuerCertAndContext);
            } else {

                return null;
            }
        }
        for (CertificateAndContext cac : certs) {

            X509Certificate cert = cac.getCertificate();
            if (LOG.isLoggable(Level.INFO)) {
                CertificateIdentifier.getId(cert);
            }
         /* If there is a validation date, we skip the issuer */
            if (validationDate != null) {

                try {

                    cert.checkValidity(validationDate);
                } catch (CertificateNotYetValidException e) {

                    if (LOG.isLoggable(Level.INFO)) {
                        LOG.info(CertificateIdentifier.getIdAsString(cert) + " validity: not yet valid");
                    }
                    continue;
                } catch (CertificateExpiredException e) {

                    if (LOG.isLoggable(Level.INFO)) {
                        LOG.info(CertificateIdentifier.getIdAsString(cert) + " validity: expired");
                    }
                    continue;
                }
                if (CertificateSourceType.TRUSTED_LIST.equals(cac.getCertificateSource()) && cac.getContext() != null) {

                    ServiceInfo info = (ServiceInfo) cac.getContext();
                    if (info.getStatusStartingDateAtReferenceTime() != null && validationDate.before(info.getStatusStartingDateAtReferenceTime())) {

                        if (LOG.isLoggable(Level.INFO)) {
                            LOG.info("tsl validity: not yet valid");
                        }
                        continue;
                    }
                    if (info.getStatusEndingDateAtReferenceTime() != null && validationDate.after(info.getStatusEndingDateAtReferenceTime())) {

                        if (LOG.isLoggable(Level.INFO)) {
                            LOG.info("tsl validity: expired");
                        }
                        continue;
                    }
                }
            }
         /* We keep the first issuer that signs the certificate */
            if (signedToken.isSignedBy(cert)) {

                return cac;
            }
        }
        return null;
    }

    /**
     * Get the issuer's certificate from Authority Information Access through id-ad-caIssuers extension.
     *
     * @param certToken
     * @param issuerX500Principal
     * @return
     */
    private CertificateAndContext getIssuerFromAIA(final CertificateToken certToken, final X500Principal issuerX500Principal) {

        try {

            final X509Certificate issuerCert = DSSUtils.loadIssuerCertificate(certToken.getCertificate(), new CommonsHttpDataLoader());
            if (issuerCert != null) {

                if (certToken.isSignedBy(issuerCert)) {

                    final CertificateAndContext issuerCertAndContext = new CertificateAndContext(issuerCert);
                    issuerCertAndContext.setCertificateSource(CertificateSourceType.AIA);
                    return issuerCertAndContext;
                }
            }
        } catch (Exception e) {

            //do nothing
        }
        return null;
    }

    /**
     * @param signedTokenToCheck
     */
    void addNotYetVerifiedToken(SignedToken signedTokenToCheck) {

        if (revocationInfo.containsKey(signedTokenToCheck)) {

            if (LOG.isLoggable(Level.INFO)) {
                LOG.info("Token was already in list " + signedTokenToCheck);
            }
            return;
        }
        revocationInfo.put(signedTokenToCheck, null);
        if (signedTokenToCheck instanceof CRLToken) {

            neededCRL.add(((CRLToken) signedTokenToCheck).getX509crl());
        } else if (signedTokenToCheck instanceof OCSPRespToken) {

            neededOCSPResp.add(((OCSPRespToken) signedTokenToCheck).getOcspResp());
        } else if (signedTokenToCheck instanceof CertificateToken) {

            // avoid duplicates
            CertificateAndContext certAndContextToCheck = ((CertificateToken) signedTokenToCheck).getCertificateAndContext();
            X509Certificate certificateToCheck = certAndContextToCheck.getCertificate();
            for (CertificateAndContext certAndContext : neededCertificates) {

                if (certAndContext.getCertificate().equals(certificateToCheck)) {

                    return;
                }
            }
            neededCertificates.add(certAndContextToCheck);
        }
        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("+ New " + signedTokenToCheck.getClass().getSimpleName() + " to check: " + signedTokenToCheck);
        }
    }

    /**
     * @param signedToken
     * @param data
     */
    void validate(SignedToken signedToken, RevocationData data) {

        if (data == null) {

            throw new IllegalArgumentException("data cannot be null");
        }
        if (!revocationInfo.containsKey(signedToken)) {

            throw new IllegalArgumentException(signedToken + " must be a key of revocationInfo");
        }
        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("RevocationValidation: " + signedToken + ":\n" + data.toString("\t"));
        }
        revocationInfo.put(signedToken, data);
    }

    /**
     * Validate the timestamp
     *
     * @param timestamp
     * @param optionalSource
     * @param optionalCRLSource
     * @param optionalOCPSSource
     */
    public void validateTimestamp(TimestampToken timestamp, CertificateSource optionalSource, CRLSource optionalCRLSource,
                                  OCSPSource optionalOCPSSource) throws IOException {

        addNotYetVerifiedToken(timestamp);
        Date date = timestamp.getTimeStamp().getTimeStampInfo().getGenTime();
        CompositeCertificateSource compositeCertificateSource = new CompositeCertificateSource(timestamp.getWrappedCertificateSource(),
              optionalSource);
        validate(date, compositeCertificateSource, optionalCRLSource, optionalOCPSSource);
    }

    /**
     * Build the validation context for the specific date
     *
     * @param validationDate
     * @param optionalSource     Most often this is the signature source
     * @param optionalCRLSource  Most often this is the signature source
     * @param optionalOCPSSource Most often this is the signature source
     * @throws IOException
     */
    public void validate(Date validationDate, CertificateSource optionalSource, CRLSource optionalCRLSource,
                         OCSPSource optionalOCPSSource) throws IOException {

        int previousSize = revocationInfo.size();
        int previousVerified = verifiedTokenCount();

        SignedToken signedToken = getNotYetVerifiedToken();
        if (signedToken == null) {

            return;
        }

        CertificateSource otherSource = optionalSource;
        if (signedToken.getWrappedCertificateSource() != null) {

            otherSource = new CompositeCertificateSource(signedToken.getWrappedCertificateSource(), optionalSource);
        }

        // Check of the signature of the certificate
        CertificateAndContext issuer = getIssuerCertificate(signedToken, otherSource, validationDate);

        RevocationData data = null;

        if (issuer == null) {
         /* We did not find an issuer, so the RevocationData cannot be retrieved. */
            LOG.warning("No issuer found for token " + signedToken);
            data = new RevocationData(signedToken);
        } else {

            // CertificateSourceType source = issuer.getCertificateSource();
            // Don't check the the trusted certificates:
            // if (source == null || !source.equals(CertificateSourceType.TRUSTED_LIST)) {

            addNotYetVerifiedToken(new CertificateToken(issuer));

            // self-signed
            X509Certificate issuerCert = issuer.getCertificate();
            if (X500PrincipalMatcher.viaAny(issuerCert.getSubjectX500Principal(), issuerCert.getIssuerX500Principal())) {

                SignedToken trustedToken = new CertificateToken(issuer);
                RevocationData noNeedToValidate = new RevocationData();
                // noNeedToValidate.setRevocationData(CertificateSourceType.TRUSTED_LIST);
                validate(trustedToken, noNeedToValidate);
            }

            // approved by trust anchor
            if (issuer.getCertificateSource() == CertificateSourceType.TRUSTED_LIST) {

                SignedToken trustedToken = new CertificateToken(issuer);
                RevocationData noNeedToValidate = new RevocationData();
                noNeedToValidate.setRevocationData(CertificateSourceType.TRUSTED_LIST);
                validate(trustedToken, noNeedToValidate);
            }
            // }
            if (signedToken instanceof CertificateToken) {

                CertificateStatus status = null;
                CertificateAndContext cac = ((CertificateToken) signedToken).getCertificateAndContext();
                if (cac.isOCSPSigning() && cac.has_id_pkix_ocsp_nocheck_extension()) {

                    LOG.info("Revocation check not needed. The certificate " + CertificateIdentifier
                          .getIdAsString(cac.getCertificate()) + " has id_pkix_ocsp_nocheck extension.");

                    data = new RevocationData();
                    data.setRevocationData(CertificateSourceType.TRUSTED_LIST);
                } else {

                    status = getRevocationData(cac, issuer, validationDate, optionalCRLSource, optionalOCPSSource);
                    data = new RevocationData(signedToken);
                    if (status != null) {

                        data.setRevocationData(status.getStatusSource());
                        if (status.getStatusSource() instanceof X509CRL) {

                            addNotYetVerifiedToken(new CRLToken((X509CRL) status.getStatusSource()));
                        } else if (status.getStatusSource() instanceof BasicOCSPResp) {

                            addNotYetVerifiedToken(new OCSPRespToken((BasicOCSPResp) status.getStatusSource()));
                        }
                    } else {

                        LOG.warning("No status for " + signedToken);
                    }
                }
            } else if (signedToken instanceof CRLToken || signedToken instanceof OCSPRespToken || signedToken instanceof TimestampToken) {

                data = new RevocationData(signedToken);
                data.setRevocationData(issuer);

            } else {
                throw new RuntimeException("Not supported token type " + signedToken.getClass().getSimpleName());
            }

        }
        validate(signedToken, data);

        // LOG.info(this.toString());

        int newSize = revocationInfo.size();
        int newVerified = verifiedTokenCount();

        if (newSize != previousSize || newVerified != previousVerified) {

            validate(validationDate, otherSource, optionalCRLSource, optionalOCPSSource);
        }

    }

    int verifiedTokenCount() {

        int count = 0;
        for (Entry<SignedToken, RevocationData> e : revocationInfo.entrySet()) {
            if (e.getValue() != null) {
                count++;
            }
        }
        return count;
    }

    public String getShortConclusion() {

        int count = 0;
        for (Entry<SignedToken, RevocationData> e : revocationInfo.entrySet()) {

            if (e.getValue() != null) {

                count++;
            }
        }
        StringBuilder buffer = new StringBuilder();
        buffer.append("ValidationContext contains ").append(revocationInfo.size()).append(" SignedToken and ").append(count)
              .append(" of them have been verified.");
        return buffer.toString();
    }

    public String toString(String indentStr) {

        int count = 0;
        StringBuilder builder = new StringBuilder();
        for (Entry<SignedToken, RevocationData> e : revocationInfo.entrySet()) {

            builder.append(indentStr).append("SignedToken[").append('\n');
            indentStr += "\t";
            builder.append(indentStr).append(e.getKey().toString(indentStr)).append('\n');
            if (e.getValue() != null) {

                builder.append(indentStr).append(e.getValue().toString(indentStr)).append('\n');
                count++;
            } else {

                builder.append(indentStr).append("NO REVOCATION DATA AVAILABLE!").append('\n');
            }
            indentStr = indentStr.substring(1);
            builder.append(indentStr).append("],\n");
        }
        StringBuilder sBuffer = new StringBuilder();
        sBuffer.append("\n").append(indentStr).append("ValidationContext contains ").append(revocationInfo.size()).append(" SignedToken and ")
              .append(count).append(" of them have been verified:\n");
        sBuffer.append(builder);
        return sBuffer.toString();
    }

    @Override
    public String toString() {

        return toString("");
    }

    private CertificateStatus getRevocationData(CertificateAndContext cac, CertificateAndContext potentialIssuer, Date validationDate,
                                                CRLSource optionalCRLSource, OCSPSource optionalOCSPSource) {

        X509Certificate cert = cac.getCertificate();
        X509Certificate issuerCert = potentialIssuer.getCertificate();
        if (optionalCRLSource != null || optionalOCSPSource != null) {

            if (LOG.isLoggable(Level.INFO)) {
                LOG.info("Verify OCSPAndCRL with offline services for " + CertificateIdentifier.getIdAsString(cert));
            }
            OCSPAndCRLCertificateVerifier verifier = new OCSPAndCRLCertificateVerifier();
            verifier.setCrlSource(optionalCRLSource);
            verifier.setOcspSource(optionalOCSPSource);
            CertificateStatus status = verifier.check(cert, issuerCert, validationDate);
            if (status != null) {

                return status;
            }
        }

        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("Verifing OCSPAndCRL with online services for " + CertificateIdentifier.getIdAsString(cert));
        }
        OCSPAndCRLCertificateVerifier onlineVerifier = new OCSPAndCRLCertificateVerifier();
        onlineVerifier.setCrlSource(crlSource);
        onlineVerifier.setOcspSource(ocspSource);
        return onlineVerifier.check(cert, issuerCert, validationDate);
    }

    /**
     * @return the neededCRL
     */
    public List<X509CRL> getNeededCRL() {

        return neededCRL;
    }

    /**
     * @return the neededOCSPResp
     */
    public List<BasicOCSPResp> getNeededOCSPResp() {

        return neededOCSPResp;
    }

    /**
     * @return Returns the list of all certificates used in the process of validation of a certificate. This list
     *         includes the certificate to check, certification chain certificates, OCSP response certificate...
     */
    public List<CertificateAndContext> getNeededCertificates() {

        return neededCertificates;
    }

    /**
     * Finds the provided certificate's issuer in the context
     *
     * @param certAndCtx The certificate whose issuer to find
     * @return the issuer's X509Certificate
     */
    public CertificateAndContext getIssuerCertificateFromThisContext(CertificateAndContext certAndCtx) {

      /* Don't search for parent of self signed certificate */
        X509Certificate cert = certAndCtx.getCertificate();
        final X500Principal certIssuerPrincipal = cert.getIssuerX500Principal();
        final X500Principal certSubjectPrincipal = cert.getSubjectX500Principal();
        if (X500PrincipalMatcher.viaAny(certSubjectPrincipal, certIssuerPrincipal)) {

            return null;
        }
      /* Ideally we should verify more thoroughly (i.e. with the signature) here */
        for (CertificateAndContext c : neededCertificates) {

            final X500Principal cSubjectPrincipal = c.getCertificate().getSubjectX500Principal();
            if (X500PrincipalMatcher.viaAny(cSubjectPrincipal, certIssuerPrincipal)) {

                return c;
            }
        }
        return null;
    }

    /**
     * Returns the CRLs in the context which concern the provided certificate. It can happen there are more than one,
     * even though this is unlikely.
     *
     * @param cert the X509 certificate
     * @return the list of CRLs related to the certificate
     */
    public List<X509CRL> getRelatedCRLs(CertificateAndContext cert) {

        List<X509CRL> crls = new ArrayList<X509CRL>();
        for (X509CRL crl : this.neededCRL) {
            final X500Principal crlPrincipal = crl.getIssuerX500Principal();
            final X500Principal certPrincipal = cert.getCertificate().getIssuerX500Principal();
            if (X500PrincipalMatcher.viaAny(crlPrincipal, certPrincipal)) {
                crls.add(crl);
            }
        }
        return crls;
    }

    /**
     * Returns the OCSP responses in the context which concern the provided certificate. It can happen there are more
     * than one, even though this is unlikely.
     *
     * @param cert the X509 certificate
     * @return the list of OCSP responses related to the certificate
     * @throws OCSPException
     */
    public List<BasicOCSPResp> getRelatedOCSPResp(CertificateAndContext cert) {

        List<BasicOCSPResp> list = new ArrayList<BasicOCSPResp>();
        for (BasicOCSPResp resp : this.neededOCSPResp) {
            if (concernsCertificate(resp, cert)) {
                list.add(resp);
            }
        }
        return list;
    }

    private boolean concernsCertificate(BasicOCSPResp basicOcspResp, CertificateAndContext cert) {

        CertificateAndContext issuerCertificate = getIssuerCertificateFromThisContext(cert);
        if (issuerCertificate == null) {
            return false;
        }

        try {
            CertificateID matchingCertID = new CertificateID(CertificateID.HASH_SHA1, issuerCertificate.getCertificate(),
                  cert.getCertificate().getSerialNumber());
            for (SingleResp resp : basicOcspResp.getResponses()) {
                if (resp.getCertID().equals(matchingCertID)) {
                    return true;
                }
            }
            return false;
        } catch (OCSPException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * @param cert
     * @return
     */
    public CertificateStatus getCertificateStatusFromContext(CertificateAndContext cert) {

        if (cert.getCertificateSource() == CertificateSourceType.TRUSTED_LIST) {

            CertificateStatus status = new CertificateStatus();
            status.setValidity(CertificateValidity.VALID);
            status.setStatusSourceType(ValidatorSourceType.TRUSTED_LIST);
            status.setCertificate(cert.getCertificate());
            return status;
        }
        CertificateAndContext issuer = getIssuerCertificateFromThisContext(cert);
        if (issuer == null) {

            return null;
        }
        // TODO by meyerfr 130201: the code below seems more reasonable: if there is nothing to check, then the status
        // should be ok, no?
        // if (false) // disabled by purpose
        // if (neededOCSPResp.isEmpty() && neededCRL.isEmpty()) {
        // CertificateStatus status = new CertificateStatus();
        // status.setValidity(CertificateValidity.VALID);
        // status.setCertificate(cert.getCertificate());
        // status.setStatusSourceType(ValidatorSourceType.OCSP);
        // return status;
        // }
        OCSPSource ocspSource = new ListOCSPSource(neededOCSPResp);
        CRLSource crlSource = new ListCRLSource(neededCRL);
        OCSPAndCRLCertificateVerifier verifier = new OCSPAndCRLCertificateVerifier();
        verifier.setCrlSource(crlSource);
        verifier.setOcspSource(ocspSource);
        return verifier.check(cert.getCertificate(), issuer.getCertificate(), getValidationDate());
    }

    /**
     * Retrieves the parent from the trusted list
     *
     * @param ctx
     * @return
     */
    public CertificateAndContext getParentFromTrustedList(CertificateAndContext ctx) {

        CertificateAndContext parent = ctx;
        while ((parent = getIssuerCertificateFromThisContext(parent)) != null) {

            if (CertificateSourceType.TRUSTED_LIST.equals(parent.getCertificateSource())) {

                LOG.info("Parent from TrustedList found " + CertificateIdentifier.getIdAsString(parent.getCertificate()));
                return parent;
            }
        }
        LOG.warning("***No issuer in the TrustedList for certificate " + CertificateIdentifier
              .getIdAsString(ctx.getCertificate()) + ". The parent found is " + parent);
        return null;
    }

    /**
     * Return the ServiceInfo of the parent (in the Trusted List) of the certificate
     *
     * @return
     */
    public ServiceInfo getRelevantServiceInfo() {

        CertificateAndContext cert = new CertificateAndContext(certificate);
        CertificateAndContext parent = getParentFromTrustedList(cert);
        if (parent == null) {

            return null;
        }
        return (ServiceInfo) parent.getContext();
    }

    /**
     * Return the qualifications statement for the signing certificate
     *
     * @return
     */
    public List<String> getQualificationStatement() {

        ServiceInfo info = getRelevantServiceInfo();
        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("Service Information " + info);
        }
        if (info == null) {
            return null;
        }
        return info.getQualifiers(new CertificateAndContext(certificate));
    }
}
