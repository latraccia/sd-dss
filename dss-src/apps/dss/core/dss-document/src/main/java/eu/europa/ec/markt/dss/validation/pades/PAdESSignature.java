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

package eu.europa.ec.markt.dss.validation.pades;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.ocsp.BasicOCSPResp;

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureInfo;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.CRLRef;
import eu.europa.ec.markt.dss.validation.CertificateRef;
import eu.europa.ec.markt.dss.validation.OCSPRef;
import eu.europa.ec.markt.dss.validation.PolicyValue;
import eu.europa.ec.markt.dss.validation.SignatureForm;
import eu.europa.ec.markt.dss.validation.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.certificate.CompositeCertificateSource;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;

/**
 * Implementation of AdvancedSignature for PAdES
 *
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */

public class PAdESSignature implements AdvancedSignature {

    private static final Logger LOG = Logger.getLogger(PAdESSignature.class.getName());

    private final PdfDict pdfCatalog;
    private final PdfDict outerCatalog;
    private final PdfDict signatureDictionary;

    private final CAdESSignature cadesSignature;

    private final PdfSignatureInfo pk;

    /**
     * The default constructor for PAdESSignature.
     *
     * @param pdfCatalog          The catalogue of the PDF that enable to access the document that contains the PAdES signature.
     * @param outerCatalog
     * @param signatureDictionary
     * @param pk
     * @throws CMSException
     * @throws IOException
     */
    public PAdESSignature(PdfDict pdfCatalog, PdfDict outerCatalog, PdfDict signatureDictionary,
                          PdfSignatureInfo pk) throws CMSException, IOException {
        this.pdfCatalog = pdfCatalog;
        this.outerCatalog = outerCatalog;
        this.signatureDictionary = signatureDictionary;
        cadesSignature = new CAdESSignature(signatureDictionary.get("Contents"));
        this.pk = pk;
    }

    @Override
    public SignatureForm getSignatureFormat() {
        return SignatureForm.PAdES;
    }

    @Override
    public String getSignatureAlgorithm() {
        if (cadesSignature == null) {
            return null;
        }
        return cadesSignature.getSignatureAlgorithm();
    }

    @Override
    public CertificateSource getCertificateSource() {
        return new CompositeCertificateSource(cadesSignature.getCertificateSource(),
              (outerCatalog != null) ? new PAdESCertificateSource(outerCatalog) : new PAdESCertificateSource(pdfCatalog));
    }

    @Override
    public PAdESCertificateSource getExtendedCertificateSource() {
        return (outerCatalog != null) ? new PAdESCertificateSource(outerCatalog) : new PAdESCertificateSource(pdfCatalog);
    }

    @Override
    public PAdESCRLSource getCRLSource() {
        return (outerCatalog != null) ? new PAdESCRLSource(outerCatalog) : new PAdESCRLSource(pdfCatalog);
    }

    @Override
    public PAdESOCSPSource getOCSPSource() {
        return (outerCatalog != null) ? new PAdESOCSPSource(outerCatalog) : new PAdESOCSPSource(pdfCatalog);
    }

    @Override
    public X509Certificate getSigningCertificate() {
        return cadesSignature.getSigningCertificate();
    }

    @Override
    public Date getSigningTime() {
        Date date = null;
        if (pk.getSigningDate() != null) {
            date = pk.getSigningDate();
        }
        if (date == null) {
            return cadesSignature.getSigningTime();
        } else {
            return date;
        }
    }

    @Override
    public PolicyValue getPolicyId() {
        return cadesSignature.getPolicyId();
    }

    @Override
    public String getLocation() {
        String location = pk.getLocation();
        if (location == null || location.trim().length() == 0) {
            return cadesSignature.getLocation();
        } else {
            return location;
        }
    }

    @Override
    public String getContentType() {
        return "application/pdf";
    }

    @Override
    public String[] getClaimedSignerRoles() {
        return cadesSignature.getClaimedSignerRoles();
    }

    @Override
    public List<TimestampToken> getSignatureTimestamps() {
        return cadesSignature.getSignatureTimestamps();
    }

    @Override
    public List<TimestampToken> getTimestampsX1() {
      /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<TimestampToken> getTimestampsX2() {
      /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<TimestampToken> getArchiveTimestamps() {
      /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<X509Certificate> getCertificates() {
        return cadesSignature.getCertificates();
    }

    @Override
    public boolean checkIntegrity(DSSDocument document) {

        try {

            /**
             * ETSI TS 102 778-4 V1.1.1 (2009-07)<br>
             * When the value of Type is DocTimestamp, the value of SubFilter shall be ETSI.RFC 3161.
             */
            if (signatureDictionary.hasANameWithValue("SubFilter", "ETSI.RFC3161")) {

                return pk.verify();
            } else {

                return pk.verify();
            }
        } catch (Exception e) {

            LOG.log(Level.WARNING, "Coulnd not check integrity", e);
            return false;
        }
    }

    @Override
    public List<AdvancedSignature> getCounterSignatures() {
      /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<CertificateRef> getCertificateRefs() {
      /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<CRLRef> getCRLRefs() {
      /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<OCSPRef> getOCSPRefs() {
      /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<X509CRL> getCRLs() {
        return getCRLSource().getContainedCRLs();
    }

    @Override
    public List<BasicOCSPResp> getOCSPs() {
        return getOCSPSource().getContainedOCSPResponses();
    }

    @Override
    public byte[] getSignatureTimestampData() {
        return cadesSignature.getSignatureTimestampData();
    }

    @Override
    public byte[] getTimestampX1Data() {
      /* Not applicable for PAdES */
        return null;
    }

    @Override
    public byte[] getTimestampX2Data() {
      /* Not applicable for PAdES */
        return null;
    }

    /**
     * @return the pdfReader catalog corresponding to the revision of the document covered by the signature
     */
    public PdfDict getPdfCatalog() {
        return pdfCatalog;
    }

    /**
     * @return the CAdES signature underlying this PAdES signature
     */
    public CAdESSignature getCAdESSignature() {
        return cadesSignature;
    }

    /**
     * @return the "outer" catalog outside the document covered by this signature
     */
    public PdfDict getOuterCatalog() {
        return outerCatalog;
    }

    /**
     * @return the signature dictionary containing the bytes
     */
    public PdfDict getSignatureDictionary() {
        return signatureDictionary;
    }

    @Override
    public byte[] getArchiveTimestampData(int index, DSSDocument originalData) {
      /* Not applicable for PAdES */
        return null;
    }

    @Override
    public String getId() {
        try {

            MessageDigest digest = MessageDigest.getInstance("MD5");
            if (getSigningTime() != null) {
                digest.update(Long.toString(getSigningTime().getTime()).getBytes());
            }
            digest.update(getSigningCertificate().getEncoded());
            return Hex.encodeHexString(digest.digest());
        } catch (Exception e) {

            throw new RuntimeException(e);
        }
    }

}
