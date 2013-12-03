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

package eu.europa.ec.markt.dss.validation102853.pades;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PdfArray;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureInfo;
import eu.europa.ec.markt.dss.signature.pdf.SignatureValidationCallback;
import eu.europa.ec.markt.dss.validation.CRLRef;
import eu.europa.ec.markt.dss.validation.CertificateRef;
import eu.europa.ec.markt.dss.validation.OCSPRef;
import eu.europa.ec.markt.dss.validation.PolicyValue;
import eu.europa.ec.markt.dss.validation.SignatureForm;
import eu.europa.ec.markt.dss.validation.crl.ListCRLSource;
import eu.europa.ec.markt.dss.validation.ocsp.ListOCSPSource;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CAdESCertificateSource;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.TimestampReference;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.bean.SigningCertificate;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;

/**
 * Implementation of AdvancedSignature for PAdES
 *
 * @version $Revision: 1849 $ - $Date: 2013-04-04 17:51:32 +0200 (Thu, 04 Apr 2013) $
 */
public class PAdESSignature implements AdvancedSignature {

    private static final Logger LOG = Logger.getLogger(PAdESSignature.class.getName());

    private final DSSDocument document;
    private final PdfDict pdfCatalog;

    private final PdfDict outerCatalog;

    private final PdfDict signatureDictionary;

    private final CAdESSignature cadesSignature;

    private final PdfSignatureInfo pk;

    private PAdESCertificateSource padesCertSources;

    /**
     * This is the reference to the global (external) pool of certificates. All encapsulated certificates in the signature are added
     * to this pool. See {@link CertificatePool}
     */
    private CertificatePool certPool;

    /**
     * This list represents all digest algorithms used to calculate the digest values of certificates.
     */
    private Set<DigestAlgorithm> usedCertificatesDigestAlgorithms = new HashSet<DigestAlgorithm>();

    /**
     * The default constructor for PAdESSignature.
     *
     * @param document
     * @param pdfCatalog          The catalogue of the PDF that enable to access the document that contains the PAdES signature.
     * @param outerCatalog
     * @param signatureDictionary
     * @param pk
     * @throws CMSException
     * @throws IOException
     */
    public PAdESSignature(DSSDocument document, final PdfDict pdfCatalog, final PdfDict outerCatalog, final PdfDict signatureDictionary,
                          final PdfSignatureInfo pk, final CertificatePool certPool) throws CMSException, IOException {
        this.document = document;
        this.pdfCatalog = pdfCatalog;
        this.outerCatalog = outerCatalog;
        this.signatureDictionary = signatureDictionary;
        this.cadesSignature = new CAdESSignature(signatureDictionary.get("Contents"), certPool);
        this.certPool = certPool;
        this.pk = pk;
    }

    @Override
    public SignatureForm getSignatureFormat() {

        return SignatureForm.PAdES;
    }

    @Override
    public EncryptionAlgorithm getEncryptionAlgo() {

        return cadesSignature.getEncryptionAlgo();
    }

    @Override
    public DigestAlgorithm getDigestAlgo() {

        return cadesSignature.getDigestAlgo();
    }

    @Override
    public PAdESCertificateSource getCertificateSource() {

        if (padesCertSources == null) {

            CAdESCertificateSource cadesCertSource = cadesSignature.getCertificateSource();
            PdfDict dico = outerCatalog != null ? outerCatalog : pdfCatalog;
            padesCertSources = new PAdESCertificateSource(dico, cadesCertSource, certPool);
        }
        return padesCertSources;
    }

    private PdfDict getDSSDictionary() {
        PdfDict catalog = outerCatalog != null ? outerCatalog : pdfCatalog;
        return catalog.getAsDict("DSS");
    }

    @Override
    public ListCRLSource getCRLSource() {

        PdfDict dss = getDSSDictionary();
        try {

            List<X509CRL> list = new ArrayList<X509CRL>();
            if (dss != null) {

                PdfArray crlArray = dss.getAsArray("CRLs");
                if (crlArray != null) {

                    CertificateFactory factory = CertificateFactory.getInstance("X509");
                    for (int i = 0; i < crlArray.size(); i++) {

                        byte[] stream = crlArray.getBytes(i);
                        X509CRL cert = (X509CRL) factory.generateCRL(new ByteArrayInputStream(stream));
                        if (!list.contains(cert)) {

                            list.add(cert);
                        }
                    }
                }
            }
            if (list.size() > 0) {
                return new ListCRLSource(list);
            }
        } catch (IOException ex) {

            throw new DSSException(ex);
        } catch (CertificateException e) {

            throw new DSSException(e);
        } catch (CRLException e) {

            throw new DSSException(e);
        }
        return null;
    }

    @Override
    public ListOCSPSource getOCSPSource() {
        PdfDict dss = getDSSDictionary();
        try {

            List<BasicOCSPResp> list = new ArrayList<BasicOCSPResp>();
            if (dss != null) {

                PdfArray ocspArray = dss.getAsArray("OCSPs");
                if (ocspArray != null) {

                    for (int i = 0; i < ocspArray.size(); i++) {

                        byte[] stream = ocspArray.getBytes(i);
                        list.add((BasicOCSPResp) new OCSPResp(stream).getResponseObject());
                    }
                }
            }
            if (list.size() > 0) {
                return new ListOCSPSource(list);
            }
        } catch (IOException e) {

            throw new DSSException(e);
        } catch (OCSPException e) {

            throw new DSSException(e);
        }
        return null;
    }

    @Override
    public SigningCertificate getSigningCertificate() {

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
    public SignatureProductionPlace getSignatureProductionPlace() {

        String location = pk.getLocation();
        if (location == null || location.trim().length() == 0) {

            return cadesSignature.getSignatureProductionPlace();
        } else {
            SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
            signatureProductionPlace.setCountryName(location);
            return signatureProductionPlace;
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
    public List<TimestampToken> getContentTimestamps() {

        return cadesSignature.getContentTimestamps();
    }

    @Override
    public List<TimestampToken> getSignatureTimestamps() {
        //TODO: check if that returns document-time-stamp PDF ? --> no --> how to find it ?
        //TODO: must return only if it is a level T timetamp
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
        //TODO: return only if a level LTA timetamp
        return Collections.emptyList();
    }

    @Override
    public List<CertificateToken> getCertificates() {
        return getCertificateSource().getCertificates();
    }

    @Override
    public SignatureCryptographicVerification checkIntegrity(DSSDocument document) {

        SignatureCryptographicVerification scv = new SignatureCryptographicVerification();
        try {
            if (signatureDictionary.hasANameWithValue("SubFilter", "ETSI.RFC3161")) {
                /**
                 * ETSI TS 102 778-4 V1.1.1 (2009-07)<br>
                 * When the value of Type is DocTimestamp, the value of SubFilter shall be ETSI.RFC 3161.
                 */
                // final byte[] contents = signatureDictionary.get("Content");
                // TimeStampToken timestampToken =  new TimeStampToken(new CMSSignedData(contents));
                //TODO: adapt to handle pk of type ETSI.RFC3161. This pk.verify doesn't work.
                scv.setSignatureIntegrity(pk.verify());
            } else {
                scv.setSignatureIntegrity(pk.verify());
            }
            scv.setReferenceDataFound(scv.isSignatureIntact());
            scv.setReferenceDataIntact(scv.isSignatureIntact());
        } catch (Exception e) {

            LOG.log(Level.WARNING, "Could not check integrity", e);
            scv.setErrorMessage(e.getMessage());
        }
        return scv;
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

        ListCRLSource source = getCRLSource();
        return source == null ? null : source.getContainedCRLs();
    }

    @Override
    public List<BasicOCSPResp> getOCSPs() {

        ListOCSPSource source = getOCSPSource();
        return source == null ? null : source.getContainedOCSPResponses();
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
     * @return the pdfReader catalogue corresponding to the revision of the document covered by the signature
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
     * @return the "outer" catalogue outside the document covered by this signature
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
    public byte[] getArchiveTimestampData(TimestampToken timestampToken) {

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
            digest.update(getSigningCertificate().getCertToken().getCertificate().getEncoded());
            return Hex.encodeHexString(digest.digest());
        } catch (Exception e) {

            throw new RuntimeException(e);
        }
    }

    @Override
    public List<TimestampReference> getTimestampedReferences() {

      /* Not applicable for PAdES */
        return Collections.emptyList();
    }

    @Override
    public Set<DigestAlgorithm> getUsedCertificatesDigestAlgorithms() {

        return usedCertificatesDigestAlgorithms;
    }

    public boolean isLevelReached(SignatureFormat signatureFormat) {
        boolean levelReached = false;
/*
        switch (signatureFormat) {
            case PAdES_BASELINE_B:
                levelReached = (pk != null);
                break;
            case PAdES_BASELINE_T:
                levelReached = isLevelReached(SignatureFormat.PAdES_BASELINE_B);
                if (levelReached) {
                    final List<TimestampToken> signatureTimestamps = getSignatureTimestamps();
                    levelReached = ((signatureTimestamps != null) && (!signatureTimestamps.isEmpty()));
                    if (!levelReached) {
                        levelReached = hasDocumentTimestamp();
                    }
                }
                break;
            case PAdES_BASELINE_LT:
                levelReached = isLevelReached(SignatureFormat.PAdES_BASELINE_T);
                if (levelReached) {
                    levelReached = hasDSSDictionary();
                } else {
                    levelReached = false;
                }
                break;
            case PAdES_BASELINE_LTV:
                levelReached = isLevelReached(SignatureFormat.PAdES_BASELINE_LT);
                if (levelReached) {
                    levelReached = hasDocumentTimestamp();
                }
                break;
            default:
                throw new IllegalArgumentException("Unknown level " + signatureFormat);
        }
        LOG.log(Level.FINE, "Level {0} found on document {1} = {2}", new Object[]{signatureFormat, document.getName(), levelReached});
*/
        return levelReached;
    }

    private boolean hasDSSDictionary() {
        boolean hasDSSDictionary;
        final PDFSignatureService pdfTimestampSignatureService = PdfObjFactory.getInstance().newTimestampSignatureService();
        try {
            final AtomicBoolean atomicHasDSSDictionnary = new AtomicBoolean(false);
            pdfTimestampSignatureService.validateSignatures(document.openStream(), new SignatureValidationCallback() {
                @Override
                public void validate(PdfDict catalog, PdfDict outerCatalog, X509Certificate signingCert, Date signingDate, Certificate[] certs,
                                     PdfDict signatureDictionary, PdfSignatureInfo pk) {
                    PdfDict _catalog = outerCatalog != null ? outerCatalog : pdfCatalog;
                    if (_catalog != null) {
                        atomicHasDSSDictionnary
                              .set((getCertificateSource() != null) && (getCertificateSource().getCertificates() != null) && (!getCertificateSource()
                                    .getCertificates().isEmpty()));
                    }
                }
            });
            hasDSSDictionary = atomicHasDSSDictionnary.get();
        } catch (IOException e) {
            throw new DSSException(e);
        } catch (SignatureException e) {
            throw new DSSException(e);
        }
        return hasDSSDictionary;
    }

    private boolean hasDocumentTimestamp() {
        boolean levelReached;
        final PDFSignatureService pdfTimestampSignatureService = PdfObjFactory.getInstance().newTimestampSignatureService();
        try {
            final AtomicBoolean atomicLevelReached = new AtomicBoolean(false);
            pdfTimestampSignatureService.validateSignatures(document.openStream(), new SignatureValidationCallback() {
                @Override
                public void validate(PdfDict catalog, PdfDict outerCatalog, X509Certificate signingCert, Date signingDate, Certificate[] certs,
                                     PdfDict signatureDictionary, PdfSignatureInfo pk) {
                    try {
                        final byte[] subFilters = signatureDictionary.get("SubFilter");
                        if (subFilters != null) {
                            String pdfSubFilter = new String(subFilters); //
                            if (StringUtils.equals("/ETSI.RFC3161", pdfSubFilter)) {
                                atomicLevelReached.set(true);
                            }
                        }
                    } catch (IOException e) {
                        throw new DSSException(e);
                    }
                }
            });
            levelReached = atomicLevelReached.get();
        } catch (IOException e) {
            throw new DSSException(e);
        } catch (SignatureException e) {
            throw new DSSException(e);
        }
        return levelReached;
    }
}
