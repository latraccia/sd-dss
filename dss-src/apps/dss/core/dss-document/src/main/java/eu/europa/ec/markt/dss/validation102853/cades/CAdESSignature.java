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

package eu.europa.ec.markt.dss.validation102853.cades;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.esf.SignerAttribute;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.StoreException;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
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
import eu.europa.ec.markt.dss.validation102853.TimestampCategory;
import eu.europa.ec.markt.dss.validation102853.TimestampReference;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.bean.SigningCertificate;

/**
 * CAdES Signature class helper
 *
 * @version $Revision: 1821 $ - $Date: 2013-03-28 15:56:00 +0100 (Thu, 28 Mar 2013) $
 */

public class CAdESSignature implements AdvancedSignature {

    private static final Logger LOG = Logger.getLogger(CAdESSignature.class.getName());

    public static final ASN1ObjectIdentifier id_aa_signatureTimeStampToken = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
    public static final ASN1ObjectIdentifier id_etsi_electronicSignatureStandard = new ASN1ObjectIdentifier("0.4.0.1733");
    public static final ASN1ObjectIdentifier id_etsi_electronicSignatureStandard_attributes = id_etsi_electronicSignatureStandard.branch("2");
    public static final ASN1ObjectIdentifier id_aa_ets_certValues = PKCSObjectIdentifiers.id_aa_ets_certValues;
    public static final ASN1ObjectIdentifier id_aa_ets_revocationValues = PKCSObjectIdentifiers.id_aa_ets_revocationValues;

    /**
     * id-aa-ets-archiveTimestampV2 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
     * id-aa(2) 48}
     */
    public static final ASN1ObjectIdentifier id_aa_ets_archiveTimestampV2 = PKCSObjectIdentifiers.id_aa.branch("48");

    /**
     * id-aa-ets-archiveTimestampV3 OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0) electronic-signature-standard(1733)
     * attributes(2) 4 }
     */
    public static final ASN1ObjectIdentifier id_etsi_electronicSignatureStandard_attributes_archiveTimestampV3 = id_etsi_electronicSignatureStandard_attributes
          .branch("4");

    /**
     * id-aa-ATSHashIndex OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0) electronicsignature-standard(1733)
     * attributes(2) 5 }
     */
    public static final ASN1ObjectIdentifier id_etsi_electronicSignatureStandard_attributes_atsHashIndex = id_etsi_electronicSignatureStandard_attributes
          .branch("5");

    /**
     * This field stores the DSS internal identifier of the signature. It is used to distinguish the different signatures inside the same document.
     * Its value is auto incremental.
     */
    private static int autoSignatureId = 1;

    private final CMSSignedData cmsSignedData;

    private final SignerInformation signerInformation;

    /**
     * The reference to the signing certificate object. If the signing certificate is an input provided by the DA then
     * getSigningCert MUST be called.
     */
    private SigningCertificate signCert;

    private CAdESCertificateSource certSource;

    /**
     * The reference to the signing certificate. If the signing certificate is an input provided by the DA then
     * getSigningCer MUST be called.
     */
    private CertificateToken signingToken;

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
     * This id identifies the signature, it is calculated on the signing time if present and on the certificate.
     */
    private String signatureId;

    /**
     * @param data
     * @throws CMSException
     */
    public CAdESSignature(byte[] data) throws CMSException {

        this(new CMSSignedData(data), new CertificatePool());
    }

    /**
     * @param data
     * @param certPool can be null
     * @throws CMSException
     */
    public CAdESSignature(byte[] data, CertificatePool certPool) throws CMSException {

        this(new CMSSignedData(data), certPool);
    }

    /**
     * The default constructor for CAdESSignature.
     *
     * @param cms
     * @param certPool can be null
     */
    public CAdESSignature(CMSSignedData cms, CertificatePool certPool) {

        this(cms, (SignerInformation) cms.getSignerInfos().getSigners().iterator().next(), certPool);
    }

    /**
     * The default constructor for CAdESSignature.
     *
     * @param cms
     * @param signerInformation
     * @param certPool          can be null
     */
    public CAdESSignature(CMSSignedData cms, SignerInformation signerInformation, CertificatePool certPool) {
        this(cms, signerInformation, certPool, null);
    }

    /**
     * The default constructor for CAdESSignature.
     *
     * @param cms
     * @param signerInformation
     * @param certPool          can be null
     */
    public CAdESSignature(CMSSignedData cms, SignerInformation signerInformation, CertificatePool certPool, DSSDocument originalDocument) {
        this.cmsSignedData = cms;
        this.signerInformation = signerInformation;
        this.certPool = certPool;
    }

    /**
     * The default constructor for CAdESSignature.
     *
     * @param cms
     * @param signerInformation
     */
    public CAdESSignature(CMSSignedData cms, SignerInformation signerInformation) {
        this(cms, signerInformation, new CertificatePool());
    }

    /**
     * The default constructor for CAdESSignature.
     *
     * @param cms
     * @param id
     */
    public CAdESSignature(CMSSignedData cms, SignerId id) {
        this(cms, cms.getSignerInfos().get(id), new CertificatePool());
    }

    /**
     * The default constructor for CAdESSignature.
     *
     * @param cms
     * @param id
     * @param certPool can be null
     */
    public CAdESSignature(CMSSignedData cms, SignerId id, CertificatePool certPool) {
        this(cms, cms.getSignerInfos().get(id), certPool);
    }

    public CAdESSignature(CMSSignedData cmsSignedData, SignerInformation signerInformation, DSSDocument originalDocument) {
        this(cmsSignedData, signerInformation, new CertificatePool(), originalDocument);
    }

    /**
     * This method returns the certificate pool used by this instance to handle encapsulated certificates.
     *
     * @return
     */
    public CertificatePool getCertPool() {
        return certPool;
    }

    @Override
    public SignatureForm getSignatureFormat() {

        return SignatureForm.CAdES;
    }

    @Override
    public CAdESCertificateSource getCertificateSource() {

        if (certSource == null) {

            certSource = new CAdESCertificateSource(cmsSignedData, signerInformation.getSID(), certPool);
        }
        return certSource;
    }

    @SuppressWarnings("unchecked")
    @Override
    public ListCRLSource getCRLSource() {

        try {

            final List<X509CRL> list = new ArrayList<X509CRL>();

            // Adds CRLs contained in SignedData
            for (final CertificateList cl : (Collection<CertificateList>) cmsSignedData.getCRLs().getMatches(null)) {
                X509CRLObject crl = new X509CRLObject(cl);
                list.add(crl);
            }

            // Adds CRLs in -XL ... inside SignerInfo attribute if present
            final SignerInformationStore store = cmsSignedData.getSignerInfos();
            final SignerInformation si = store.get(signerInformation.getSID());
            if (si != null) {
                final AttributeTable attributes = si.getUnsignedAttributes();
                if (attributes != null) {
                    final Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues);
                    if (attribute != null) {
                        final ASN1Set attrValues = attribute.getAttrValues();
                        final DEREncodable attValue = attrValues.getObjectAt(0);
                        final RevocationValues revValues = RevocationValues.getInstance(attValue);

                        for (final CertificateList revValue : revValues.getCrlVals()) {
                            final X509CRLObject crl = new X509CRLObject(revValue);
                            list.add(crl);
                        }
                    }
                }
            }

            if (!list.isEmpty()) {
                return new ListCRLSource(list);
            }

        } catch (StoreException e) {
            throw new DSSException(e);
        } catch (CRLException e) {
            throw new DSSException(e);
        }

        return null;
    }

    @Override
    public ListOCSPSource getOCSPSource() {

        final List<BasicOCSPResp> list = new ArrayList<BasicOCSPResp>();

        // Adds OCSP responses in -XL certificate-values inside SignerInfo attribute if present
        final SignerInformationStore store = cmsSignedData.getSignerInfos();
        SignerInformation si = store.get(signerInformation.getSID());
        if (si != null) {
            final AttributeTable attributes = si.getUnsignedAttributes();
            if (attributes != null) {
                final Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues);
                if (attribute != null) {
                    final ASN1Set attrValues = attribute.getAttrValues();
                    final DEREncodable attValue = attrValues.getObjectAt(0);
                    final RevocationValues revValues = RevocationValues.getInstance(attValue);

                    for (final BasicOCSPResponse revValue : revValues.getOcspVals()) {
                        final BasicOCSPResp ocspResp = new BasicOCSPResp(revValue);
                        list.add(ocspResp);
                    }
                }
            }
        }

        if (!list.isEmpty()) {
            return new ListOCSPSource(list);
        }

        return null;
    }

    @Override
    public SigningCertificate getSigningCertificate() {

        if (signCert != null) {

            return signCert;
        }

        signCert = new SigningCertificate();

        // X509Certificate signCertCandidate = signerInformation.getSID().getCertificate();
        // The correct way of the identifying the signer certificate need to be implemented.
        final Collection<CertificateToken> certs = getCertificates();
        for (final CertificateToken cert : certs) {

            signCert.setDigestMatch(false);
            signCert.setSerialNumberMatch(false);

            if (!signerInformation.getSID().match(cert.getCertificate())) {
                continue;
            }

            if (LOG.isLoggable(Level.INFO)) {
                LOG.info("Signing certificate found: " + cert.getDSSIdAsString());
            }

            signingToken = cert;
            signCert.setCertToken(signingToken);
            signCert.setDigestMatch(true);
            signCert.setSerialNumberMatch(true);

            return signCert;
        }

        if (LOG.isLoggable(Level.INFO)) {
            LOG.info("!!! Signing certificate not found: " + signerInformation.getSID());
        }
        return signCert;
    }

    @Override
    public List<CertificateToken> getCertificates() {
        return getCertificateSource().getCertificates();
    }

    @Override
    public PolicyValue getPolicyId() {
        final AttributeTable attributes = signerInformation.getSignedAttributes();
        if (attributes == null) {
            return null;
        }

        Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
        if (attribute == null) {
            return null;
        }

        final DEREncodable attrValue = attribute.getAttrValues().getObjectAt(0);
        if (attrValue instanceof DERNull) {
            return new PolicyValue();
        }

        final SignaturePolicyId sigPolicy = SignaturePolicyId.getInstance(attrValue);
        if (sigPolicy == null) {
            return new PolicyValue();
        }

        return new PolicyValue(sigPolicy.getSigPolicyId().getId());
    }

    @Override
    public Date getSigningTime() {

        final AttributeTable attributes = signerInformation.getSignedAttributes();
        if (attributes == null) {
            return null;
        }

        final Attribute attr = attributes.get(PKCSObjectIdentifiers.pkcs_9_at_signingTime);
        if (attr != null) {

            ASN1Set attrValues = attr.getAttrValues();
            try {

                final DEREncodable attrValue = attrValues.getObjectAt(0);
                if (attrValue instanceof ASN1UTCTime) {
                    return ((ASN1UTCTime) attrValue).getDate();
                }
                if (attrValue instanceof Time) {
                    return ((Time) attrValue).getDate();
                }

                if (LOG.isLoggable(Level.SEVERE)) {
                    LOG.log(Level.SEVERE, "Error when reading signing time. Unrecognized " + attrValue.getClass());
                }
            } catch (Exception ex) {
                if (LOG.isLoggable(Level.SEVERE)) {
                    LOG.log(Level.SEVERE, "Error when reading signing time ", ex);
                }
            }
        }

        return null;
    }

    /**
     * @return the cmsSignedData
     */
    public CMSSignedData getCmsSignedData() {

        return cmsSignedData;
    }

    @Override
    public SignatureProductionPlace getSignatureProductionPlace() {

        final AttributeTable attributes = signerInformation.getSignedAttributes();
        if (attributes == null) {

            return null;
        }
        Attribute signatureProductionPlaceAttr = attributes.get(PKCSObjectIdentifiers.id_aa_ets_signerLocation);
        if (signatureProductionPlaceAttr == null) {

            return null;
        }
        SignerLocation signerLocation = SignerLocation.getInstance(signatureProductionPlaceAttr.getAttrValues().getObjectAt(0));
        if (signerLocation == null) {
            return null;
        }
        SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
        signatureProductionPlace.setCountryName(signerLocation.getCountryName().getString());
        signatureProductionPlace.setCity(signerLocation.getLocalityName().getString());
        StringBuilder address = new StringBuilder();
        ASN1Sequence seq = signerLocation.getPostalAddress();
        for (int ii = 0; ii < seq.size(); ii++) {

            if (seq.getObjectAt(ii) instanceof DEROctetString) {
                if (address.length() > 0) {
                    address.append("\n");
                }
                // TODO: getOctets returns an array
                address.append(new String(((DEROctetString) seq.getObjectAt(ii)).getOctets()));
            }
        }
        signatureProductionPlace.setPostalCode(address.toString());
        // This property is not used in CAdES version of signature
        // signatureProductionPlace.setStateOrProvince(stateOrProvince);
        return signatureProductionPlace;
    }

    @Override
    public String[] getClaimedSignerRoles() {

        final AttributeTable attributes = signerInformation.getSignedAttributes();
        if (attributes == null) {
            return null;
        }

        final Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_signerAttr);
        if (attribute == null) {
            return null;
        }

        final ASN1Set attrValues = attribute.getAttrValues();
        final DEREncodable attrValue = attrValues.getObjectAt(0);

        final SignerAttribute signerAttr = SignerAttribute.getInstance(attrValue);
        if (signerAttr == null) {
            return null;
        }

        final ASN1Sequence claimedAttributes = signerAttr.getClaimedAttributes();
        final String[] ret = new String[claimedAttributes.size()];
        for (int i = 0; i < claimedAttributes.size(); i++) {
            final DEREncodable claimedAttribute = claimedAttributes.getObjectAt(i);
            if (claimedAttribute instanceof DEROctetString) {
                final byte[] octets = ((DEROctetString) claimedAttribute).getOctets();
                ret[i] = new String(octets); // TODO 20130531 by meyerfr: there is no character encoding set?
            } else {
                ret[i] = claimedAttribute.toString();
            }
        }

        return ret;
    }

    private List<TimestampToken> getTimestampList(ASN1ObjectIdentifier attrType, TimestampType timestampType) {

        List<TimestampToken> list = new ArrayList<TimestampToken>();

        final AttributeTable attributes = signerInformation.getUnsignedAttributes();
        if (attributes == null) {
            return list;
        }

        final Attribute attribute = attributes.get(attrType);
        if (attribute == null) {
            return list;
        }

        final ASN1Set attrValues = attribute.getAttrValues();
        for (final ASN1Encodable value : attrValues.toArray()) {
            try {
                TimeStampToken token = new TimeStampToken(new CMSSignedData(value.getDEREncoded()));
                list.add(new TimestampToken(token, timestampType, certPool));
            } catch (Exception e) {
                throw new RuntimeException("Parsing error", e);
            }
        }

        return list;
    }

    public List<TimestampToken> getContentTimestamps() {
        return getTimestampList(PKCSObjectIdentifiers.id_aa_ets_contentTimestamp, TimestampType.CONTENT_TIMESTAMP);
    }

    @Override
    public List<TimestampToken> getSignatureTimestamps() throws RuntimeException {
        return getTimestampList(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, TimestampType.SIGNATURE_TIMESTAMP);
    }

    @Override
    public List<TimestampToken> getTimestampsX1() {
        return getTimestampList(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp, TimestampType.VALIDATION_DATA_TIMESTAMP);
    }

    @Override
    public List<TimestampToken> getTimestampsX2() {
        return getTimestampList(PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
    }

    @Override
    public List<TimestampToken> getArchiveTimestamps() {
        return getTimestampList(id_aa_ets_archiveTimestampV2, TimestampType.ARCHIVE_TIMESTAMP);
    }

    @Override
    public EncryptionAlgorithm getEncryptionAlgo() {

        String oid = signerInformation.getEncryptionAlgOID();

        try {
            return EncryptionAlgorithm.forOID(oid);
        } catch (RuntimeException e) {
            // purposely empty
        }

        // fallback to identify via signaturealgorithm
        SignatureAlgorithm signatureAlgo = SignatureAlgorithm.forOID(oid);
        return signatureAlgo.getEncryptionAlgo();
    }

    @Override
    public DigestAlgorithm getDigestAlgo() {
        return DigestAlgorithm.forOID(signerInformation.getDigestAlgOID());
    }

    @Override
    public SignatureCryptographicVerification checkIntegrity(DSSDocument detachedDocument) {

        final SignatureCryptographicVerification scv = new SignatureCryptographicVerification();
        scv.setSignatureIntegrity(false);

        try {

            SignerInformation si;
            if (detachedDocument == null) {
                si = signerInformation;
            } else {
                // Recreate a SignerInformation with the content using a CMSSignedDataParser
                final CMSSignedDataParser sp = new CMSSignedDataParser(new CMSTypedStream(detachedDocument.openStream()), cmsSignedData.getEncoded());
                sp.getSignedContent().drain();
                si = sp.getSignerInfos().get(signerInformation.getSID());
            }

            final JcaSimpleSignerInfoVerifierBuilder verifier = new JcaSimpleSignerInfoVerifierBuilder();
            boolean signatureIntact = si.verify(verifier.build(getSigningCertificate().getCertToken().getCertificate()));
            scv.setReferenceDataFound(signatureIntact);
            scv.setReferenceDataIntact(signatureIntact);
            scv.setSignatureIntegrity(signatureIntact);

        } catch (OperatorCreationException e) {
            scv.setErrorMessage(e.getMessage());
        } catch (CMSException e) {
            scv.setErrorMessage(e.getMessage());
        } catch (IOException e) {
            scv.setErrorMessage(e.getMessage());
        }
        return scv;
    }

    @Override
    public String getContentType() {
        return signerInformation.getContentType().toString();
    }

    /**
     * @return the signerInformation
     */
    public SignerInformation getSignerInformation() {
        return signerInformation;
    }

    @Override
    public List<AdvancedSignature> getCounterSignatures() {

        final List<AdvancedSignature> list = new ArrayList<AdvancedSignature>();

        for (Object o : this.signerInformation.getCounterSignatures().getSigners()) {
            SignerInformation i = (SignerInformation) o;
            CAdESSignature info = new CAdESSignature(this.cmsSignedData, i.getSID(), certPool);
            list.add(info);
        }

        return list;
    }

    @Override
    public List<CertificateRef> getCertificateRefs() {

        final List<CertificateRef> list = new ArrayList<CertificateRef>();

        final AttributeTable attributes = signerInformation.getUnsignedAttributes();
        if (attributes == null) {

            return list;
        }

        final Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs);

        if (attribute == null) {
            return list;
        }

        final ASN1Set attrValues = attribute.getAttrValues();
        if (attrValues.size() <= 0) {
            return list;
        }

        final DEREncodable attrValue = attrValues.getObjectAt(0);
        final DERSequence completeCertificateRefs = (DERSequence) attrValue;

        for (int i = 0; i < completeCertificateRefs.size(); i++) {

            final OtherCertID otherCertId = OtherCertID.getInstance(completeCertificateRefs.getObjectAt(i));
            final CertificateRef certId = new CertificateRef();
            certId.setDigestAlgorithm(otherCertId.getAlgorithmHash().getAlgorithm().getId());
            certId.setDigestValue(otherCertId.getCertHash());

            final IssuerSerial issuer = otherCertId.getIssuerSerial();
            if (issuer != null) {
                final GeneralNames issuerName = issuer.getIssuer();
                if (issuerName != null) {
                    certId.setIssuerName(issuerName.toString());
                }
                final DERInteger issuerSerial = issuer.getSerial();
                if (issuerSerial != null) {
                    certId.setIssuerSerial(issuerSerial.toString());
                }
            }
            list.add(certId);
        }
        return list;
    }

    @Override
    public List<CRLRef> getCRLRefs() {

        final List<CRLRef> list = new ArrayList<CRLRef>();

        final AttributeTable attributes = signerInformation.getUnsignedAttributes();
        if (attributes == null) {
            return list;
        }

        final Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);

        if (attribute == null) {
            return list;
        }

        final ASN1Set attrValues = attribute.getAttrValues();
        if (attrValues.size() <= 0) {
            return list;
        }

        final DEREncodable attrValue = attrValues.getObjectAt(0);
        final DERSequence completeCertificateRefs = (DERSequence) attrValue;
        for (int i = 0; i < completeCertificateRefs.size(); i++) {
            final CrlOcspRef otherCertId = CrlOcspRef.getInstance(completeCertificateRefs.getObjectAt(i));
            for (final CrlValidatedID id : otherCertId.getCrlids().getCrls()) {
                list.add(new CRLRef(id));
            }
        }

        return list;
    }

    @Override
    public List<OCSPRef> getOCSPRefs() {

        final List<OCSPRef> list = new ArrayList<OCSPRef>();

        final AttributeTable attributes = signerInformation.getUnsignedAttributes();
        if (attributes == null) {
            return list;
        }

        final Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
        if (attribute == null) {
            return list;
        }
        final ASN1Set attrValues = attribute.getAttrValues();
        if (attrValues.size() <= 0) {
            return list;
        }

        final DEREncodable attrValue = attrValues.getObjectAt(0);
        final DERSequence completeRevocationRefs = (DERSequence) attrValue;
        for (int i = 0; i < completeRevocationRefs.size(); i++) {
            final CrlOcspRef otherCertId = CrlOcspRef.getInstance(completeRevocationRefs.getObjectAt(i));
            for (final OcspResponsesID id : otherCertId.getOcspids().getOcspResponses()) {
                list.add(new OCSPRef(id, true));
            }
        }
        return list;
    }

    @Override
    public List<X509CRL> getCRLs() {
        final ListCRLSource source = getCRLSource();
        return source == null ? null : source.getContainedCRLs();
    }

    @Override
    public List<BasicOCSPResp> getOCSPs() {
        final ListOCSPSource source = getOCSPSource();
        return source == null ? null : source.getContainedOCSPResponses();
    }

    @Override
    public byte[] getSignatureTimestampData() {
        return signerInformation.getSignature();
    }

    @Override
    public byte[] getTimestampX1Data() {

        try {
            @SuppressWarnings("resource")
            final ByteArrayOutputStream data = new ByteArrayOutputStream();

            data.write(signerInformation.getSignature());

         /*
          * We don't include the outer SEQUENCE, only the attrType and attrValues as stated by the TS Â§6.3.5, NOTE 2
          */
            final AttributeTable attributes = signerInformation.getUnsignedAttributes();
            if (attributes != null) {

                final Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
                if (attribute != null) {

                    data.write(attribute.getAttrType().getDEREncoded());
                    data.write(attribute.getAttrValues().getDEREncoded());
                }
            }

         /* Those are common to Type 1 and Type 2 */
            data.write(getTimestampX2Data());

            return data.toByteArray();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public byte[] getTimestampX2Data() {

        try {
            @SuppressWarnings("resource")
            final ByteArrayOutputStream data = new ByteArrayOutputStream();

         /* Those are common to Type 1 and Type 2 */
            final AttributeTable attributes = signerInformation.getUnsignedAttributes();

            if (attributes != null) {

                final Attribute certAttribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs);
                if (certAttribute != null) {

                    data.write(certAttribute.getAttrType().getDEREncoded());
                    data.write(certAttribute.getAttrValues().getDEREncoded());
                }

                final Attribute revAttribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
                if (revAttribute != null) {

                    data.write(revAttribute.getAttrType().getDEREncoded());
                    data.write(revAttribute.getAttrValues().getDEREncoded());
                }
            }
            return data.toByteArray();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

    }

    @Override
    public byte[] getArchiveTimestampData(TimestampToken timestampToken) {

        InputStream input = null;
        try {
            final ByteArrayOutputStream data = new ByteArrayOutputStream();

            ContentInfo contentInfo = cmsSignedData.getContentInfo();
            SignedData signedData = SignedData.getInstance(contentInfo.getContent());

            /**
             * The encapContentInfo should always be present according to the standard, but sometimes it's omitted<br>
             * TODO 20130702 by bielecro: why ?<br>
             * 5.4.1
             */
            if (signedData.getEncapContentInfo() == null || signedData.getEncapContentInfo().getContent() == null) {
            /* Detached signatures have either no encapContentInfo in signedData, or it exists but has no eContent */
                // commented by Bob to be solved one day
                // if (originalDocument != null) {
                //
                // input = originalDocument.openStream();
                // data.write(input);
                // } else {
                //
                // throw new RuntimeException("Signature is detached and no original data provided.");
                // }
            } else {

                ContentInfo content = signedData.getEncapContentInfo();
                DEROctetString octet = (DEROctetString) content.getContent();

                ContentInfo info2 = new ContentInfo(PKCSObjectIdentifiers.data, new BERConstructedOctetString(octet.getOctets()));
                data.write(info2.getEncoded());
            }

            if (signedData.getCertificates() != null) {
                DEROutputStream output = new DEROutputStream(data);
                output.writeObject(signedData.getCertificates());
                output.close();
            }

            if (signedData.getCRLs() != null) {
                data.write(signedData.getCRLs().getEncoded());
            }

            final AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
            if (unsignedAttributes != null) {
                ASN1EncodableVector original = unsignedAttributes.toASN1EncodableVector();

                // TODO 20130702 by bielecro: We need to keep archive timestamps when archiving.
                // wrong interpretation of the standard need to be solved one day
                // List<Attribute> timeStampToRemove = getTimeStampToRemove(index);
                List<Attribute> timeStampToRemove = new ArrayList<Attribute>();

                ASN1EncodableVector filtered = new ASN1EncodableVector();
                for (int i = 0; i < original.size(); i++) {
                    DEREncodable enc = original.get(i);
                    if (!timeStampToRemove.contains(enc)) { // TODO 20130531 by meyerfr: is it guaranteed that this works
                        // (DEREncodable is an Attribute and can be found (via equals or
                        // ==))?
                        filtered.add(original.get(i));
                    }
                }
                SignerInformation filteredInfo = SignerInformation.replaceUnsignedAttributes(signerInformation, new AttributeTable(filtered));

                data.write(filteredInfo.toASN1Structure().getEncoded());
            }

            return data.toByteArray();

        } catch (IOException e) {
            throw new DSSException(e);
        } finally {
            DSSUtils.closeQuietly(input);
        }
    }

    // private List<Attribute> getTimeStampToRemove(int archiveTimeStampToKeep) {
    //
    // List<Attribute> list = new ArrayList<Attribute>();
    // /*
    // * We need to remove every ArchiveTimeStamp with index < index. Every timestamp is retrieved, then the list is
    // * sorted
    // */
    // if (signerInformation.getUnsignedAttributes() != null) {
    // ASN1EncodableVector v = signerInformation.getUnsignedAttributes().getAll(id_aa_ets_archiveTimestampV2);
    //
    // for (int i = 0; i < v.size(); i++) {
    // DEREncodable enc = v.get(i);
    // list.add((Attribute) enc);
    // }
    //
    // Collections.sort(list, new AttributeTimeStampComparator());
    //
    // /*
    // * TS will contain the list of TimeStamps we must remove the (index) first timestamp. The list is sorted with
    // * timestaps descending.
    // */
    // for (int i = 0; i < archiveTimeStampToKeep; i++) {
    // list.remove(0);
    // }
    //
    // }
    // return list;
    // }

    // private class AttributeTimeStampComparator implements Comparator<Attribute> {
    //
    // @Override
    // public int compare(Attribute o1, Attribute o2) {
    // try {
    // final byte[] data1 = o1.getAttrValues().getObjectAt(0).getDERObject().getDEREncoded();
    // TimeStampToken t1 = new TimeStampToken(new CMSSignedData(data1));
    // final byte[] data2 = o2.getAttrValues().getObjectAt(0).getDERObject().getDEREncoded();
    // TimeStampToken t2 = new TimeStampToken(new CMSSignedData(data2));
    // final Date time1 = t1.getTimeStampInfo().getGenTime();
    // final Date time2 = t2.getTimeStampInfo().getGenTime();
    // return -time1.compareTo(time2);
    // } catch (Exception e) {
    // throw new RuntimeException("Cannot read original ArchiveTimeStamp", e);
    // }
    // }
    // }

    @Override
    public String getId() {

        try {

            if (signatureId == null) {

                signatureId = "id-" + String.format("%05d", autoSignatureId++);;
            }
            return signatureId;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public List<TimestampReference> getTimestampedReferences() {

        final List<TimestampReference> references = new ArrayList<TimestampReference>();
        final List<CertificateRef> certRefs = getCertificateRefs();
        for (final CertificateRef certificateRef : certRefs) {

            final String digestValue = DSSUtils.base64Encode(certificateRef.getDigestValue());
            TimestampReference reference = new TimestampReference();
            reference.setCategory(TimestampCategory.CERTIFICATE);
            DigestAlgorithm digestAlgorithmObj = DigestAlgorithm.forOID(certificateRef.getDigestAlgorithm());
            reference.setDigestAlgorithm(certificateRef.getDigestAlgorithm());
            if (!usedCertificatesDigestAlgorithms.contains(digestAlgorithmObj)) {

                usedCertificatesDigestAlgorithms.add(digestAlgorithmObj);
            }
            reference.setDigestValue(digestValue);
            references.add(reference);
        }

        final List<OCSPRef> ocspRefs = getOCSPRefs();
        for (final OCSPRef ocspRef : ocspRefs) {

            final String digestValue = DSSUtils.base64Encode(ocspRef.getDigestValue());
            TimestampReference reference = new TimestampReference();
            reference.setCategory(TimestampCategory.REVOCATION);
            reference.setDigestAlgorithm(ocspRef.getDigestAlgorithm());
            reference.setDigestValue(digestValue);
            references.add(reference);
        }

        final List<CRLRef> crlRefs = getCRLRefs();
        for (final CRLRef crlRef : crlRefs) {

            final String digestValue = DSSUtils.base64Encode(crlRef.getDigestValue());
            TimestampReference reference = new TimestampReference();
            reference.setCategory(TimestampCategory.REVOCATION);
            reference.setDigestAlgorithm(crlRef.getDigestAlgorithm());
            reference.setDigestValue(digestValue);
            references.add(reference);
        }
        return references;
    }

    @Override
    public Set<DigestAlgorithm> getUsedCertificatesDigestAlgorithms() {

        return usedCertificatesDigestAlgorithms;
    }

    /**
     * @param signerInformation
     * @return the existing unsigned attributes or an empty attributes hashtable
     */
    public static AttributeTable getUnsignedAttributes(final SignerInformation signerInformation) {
        final AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes == null) {
            return new AttributeTable(new Hashtable<ASN1ObjectIdentifier, Attribute>());
        } else {
            return unsignedAttributes;
        }
    }

    /**
     * @param signerInformation
     * @return the existing signed attributes or an empty attributes hashtable
     */
    public static AttributeTable getSignedAttributes(final SignerInformation signerInformation) {
        final AttributeTable signedAttributes = signerInformation.getSignedAttributes();
        if (signedAttributes == null) {
            return new AttributeTable(new Hashtable<ASN1ObjectIdentifier, Attribute>());
        } else {
            return signedAttributes;
        }
    }

    public boolean isLevelReached(SignatureFormat signatureFormat) {
//        final AttributeTable unsignedAttributes = getUnsignedAttributes(signerInformation);
//        final AttributeTable signedAttributes = getSignedAttributes(signerInformation);
//        boolean levelReached;
//        switch (signatureFormat) {
//            case CAdES_BASELINE_B:
//                levelReached = signedAttributes.get(PKCSObjectIdentifiers.id_aa_signingCertificate) != null;
//                break;
//            case CAdES_BASELINE_T:
//                levelReached = unsignedAttributes.get(id_aa_signatureTimeStampToken) != null;
//                break;
//            case CAdES_BASELINE_LT:
//                if (unsignedAttributes.get(id_aa_ets_certValues) != null) {
//                    levelReached = true;
//                } else {
//                    levelReached = unsignedAttributes.get(id_aa_ets_revocationValues) != null;
//                }
//                break;
//            case CAdES_BASELINE_LTA:
//                levelReached = unsignedAttributes.get(id_etsi_electronicSignatureStandard_attributes_archiveTimestampV3) != null;
//                break;
//            default:
//                throw new IllegalArgumentException("Unknown level " + signatureFormat);
//        }
//        return levelReached;
        return false;
    }
}