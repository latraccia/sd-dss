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

package eu.europa.ec.markt.dss.validation102853.xades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.Data;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.EncodingException;
import eu.europa.ec.markt.dss.exception.EncodingException.MSG;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.signature.xades.ExternalFileURIDereferencer;
import eu.europa.ec.markt.dss.validation.CRLRef;
import eu.europa.ec.markt.dss.validation.CertificateRef;
import eu.europa.ec.markt.dss.validation.OCSPRef;
import eu.europa.ec.markt.dss.validation.PolicyValue;
import eu.europa.ec.markt.dss.validation.SignatureForm;
import eu.europa.ec.markt.dss.validation.crl.ListCRLSource;
import eu.europa.ec.markt.dss.validation.ocsp.ListOCSPSource;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.ArchiveTimestampType;
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
 * Parse an XAdES structure
 *
 * @version $Revision: 1825 $ - $Date: 2013-03-28 15:57:37 +0100 (Thu, 28 Mar 2013) $
 */

public class XAdESSignature implements AdvancedSignature {

    private static final Logger LOG = Logger.getLogger(XAdESSignature.class.getName());

    public static final String XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";

    public static final String XADES_COUNTERSIGNED_SIGNATURE = "http://uri.etsi.org/01903#CountersignedSignature";

    /**
     * This is the default canonicalization method for XMLDSIG used for timestamps.
     */
    public static final String XMLDSIG_DEFAULT_CANONICALIZATION_METHOD = CanonicalizationMethod.INCLUSIVE;

    public static final String XMLE_SIGNATURE = "Signature";
    public static final String XMLE_ALGORITHM = "Algorithm";

    public static final String XMLE_CITY = "City";
    public static final String XMLE_STATE_OR_PROVINCE = "StateOrProvince";
    public static final String XMLE_POSTAL_CODE = "PostalCode";
    public static final String XMLE_COUNTRY_NAME = "CountryName";

    public static final String XMLE_ARCHIVE_TIME_STAMP = "ArchiveTimeStamp";
    public static final String XMLE_ARCHIVE_TIME_STAMP_V2 = "ArchiveTimeStampV2";

    public static final String XPATH_SIGNATURE = "./ds:Signature";
    public static final String XPATH_SIGNED_INFO = "./ds:SignedInfo";
    public static final String XPATH_SIGNATURE_METHOD = XPATH_SIGNED_INFO + "/ds:SignatureMethod";
    public static final String XPATH_SIGNATURE_VALUE = "./ds:SignatureValue";
    public static final String XPATH_KEY_INFO = "./ds:KeyInfo";
    public static final String XPATH_X509_DATA = XPATH_KEY_INFO + "/ds:X509Data";

    public static final String XPATH_KEY_INFO_X509_CERTIFICATE = XPATH_X509_DATA + "/ds:X509Certificate";
    public static final String XPATH_X509_ISSUER_SERIAL = XPATH_X509_DATA + "/ds:X509IssuerSerial";

    public static final String XPATH_OBJECT = "./ds:Object";
    public static final String XPATH_QUALIFYING_PROPERTIES = XPATH_OBJECT + "/xades:QualifyingProperties";

    public static final String XPATH_SIGNED_PROPERTIES = XPATH_QUALIFYING_PROPERTIES + "/xades:SignedProperties";
    public static final String XPATH_SIGNED_SIGNATURE_PROPERTIES = XPATH_SIGNED_PROPERTIES + "/xades:SignedSignatureProperties";
    public static final String XPATH_ALL_DATA_OBJECT_TIMESTAMP = XPATH_SIGNED_PROPERTIES + "/xades:SignedDataObjectProperties/xades:AllDataObjectsTimeStamp";
    public static final String XPATH_SIGNING_TIME = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SigningTime";
    public static final String XPATH_SIGNING_CERTIFICATE_CERT = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SigningCertificate/xades:Cert";
    public static final String XPATH_CERT_DIGEST = XPATH_SIGNING_CERTIFICATE_CERT + "/xades:CertDigest";
    public static final String XPATH_SIGNATURE_POLICY_IDENTIFIER = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SignaturePolicyIdentifier";
    public static final String XPATH_CLAIMED_ROLE = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole";
    public static final String XPATH_PRODUCTION_PLACE = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SignatureProductionPlace";
    public static final String XPATH__SIGNATURE_POLICY_ID = "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier";

    public static final String XPATH__X509_ISSUER_NAME = "./xades:IssuerSerial/ds:X509IssuerName";
    public static final String XPATH__X509_SERIAL_NUMBER = "./xades:IssuerSerial/ds:X509SerialNumber";
    public static final String XPATH__DIGEST_METHOD = "./xades:CertDigest/ds:DigestMethod";
    public static final String XPATH__DIGEST_VALUE = "./ds:DigestValue";
    public static final String XPATH__CERT_DIGEST_DIGEST_VALUE = "./xades:CertDigest/ds:DigestValue";

    public static final String XPATH_UNSIGNED_PROPERTIES = XPATH_QUALIFYING_PROPERTIES + "/xades:UnsignedProperties";
    public static final String XPATH_UNSIGNED_SIGNATURE_PROPERTIES = XPATH_UNSIGNED_PROPERTIES + "/xades:UnsignedSignatureProperties";
    public static final String XPATH_SIGNATURE_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:SignatureTimeStamp";
    public static final String XPATH_SIGNATURE_TIMESTAMP_CANON = XPATH_SIGNATURE_TIMESTAMP + "/ds:CanonicalizationMethod";
    public static final String XPATH_COMPLETE_CERTIFICATE_REFS = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:CompleteCertificateRefs";
    public static final String XPATH_COMPLETE_REVOCATION_REFS = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:CompleteRevocationRefs";
    public static final String XPATH_SIG_AND_REFS_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:SigAndRefsTimeStamp";
    public static final String XPATH_SIG_AND_REFS_TIMESTAMP_CANON = XPATH_SIG_AND_REFS_TIMESTAMP + "/ds:CanonicalizationMethod";
    public static final String XPATH_REFS_ONLY_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:RefsOnlyTimeStamp";
    public static final String XPATH_REFS_ONLY_TIMESTAMP_CANON = XPATH_REFS_ONLY_TIMESTAMP + "/ds:CanonicalizationMethod";
    public static final String XPATH_CERTIFICATE_VALUES = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:CertificateValues";
    public static final String XPATH_REVOCATION_VALUES = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:RevocationValues";
    public static final String XPATH_COUNTER_SIGNATURE = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:CounterSignature";
    public static final String XPATH_ARCHIVE_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:" + XMLE_ARCHIVE_TIME_STAMP;
    public static final String XPATH_ARCHIVE_TIMESTAMP_141 = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades141:" + XMLE_ARCHIVE_TIME_STAMP;
    public static final String XPATH_ARCHIVE_TIMESTAMP_V2 = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades141:" + XMLE_ARCHIVE_TIME_STAMP_V2;
    public static final String XPATH_REVOCATION_CRL_REFS = XPATH_COMPLETE_REVOCATION_REFS + "/xades:CRLRefs";

    public static final String XPATH__DIGEST_METHOD_ALGORITHM = "./ds:DigestMethod/@Algorithm";

    public static final String XPATH__CRL_REF = "./xades:CRLRef";
    public static final String XPATH__COMPLETE_CERTIFICATE_REFS__CERT_DIGEST = "./xades:CertRefs/xades:Cert/xades:CertDigest";
    public static final String XPATH__DAAV_DIGEST_METHOD = "./xades:DigestAlgAndValue/ds:DigestMethod";
    public static final String XPATH__DAAV_DIGEST_VALUE = "./xades:DigestAlgAndValue/ds:DigestValue";
    public static final String XPATH__CANONICALIZATION_METHOD = "./ds:CanonicalizationMethod";
    public static final String XPATH__ENCAPSULATED_TIMESTAMP = "./xades:EncapsulatedTimeStamp";

    public static final String XPATH_ENCAPSULATED_X509_CERTIFICATE = XPATH_CERTIFICATE_VALUES + "/xades:EncapsulatedX509Certificate";

    public static final String XPATH_CERT_REFS = XPATH_COMPLETE_CERTIFICATE_REFS + "/xades:CertRefs";

    public static final String XPATH_ENCAPSULATED_CRL_VALUE = XPATH_REVOCATION_VALUES + "/xades:CRLValues/xades:EncapsulatedCRLValue";
    public static final String XPATH_ENCAPSULATED_OCSP_VALUE = XPATH_REVOCATION_VALUES + "/xades:OCSPValues/xades:EncapsulatedOCSPValue";

    private final Element signatureElement;

    /**
     * Used in validation process
     */
    private final XMLDSigRI xmlProvider = new XMLDSigRI();

    Element qualifyingProperties;
    Element unsignedProperties;
    Element unsignedSignatureProperties;

    /**
     * Indicates the id of the signature. If not existing this attribute is auto calculated.
     */
    private String id;

    /**
     * The reference to the signing certificate object. If the signing certificate is an input provided by the DA then
     * getSigningCert MUST be called.
     */
    private SigningCertificate signingCert;

    private XAdESCertificateSource certificatesSource;

    /**
     * This is the reference to the global (external) pool of certificates. All encapsulated certificates in the signature are added
     * to this pool. See {@link CertificatePool}
     */
    private CertificatePool certPool;

    /**
     * This attribute is used when validate the ArchiveTimeStamp (XAdES-A).
     */
    private ByteArrayOutputStream referencesDigestOutputStream = new ByteArrayOutputStream();

    /**
     * This list represents all digest algorithms used to calculate the digest values of certificates.
     */
    private Set<DigestAlgorithm> usedCertificatesDigestAlgorithms = new HashSet<DigestAlgorithm>();

    static {

        Init.init();
    }

    /**
     * The default constructor for XAdESSignature.
     *
     * @param signatureElement w3c.dom signature element
     * @param certPool         can be null
     */
    public XAdESSignature(final Element signatureElement, CertificatePool certPool) {

        if (signatureElement == null) {

            throw new DSSException("DOM signature element is null, it must be provided!");
        }
        this.signatureElement = signatureElement;
        this.certPool = certPool;
    }

    /**
     * This method returns the certificate pool used by this instance to handle encapsulated certificates.
     *
     * @return
     */
    public CertificatePool getCertPool() {
        return certPool;
    }

    /**
     * Returns the w3c.dom encapsulated signature element.
     *
     * @return the signatureElement
     */
    public Element getSignatureElement() {

        return signatureElement;
    }

    @Override
    public SignatureForm getSignatureFormat() {

        return SignatureForm.XAdES;
    }

    @Override
    public EncryptionAlgorithm getEncryptionAlgo() {

        final String xmlName = DSSXMLUtils.getElement(signatureElement, XPATH_SIGNATURE_METHOD).getAttribute(XMLE_ALGORITHM);
        final SignatureAlgorithm signatureAlgo = SignatureAlgorithm.forXML(xmlName);
        return signatureAlgo.getEncryptionAlgo();
    }

    @Override
    public DigestAlgorithm getDigestAlgo() {

        final String xmlName = DSSXMLUtils.getElement(signatureElement, XPATH_SIGNATURE_METHOD).getAttribute(XMLE_ALGORITHM);
        final SignatureAlgorithm signatureAlgo = SignatureAlgorithm.forXML(xmlName);
        return signatureAlgo.getDigestAlgo();
    }

    @Override
    public XAdESCertificateSource getCertificateSource() {

        if (certificatesSource == null) {

            certificatesSource = new XAdESCertificateSource(signatureElement, certPool);
        }
        return certificatesSource;
    }

    @Override
    public ListCRLSource getCRLSource() {

        final List<X509CRL> list = new ArrayList<X509CRL>();
        final NodeList nodeList = DSSXMLUtils.getNodeList(signatureElement, XPATH_ENCAPSULATED_CRL_VALUE);
        for (int ii = 0; ii < nodeList.getLength(); ii++) {

            final Element crlEl = (Element) nodeList.item(ii);
            final X509CRL crl = DSSUtils.loadCRLBase64Encoded(crlEl.getTextContent());
            list.add(crl);
        }
        if (list.size() > 0) {

            return new ListCRLSource(list);
        }
        return null;
    }

    @Override
    public ListOCSPSource getOCSPSource() {

        final List<BasicOCSPResp> list = new ArrayList<BasicOCSPResp>();
        final NodeList nodeList = DSSXMLUtils.getNodeList(signatureElement, XAdESSignature.XPATH_ENCAPSULATED_OCSP_VALUE);
        for (int ii = 0; ii < nodeList.getLength(); ii++) {

            final Element certEl = (Element) nodeList.item(ii);
            final BasicOCSPResp basicOCSPResp = DSSUtils.loadOCSPBase64Encoded(certEl.getTextContent());
            list.add(basicOCSPResp);
        }
        if (list.size() > 0) {
            return new ListOCSPSource(list);
        }
        return null;
    }

    @Override
    public SigningCertificate getSigningCertificate() {

        if (signingCert == null) {

            try {

                signingCert = new SigningCertificate();
                /**
                 * The ../SignedProperties/SignedSignatureProperties/SigningCertificate element MAY contain references and
                 * digests values of other certificates (that MAY form a chain up to the point of trust).
                 */

                final NodeList list = DSSXMLUtils.getNodeList(signatureElement, XPATH_SIGNING_CERTIFICATE_CERT);
                for (int ii = 0; ii < list.getLength(); ii++) {

                    final Element element = (Element) list.item(ii);

                    final Element digestMethodEl = DSSXMLUtils.getElement(element, XPATH__DIGEST_METHOD);
                    if (digestMethodEl == null) {
                        continue;
                    }
                    final String xmlAlgoName = digestMethodEl.getAttribute(XMLE_ALGORITHM);
                    final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(xmlAlgoName);
                    final String shortAlgoNam = digestAlgorithm.getName();

                    final Element digestValueEl = DSSXMLUtils.getElement(element, XPATH__CERT_DIGEST_DIGEST_VALUE);
                    if (digestValueEl == null) {
                        continue;
                    }
                    final String digestValueBase64 = digestValueEl.getTextContent();

                    /**
                     * 5.1.4.1 XAdES processing<br>
                     * <i>Candidates for the signing certificate extracted from ds:KeyInfo element</i> shall be checked
                     * against all references present in the ds:SigningCertificate property, if present, since one of these
                     * references shall be a reference to the signing certificate.
                     */
                    final XAdESCertificateSource certSource = getCertificateSource();
                    certSource.extract();
                    for (CertificateToken token : certSource.getKeyInfoCertificates()) {

                        /**
                         * Step 1:<br>
                         * Take the first child of the property and check that the content of ds:DigestValue matches the
                         * result of digesting <i>the candidate for</i> the signing certificate with the algorithm indicated
                         * in ds:DigestMethod. If they do not match, take the next child and repeat this step until a matching
                         * child element has been found or all children of the element have been checked. If they do match,
                         * continue with step 2. If the last element is reached without finding any match, the validation of
                         * this property shall be taken as failed and INVALID/FORMAT_FAILURE is returned.
                         */
                        final String encoded;
                        if (digestAlgorithm.equals(DigestAlgorithm.RIPEMD160)) {

                            final RIPEMD160Digest digest = new RIPEMD160Digest();
                            final byte[] message = token.getCertificate().getEncoded();
                            digest.update(message, 0, message.length);
                            final byte[] digestValue = new byte[digest.getDigestSize()];
                            digest.doFinal(digestValue, 0);
                            encoded = DSSUtils.base64Encode(digestValue);
                        } else {

                            final MessageDigest digest = MessageDigest.getInstance(shortAlgoNam);
                            digest.update(token.getCertificate().getEncoded());
                            encoded = DSSUtils.base64Encode(digest.digest());
                        }
                        signingCert.setDigestMatch(false);
                        if (encoded.equals(digestValueBase64)) {

                            final Element issuerNameEl = DSSXMLUtils.getElement(element, XPATH__X509_ISSUER_NAME);
                            final X500Principal issuerName = new X500Principal(issuerNameEl.getTextContent());
                            final X500Principal candidateIssuerName = token.getIssuerX500Principal();
                            final boolean issuerNameMatches = candidateIssuerName.equals(issuerName);

                            final Element serialNumberEl = DSSXMLUtils.getElement(element, XPATH__X509_SERIAL_NUMBER);
                            final BigInteger serialNumber = new BigInteger(serialNumberEl.getTextContent());
                            final BigInteger candidateSerialNumber = token.getSerialNumber();
                            final boolean serialNumberMatches = candidateSerialNumber.equals(serialNumber);

                            signingCert.setDigestMatch(true);
                            signingCert.setSerialNumberMatch(serialNumberMatches && issuerNameMatches);
                            signingCert.setCertToken(token);
                            return signingCert;
                        }
                    }
                }
            } catch (NoSuchAlgorithmException e) {

                throw new DSSException(e);
            } catch (CertificateEncodingException e) {

                throw new DSSException(e);
            }
        }
        return signingCert;
    }

    @Override
    public Date getSigningTime() {

        try {

            final Element signingTimeEl = DSSXMLUtils.getElement(signatureElement, XPATH_SIGNING_TIME);
            if (signingTimeEl == null) {
                return null;
            }
            final String text = signingTimeEl.getTextContent();
            final DatatypeFactory factory = DatatypeFactory.newInstance();
            final XMLGregorianCalendar cal = factory.newXMLGregorianCalendar(text);
            return cal.toGregorianCalendar().getTime();
        } catch (DOMException e) {
            throw new RuntimeException(e);
        } catch (DatatypeConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public PolicyValue getPolicyId() {

        final Element policyId = DSSXMLUtils.getElement(signatureElement, XPATH_SIGNATURE_POLICY_IDENTIFIER);
        if (policyId != null) {

         /* There is a policy */
            final Element el = DSSXMLUtils.getElement(policyId, XPATH__SIGNATURE_POLICY_ID);
            if (el != null) {
            /* Explicit policy */
                return new PolicyValue(el.getTextContent());
            } else {
            /* Implicit policy */
                return new PolicyValue();
            }
        } else {

            return null;
        }
    }

    @Override
    public SignatureProductionPlace getSignatureProductionPlace() {

        final NodeList list = DSSXMLUtils.getNodeList(signatureElement, XPATH_PRODUCTION_PLACE);
        if (list.getLength() == 0) {

            return null;
        }
        final SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
        for (int ii = 0; ii < list.getLength(); ii++) {

            final String name = list.item(ii).getNodeName();
            if (XMLE_CITY.equals(name)) {

                signatureProductionPlace.setCity(name);
            } else if (XMLE_STATE_OR_PROVINCE.equals(name)) {

                signatureProductionPlace.setStateOrProvince(name);
            } else if (XMLE_POSTAL_CODE.equals(name)) {

                signatureProductionPlace.setPostalCode(name);
            } else if (XMLE_COUNTRY_NAME.equals(name)) {

                signatureProductionPlace.setCountryName(name);
            }
        }
        return signatureProductionPlace;
    }

    @Override
    public String[] getClaimedSignerRoles() {

        final NodeList list = DSSXMLUtils.getNodeList(signatureElement, XPATH_CLAIMED_ROLE);
        if (list.getLength() == 0) {

            return null;
        }
        final String[] roles = new String[list.getLength()];
        for (int i = 0; i < list.getLength(); i++) {

            roles[i] = ((Element) list.item(i)).getTextContent();
        }
        return roles;
    }

    @Override
    public String getContentType() {

        return "text/xml";
    }

    private TimestampToken makeTimestampToken(int id, Element el, TimestampType timestampType) throws XPathExpressionException {

        final Element timestampTokenNode = DSSXMLUtils.getElement(el, XPATH__ENCAPSULATED_TIMESTAMP);
        try {

            final byte[] tokenBytes = DSSUtils.base64Decode(timestampTokenNode.getTextContent());
            final TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(tokenBytes));
            final TimestampToken timestampToken = new TimestampToken(timeStampToken, timestampType, certPool);
            timestampToken.setDSSId(id);
            return timestampToken;
        } catch (Exception e) {

            throw new DSSException(e);
        }
    }

    public Element getKeyInfo() {

        return DSSXMLUtils.getElement(signatureElement, XAdESSignature.XPATH_KEY_INFO);
    }

    public Element getSignedInfo() {

        return DSSXMLUtils.getElement(signatureElement, XAdESSignature.XPATH_SIGNED_INFO);
    }

    public Node getSignatureValue() {

        return DSSXMLUtils.getNode(signatureElement, XAdESSignature.XPATH_SIGNATURE_VALUE);
    }

    public Element getObject() {

        return DSSXMLUtils.getElement(signatureElement, XAdESSignature.XPATH_OBJECT);
    }

    /**
     * This method returns the list of ds:Object elements for the current signature element.
     *
     * @return
     */
    public NodeList getObjects() {

        return DSSXMLUtils.getNodeList(signatureElement, XAdESSignature.XPATH_OBJECT);
    }

    public Element getQualifyingProperties() {

        if (qualifyingProperties == null) {

            qualifyingProperties = DSSXMLUtils.getElement(signatureElement, XAdESSignature.XPATH_QUALIFYING_PROPERTIES);
        }
        return qualifyingProperties;
    }

    public Element getUnsignedSignatureProperties() {

        if (unsignedSignatureProperties == null) {

            unsignedSignatureProperties = DSSXMLUtils.getElement(signatureElement, XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
        }
        return unsignedSignatureProperties;
    }

    public Element getUnsignedProperties() {

        if (unsignedProperties == null) {

            unsignedProperties = DSSXMLUtils.getElement(signatureElement, XPATH_UNSIGNED_PROPERTIES);
        }
        return unsignedProperties;
    }

    public Element getCompleteCertificateRefs() {

        return DSSXMLUtils.getElement(signatureElement, XPATH_COMPLETE_CERTIFICATE_REFS);
    }

    public Element getCompleteRevocationRefs() {

        return DSSXMLUtils.getElement(signatureElement, XPATH_COMPLETE_REVOCATION_REFS);
    }

    public NodeList getSigAndRefsTimeStamp() {

        return DSSXMLUtils.getNodeList(signatureElement, XPATH_SIG_AND_REFS_TIMESTAMP);
    }

    public Element getCertificateValues() {

        return DSSXMLUtils.getElement(signatureElement, XPATH_CERTIFICATE_VALUES);
    }

    public Element getRevocationValues() {

        return DSSXMLUtils.getElement(signatureElement, XPATH_REVOCATION_VALUES);
    }

    /**
     * Checks the presence of SignatureTimeStamp segment in the signature, what is the proof -T extension existence
     *
     * @return
     */
    public boolean hasTExtension() {

        return DSSXMLUtils.getNodeList(signatureElement, XPATH_SIGNATURE_TIMESTAMP).getLength() > 0;
    }

    /**
     * Checks the presence of CompleteCertificateRefs & CompleteRevocationRefs segments in the signature, what is the
     * proof -C extension existence
     *
     * @return
     */
    public boolean hasCExtension() {

        return DSSXMLUtils.getNodeList(signatureElement, XPATH_COMPLETE_CERTIFICATE_REFS).getLength() > 0 || DSSXMLUtils
              .getNodeList(signatureElement, XPATH_COMPLETE_REVOCATION_REFS).getLength() > 0;
    }

    /**
     * Checks the presence of SigAndRefsTimeStamp segment in the signature, what is the proof -X extension existence
     *
     * @return
     */
    public boolean hasXExtension() {

        return DSSXMLUtils.getNodeList(signatureElement, XPATH_SIG_AND_REFS_TIMESTAMP).getLength() > 0;
    }

    /**
     * Checks the presence of CertificateValues and RevocationValues segments in the signature, what is the proof -XL
     * extension existence
     *
     * @return
     */
    public boolean hasXLExtension() {

        return DSSXMLUtils.getNodeList(signatureElement, XPATH_CERTIFICATE_VALUES).getLength() > 0 || DSSXMLUtils
              .getNodeList(signatureElement, XPATH_REVOCATION_VALUES).getLength() > 0;
    }

    @Override
    public List<TimestampToken> getContentTimestamps() {

        try {

            final List<TimestampToken> contentTimestamps = new ArrayList<TimestampToken>();
            final NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, XPATH_ALL_DATA_OBJECT_TIMESTAMP);
            for (int ii = 0; ii < timestampsNodes.getLength(); ii++) {

                final TimestampToken timestampToken = makeTimestampToken(ii, (Element) timestampsNodes.item(ii), TimestampType.CONTENT_TIMESTAMP);
                if (timestampToken != null) {

                    contentTimestamps.add(timestampToken);
                }
            }

            return contentTimestamps;
        } catch (XPathExpressionException e) {

            throw new EncodingException(MSG.SIGNATURE_TIMESTAMP_ENCODING, e);
        }
    }

    @Override
    public List<TimestampToken> getSignatureTimestamps() {

        try {

            final List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
            final NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, XPATH_SIGNATURE_TIMESTAMP);
            for (int ii = 0; ii < timestampsNodes.getLength(); ii++) {

                final TimestampToken tsToken = makeTimestampToken(ii, (Element) timestampsNodes.item(ii), TimestampType.SIGNATURE_TIMESTAMP);
                if (tsToken != null) {

                    final List<TimestampReference> references = new ArrayList<TimestampReference>();
                    final TimestampReference signatureReference = new TimestampReference();
                    signatureReference.setCategory(TimestampCategory.SIGNATURE);
                    signatureReference.setSignatureId(getId());
                    references.add(signatureReference);
                    final NodeList list = DSSXMLUtils.getNodeList(signatureElement, XPATH_CERT_DIGEST);
                    for (int jj = 0; jj < list.getLength(); jj++) {

                        final Element element = (Element) list.item(jj);
                        final TimestampReference signingCertReference = createCertificateTimestampReference(element);
                        references.add(signingCertReference);
                    }

                    tsToken.setTimestampedReferences(references);
                    signatureTimestamps.add(tsToken);
                }
            }
            return signatureTimestamps;
        } catch (XPathExpressionException e) {

            throw new EncodingException(MSG.SIGNATURE_TIMESTAMP_ENCODING, e);
        }
    }

    @Override
    public List<TimestampToken> getTimestampsX1() {

        try {

            final List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
            final NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, XPATH_SIG_AND_REFS_TIMESTAMP);
            for (int ii = 0; ii < timestampsNodes.getLength(); ii++) {

                final TimestampToken timestampToken = makeTimestampToken(ii, (Element) timestampsNodes.item(ii), TimestampType.VALIDATION_DATA_TIMESTAMP);
                if (timestampToken != null) {

                    final List<TimestampReference> references = getTimestampedReferences();
                    final TimestampReference signatureReference = new TimestampReference();
                    signatureReference.setCategory(TimestampCategory.SIGNATURE);
                    signatureReference.setSignatureId(getId());
                    references.add(0, signatureReference);
                    timestampToken.setTimestampedReferences(references);
                    signatureTimestamps.add(timestampToken);
                }
            }
            return signatureTimestamps;
        } catch (XPathExpressionException e) {

            throw new EncodingException(MSG.TIMESTAMP_X1_ENCODING, e);
        }
    }

    @Override
    public List<TimestampToken> getTimestampsX2() {

        try {

            final List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
            final NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, XPATH_REFS_ONLY_TIMESTAMP);
            for (int ii = 0; ii < timestampsNodes.getLength(); ii++) {

                final TimestampToken timestampToken = makeTimestampToken(ii, (Element) timestampsNodes.item(ii),
                      TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
                if (timestampToken != null) {

                    timestampToken.setTimestampedReferences(getTimestampedReferences());
                    signatureTimestamps.add(timestampToken);
                }
            }
            return signatureTimestamps;
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.TIMESTAMP_X2_ENCODING, e);
        }
    }

    @Override
    public List<TimestampToken> getArchiveTimestamps() {

        try {

            final List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
            final NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, XPATH_ARCHIVE_TIMESTAMP);
            addArchiveTimestamps(signatureTimestamps, timestampsNodes, ArchiveTimestampType.XAdES);
            final NodeList timestampsNodes141 = DSSXMLUtils.getNodeList(signatureElement, XPATH_ARCHIVE_TIMESTAMP_141);
            addArchiveTimestamps(signatureTimestamps, timestampsNodes141, ArchiveTimestampType.XAdES_141);
            final NodeList timestampsNodesV2 = DSSXMLUtils.getNodeList(signatureElement, XPATH_ARCHIVE_TIMESTAMP_V2);
            addArchiveTimestamps(signatureTimestamps, timestampsNodesV2, ArchiveTimestampType.XAdES_141_V2);
            return signatureTimestamps;
        } catch (XPathExpressionException e) {

            throw new EncodingException(MSG.ARCHIVE_TIMESTAMP_ENCODING, e);
        }
    }

    private void addArchiveTimestamps(List<TimestampToken> signatureTimestamps, NodeList timestampsNodes,
                                      ArchiveTimestampType archiveTimestampType) throws XPathExpressionException {

        for (int ii = 0; ii < timestampsNodes.getLength(); ii++) {

            Element timestampElement = (Element) timestampsNodes.item(ii);
            final TimestampToken timestampToken = makeTimestampToken(ii, timestampElement, TimestampType.ARCHIVE_TIMESTAMP);
            if (timestampToken != null) {

                timestampToken.setArchiveTimestampType(archiveTimestampType);

                final Element canonicalizationMethodElement = DSSXMLUtils.getElement(timestampElement, XPATH__CANONICALIZATION_METHOD);
                final String canonicalizationMethod;
                if (canonicalizationMethodElement != null) {

                    canonicalizationMethod = canonicalizationMethodElement.getAttribute(XMLE_ALGORITHM);
                } else {

                    canonicalizationMethod = XMLDSIG_DEFAULT_CANONICALIZATION_METHOD;
                }
                timestampToken.setCanonicalizationMethod(canonicalizationMethod);

                final List<TimestampReference> references = getTimestampedReferences();
                final TimestampReference signatureReference = new TimestampReference();
                signatureReference.setCategory(TimestampCategory.SIGNATURE);
                signatureReference.setSignatureId(getId());
                references.add(0, signatureReference);
                timestampToken.setTimestampedReferences(references);
                signatureTimestamps.add(timestampToken);
            }
        }
    }

    /*
     * Returns the list of certificates encapsulated in the signature
     *
     * @see eu.europa.ec.markt.dss.validation.AdvancedSignature#getCertificates()
     */
    @Override
    public List<CertificateToken> getCertificates() {

        return getCertificateSource().getCertificates();
    }

    /*
     * Returns the list of certificates encapsulated in the KeyInfo segment
     */
    public List<CertificateToken> getKeyInfoCertificates() {

        return getCertificateSource().getKeyInfoCertificates();
    }

    @Override
    public SignatureCryptographicVerification checkIntegrity(DSSDocument detachedDocument) {

        final SignatureCryptographicVerification scv = new SignatureCryptographicVerification();

        final CertificateToken certToken = getSigningCertificate().getCertToken();
        if (certToken != null) {

            final PublicKey publicKey = certToken.getCertificate().getPublicKey();
            final KeySelector keySelector = KeySelector.singletonKeySelector(publicKey);

            /**
             * Creating a Validation Context<br>
             * We create an XMLValidateContext instance containing input parameters for validating the signature. Since we
             * are using DOM, we instantiate a DOMValidateContext instance (a subclass of XMLValidateContext), and pass it
             * two parameters, a KeyValueKeySelector object and a reference to the Signature element to be validated (which
             * is the first entry of the NodeList we generated earlier):
             */
            final DOMValidateContext valContext = new DOMValidateContext(keySelector, signatureElement);
            try {

                URIDereferencer dereferencer = new ExternalFileURIDereferencer(detachedDocument);
                valContext.setURIDereferencer(dereferencer);
                /**
                 * This property controls whether or not the digested Reference objects will cache the dereferenced content
                 * and pre-digested input for subsequent retrieval via the Reference.getDereferencedData and
                 * Reference.getDigestInputStream methods. The default value if not specified is Boolean.FALSE.
                 */
                valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);

                /**
                 * Unmarshalling the XML Signature<br>
                 * We extract the contents of the Signature element into an XMLSignature object. This process is called
                 * unmarshalling. The Signature element is unmarshalled using an XMLSignatureFactory object. An application
                 * can obtain a DOM implementation of XMLSignatureFactory by calling the following line of code:
                 */

                // These providers do not support ECDSA algorithm
                // factory = XMLSignatureFactory.getInstance("DOM");
                // factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
                // factory = XMLSignatureFactory.getInstance("DOM", new org.jcp.xml.dsig.internal.dom.XMLDSigRI());

                // This provider support ECDSA signature
                /**
                 * ApacheXMLDSig / Apache Santuario XMLDSig (DOM XMLSignatureFactory; DOM KeyInfoFactory; C14N 1.0, C14N
                 * 1.1, Exclusive C14N, Base64, Enveloped, XPath, XPath2, XSLT TransformServices)<br>
                 * If this library is used than the same library must be used for the URIDereferencer.
                 */
                final XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", xmlProvider);

                /**
                 * We then invoke the unmarshalXMLSignature method of the factory to unmarshal an XMLSignature object, and
                 * pass it the validation context we created earlier:
                 */
                final XMLSignature signature = factory.unmarshalXMLSignature(valContext);
                //System.out.println("XMLSignature class: " + signature.getClass());

                // Austrian specific signature
                //org.apache.xml.security.signature.XMLSignature signature_ = null;
                // try {
                // signature_ = new org.apache.xml.security.signature.XMLSignature(signatureElement, "");
                // } catch (Exception e) {
                //
                // throw new DSSException(e);
                // }
                // signature.addResourceResolver(new XPointerResourceResolver(signatureElement));

                //signature_.getSignedInfo().verifyReferences();//getVerificationResult(1);
                /**
                 * In case of org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI() provider, the ID attributes need to be set
                 * manually.<br>
                 * The DSSXMLUtils.recursiveIdBrowse(...) method do not take into account the XML outside of the Signature
                 * tag. It prevents some signatures to be validated.<br>
                 *
                 * Solution: the following lines where added:
                 */
                final Document document = signatureElement.getOwnerDocument();
                final Element rootElement = document.getDocumentElement();
                if (rootElement.hasAttribute(DSSXMLUtils.ID_ATTRIBUTE_NAME)) {

                    valContext.setIdAttributeNS(rootElement, null, DSSXMLUtils.ID_ATTRIBUTE_NAME);
                }

                DSSXMLUtils.recursiveIdBrowse(valContext, rootElement);

                /**
                 * Validating the XML Signature<br>
                 * Now we are ready to validate the signature. We do this by invoking the validate method on the
                 * XMLSignature object, and pass it the validation context as follows:
                 */
                boolean coreValidity = false;
                try {

                    coreValidity = signature.validate(valContext);
                } catch (XMLSignatureException e) {

                    scv.setErrorMessage("Signature validation: " + e.getMessage());
                }
                boolean signatureValidity = coreValidity;
                boolean dataFound = true;
                boolean dataHashValid = true;

                /**
                 * If the XMLSignature.validate method returns false, we can try to narrow down the cause of the failure.
                 * There are two phases in core XML Signature validation: <br>
                 * - Signature validation (the cryptographic verification of the signature)<br>
                 * - Reference validation (the verification of the digest of each reference in the signature)<br>
                 * Each phase must be successful for the signature to be valid. To check if the signature failed to
                 * cryptographically validate, we can check the status, as follows:
                 */

                try {

                    signatureValidity = signature.getSignatureValue().validate(valContext);
                } catch (XMLSignatureException e) {

                    scv.setErrorMessage(e.getMessage());
                }

                @SuppressWarnings("unchecked")
                final List<Reference> references = signature.getSignedInfo().getReferences();
                for (Reference reference : references) {

                    boolean refHashValidity = false;
                    try {

                        refHashValidity = reference.validate(valContext);
                    } catch (XMLSignatureException e) {

                        scv.setErrorMessage(reference.getURI() + ": " + e.getMessage());
                    }
                    dataHashValid = dataHashValid && refHashValidity;
                    if (LOG.isLoggable(Level.INFO)) {
                        LOG.info("Reference hash validity checked: " + reference.getURI() + "=" + refHashValidity);
                    }
                    final Data data = reference.getDereferencedData();
                    dataFound = dataFound && (data != null);

                    final InputStream digestInputStream = reference.getDigestInputStream();
                    if (data != null && digestInputStream != null) {

                        // The references are saved for later treatment in -A level.
                        try {

                            IOUtils.copy(digestInputStream, referencesDigestOutputStream);
                        } catch (IOException e) {
                        }
                    }
                }
                scv.setReferenceDataFound(dataFound);
                scv.setReferenceDataIntact(dataHashValid);
                scv.setSignatureIntegrity(signatureValidity);
            } catch (MarshalException e) {

                scv.setErrorMessage(e.getMessage());
            }
        } else {

            scv.setErrorMessage("Unable to proceed with the signature cryptographic verification. There is no signing certificate!");
        }
        return scv;
    }

    @Override
    public List<AdvancedSignature> getCounterSignatures() {

        // see ETSI TS 101 903 V1.4.2 (2010-12) pp. 38/39/40

        try {
            NodeList counterSigs = DSSXMLUtils.getNodeList(signatureElement, XPATH_COUNTER_SIGNATURE);
            if (counterSigs == null) {
                return null;
            }

            List<AdvancedSignature> xadesList = new ArrayList<AdvancedSignature>();

            for (int i = 0; i < counterSigs.getLength(); i++) {

                Element counterSigEl = (Element) counterSigs.item(i);
                Element signatureEl = DSSXMLUtils.getElement(counterSigEl, XPATH_SIGNATURE);

                // Verify that the element is a proper signature by trying to build a XAdESSignature out of it
                XAdESSignature xCounterSig = new XAdESSignature(signatureEl, certPool);

            /*
             * Verify that there is a ds:Reference element with a Type set to:
             * http://uri.etsi.org/01903#CountersignedSignature (as per the XAdES spec)
             */
                XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
                javax.xml.crypto.dsig.XMLSignature signature = factory.unmarshalXMLSignature(new DOMStructure(signatureEl));

                LOG.info("Verifying countersignature References");
                for (Object refobj : signature.getSignedInfo().getReferences()) {

                    Reference ref = (Reference) refobj;
                    if (ref.getType() != null && ref.getType().equals(XADES_COUNTERSIGNED_SIGNATURE)) {

                        // Ok, this seems to be a CounterSignature
                        // Verify that the digest is that of the signature value
                        CertificateToken certToken = xCounterSig.getSigningCertificate().getCertToken();
                        PublicKey publicKey = certToken.getCertificate().getPublicKey();
                        if (ref.validate(new DOMValidateContext(publicKey, DSSXMLUtils.getElement(signatureElement, XPATH_SIGNATURE_VALUE)))) {

                            LOG.info("Reference verification succeeded, adding countersignature");
                            xadesList.add(xCounterSig);
                        } else {

                            LOG.warning("Skipping countersignature because the Reference doesn't contain a hash of the embedding SignatureValue");
                        }
                        break;
                    }
                }
            }
            return xadesList;
        } catch (MarshalException e) {

            throw new EncodingException(MSG.COUNTERSIGNATURE_ENCODING, e);
        } catch (XMLSignatureException e) {

            throw new EncodingException(MSG.COUNTERSIGNATURE_ENCODING, e);
        }
    }

    @Override
    public List<CertificateRef> getCertificateRefs() {

        Element signingCertEl = DSSXMLUtils.getElement(signatureElement, XPATH_CERT_REFS);
        if (signingCertEl == null) {

            return null;
        }
        List<CertificateRef> certIds = new ArrayList<CertificateRef>();
        NodeList certIdnodes = DSSXMLUtils.getNodeList(signingCertEl, "./xades:Cert");
        for (int i = 0; i < certIdnodes.getLength(); i++) {

            Element certId = (Element) certIdnodes.item(i);
            Element issuerNameEl = DSSXMLUtils.getElement(certId, XPATH__X509_ISSUER_NAME);
            Element issuerSerialEl = DSSXMLUtils.getElement(certId, XPATH__X509_SERIAL_NUMBER);
            Element digestAlgorithmEl = DSSXMLUtils.getElement(certId, XPATH__DIGEST_METHOD);
            Element digestValueEl = DSSXMLUtils.getElement(certId, XPATH__CERT_DIGEST_DIGEST_VALUE);

            CertificateRef genericCertId = new CertificateRef();
            if (issuerNameEl != null && issuerSerialEl != null) {
                genericCertId.setIssuerName(issuerNameEl.getTextContent());
                genericCertId.setIssuerSerial(issuerSerialEl.getTextContent());
            }

            String xmlName = digestAlgorithmEl.getAttribute(XMLE_ALGORITHM);
            genericCertId.setDigestAlgorithm(DigestAlgorithm.forXML(xmlName).getName());

            genericCertId.setDigestValue(DSSUtils.base64Decode(digestValueEl.getTextContent()));
            certIds.add(genericCertId);
        }

        return certIds;

    }

    @Override
    public List<CRLRef> getCRLRefs() {

        List<CRLRef> certIds = new ArrayList<CRLRef>();
        Element signingCertEl = DSSXMLUtils.getElement(signatureElement, XPATH_REVOCATION_CRL_REFS);
        if (signingCertEl != null) {

            NodeList certIdnodes = DSSXMLUtils.getNodeList(signingCertEl, XPATH__CRL_REF);
            for (int i = 0; i < certIdnodes.getLength(); i++) {
                Element certId = (Element) certIdnodes.item(i);
                Element digestAlgorithmEl = DSSXMLUtils.getElement(certId, XPATH__DAAV_DIGEST_METHOD);
                Element digestValueEl = DSSXMLUtils.getElement(certId, XPATH__DAAV_DIGEST_VALUE);

                String xmlName = digestAlgorithmEl.getAttribute(XMLE_ALGORITHM);
                String digestAlgo = DigestAlgorithm.forXML(xmlName).getName();

                CRLRef ref = new CRLRef();
                ref.setDigestAlgorithm(digestAlgo);
                ref.setDigestValue(DSSUtils.base64Decode(digestValueEl.getTextContent()));
                certIds.add(ref);
            }
        }
        return certIds;
    }

    @Override
    public List<OCSPRef> getOCSPRefs() {

        List<OCSPRef> certIds = new ArrayList<OCSPRef>();
        Element signingCertEl = DSSXMLUtils.getElement(signatureElement, XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:CompleteRevocationRefs/xades:OCSPRefs");
        if (signingCertEl != null) {

            NodeList certIdnodes = DSSXMLUtils.getNodeList(signingCertEl, "./xades:OCSPRef");
            for (int i = 0; i < certIdnodes.getLength(); i++) {
                Element certId = (Element) certIdnodes.item(i);
                Element digestAlgorithmEl = DSSXMLUtils.getElement(certId, "./xades:DigestAlgAndValue/ds:DigestMethod");
                Element digestValueEl = DSSXMLUtils.getElement(certId, "./xades:DigestAlgAndValue/ds:DigestValue");

                if (digestAlgorithmEl == null || digestValueEl == null) {
                    throw new NotETSICompliantException(NotETSICompliantException.MSG.XADES_DIGEST_ALG_AND_VALUE_ENCODING);
                }

                String xmlName = digestAlgorithmEl.getAttribute(XMLE_ALGORITHM);
                String digestAlgo = DigestAlgorithm.forXML(xmlName).getName();

                certIds.add(new OCSPRef(digestAlgo, DSSUtils.base64Decode(digestValueEl.getTextContent()), false));
            }
        }
        return certIds;
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

    /**
     * This method returns the array of bytes canonicalised with the given method.
     *
     * @param node
     * @param canonicalizationMethod
     * @return
     */
    private byte[] getC14nValue(Node node, String canonicalizationMethod) {

        try {

            Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
            return c14n.canonicalizeSubtree(node);
        } catch (InvalidCanonicalizerException e) {
            throw new RuntimeException("c14n algo error: " + e.getMessage(), e);
        } catch (CanonicalizationException e) {
            throw new RuntimeException("c14n error: " + e.getMessage(), e);
        }
    }

    /**
     * This method returns the array of bytes canonicalised with the given method.
     *
     * @param nodeList
     * @param canonicalizationMethod
     * @return
     */
    private byte[] getC14nValue(List<Node> nodeList, String canonicalizationMethod) {

        try {

            Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
            // Canonicalizer c14n = Canonicalizer.getInstance(CanonicalizationMethod.EXCLUSIVE);
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            for (Node node : nodeList) {

                buffer.write(c14n.canonicalizeSubtree(node));
            }
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InvalidCanonicalizerException e) {
            throw new RuntimeException("c14n algo error: " + e.getMessage(), e);
        } catch (CanonicalizationException e) {
            throw new RuntimeException("c14n error: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] getSignatureTimestampData() {

        Element signatureValue = DSSXMLUtils.getElement(signatureElement, XPATH_SIGNATURE_VALUE);
        Element canonicalizationMethod = DSSXMLUtils.getElement(signatureElement, XPATH_SIGNATURE_TIMESTAMP + XPATH__CANONICALIZATION_METHOD);
        if (canonicalizationMethod != null) {

            String canonicalizationMethodStr = canonicalizationMethod.getTextContent();
            return getC14nValue(signatureValue, canonicalizationMethodStr);
        }
        return getC14nValue(signatureValue, XMLDSIG_DEFAULT_CANONICALIZATION_METHOD);
    }

    @Override
    public byte[] getTimestampX1Data() {

        String canonicalizationMethod = XMLDSIG_DEFAULT_CANONICALIZATION_METHOD;
        Element canonicalizationMethodEl = DSSXMLUtils.getElement(signatureElement, XPATH_SIG_AND_REFS_TIMESTAMP + XPATH__CANONICALIZATION_METHOD);
        if (canonicalizationMethodEl != null) {

            canonicalizationMethod = canonicalizationMethodEl.getTextContent();
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try {

            byte[] canonicalizedValue = null;

            Element signatureValue = DSSXMLUtils.getElement(signatureElement, XPATH_SIGNATURE_VALUE);
            canonicalizedValue = getC14nValue(signatureValue, canonicalizationMethod);
            buffer.write(canonicalizedValue);

            NodeList signatureTimeStampNode = DSSXMLUtils.getNodeList(signatureElement, XPATH_SIGNATURE_TIMESTAMP);
            if (signatureTimeStampNode != null) {

                for (int i = 0; i < signatureTimeStampNode.getLength(); i++) {

                    canonicalizedValue = getC14nValue(signatureTimeStampNode.item(i), canonicalizationMethod);
                    buffer.write(canonicalizedValue);
                }
            }

            Node completeCertificateRefsNode = DSSXMLUtils.getElement(signatureElement, XPATH_COMPLETE_CERTIFICATE_REFS);
            if (completeCertificateRefsNode != null) {

                canonicalizedValue = getC14nValue(completeCertificateRefsNode, canonicalizationMethod);
                buffer.write(canonicalizedValue);
            }
            Node completeRevocationRefsNode = DSSXMLUtils.getElement(signatureElement, XPATH_COMPLETE_REVOCATION_REFS);
            if (completeRevocationRefsNode != null) {

                canonicalizedValue = getC14nValue(completeRevocationRefsNode, canonicalizationMethod);
                buffer.write(canonicalizedValue);
            }
        } catch (IOException e) {

            throw new DSSException("Error when computing the SigAndRefsTimeStamp", e);
        }
        return buffer.toByteArray();
    }

    @Override
    public byte[] getTimestampX2Data() {

        List<Node> timeStampNodesXadesX2 = new ArrayList<Node>();
        Node completeCertificateRefsNode = DSSXMLUtils.getElement(signatureElement, XPATH_COMPLETE_CERTIFICATE_REFS);
        if (completeCertificateRefsNode != null) {
            timeStampNodesXadesX2.add(completeCertificateRefsNode);
        }
        Node completeRevocationRefsNode = DSSXMLUtils.getElement(signatureElement, XPATH_COMPLETE_REVOCATION_REFS);
        if (completeRevocationRefsNode != null) {
            timeStampNodesXadesX2.add(completeRevocationRefsNode);
        }
        Element canonicalizationMethod = DSSXMLUtils.getElement(signatureElement, XPATH_REFS_ONLY_TIMESTAMP + XPATH__CANONICALIZATION_METHOD);
        if (canonicalizationMethod != null) {

            String canonicalizationMethodStr = canonicalizationMethod.getTextContent();
            return getC14nValue(timeStampNodesXadesX2, canonicalizationMethodStr);
        }
        return getC14nValue(timeStampNodesXadesX2, XMLDSIG_DEFAULT_CANONICALIZATION_METHOD);
    }

    /**
     * Creates the hash sent to the TSA (messageImprint) computed on the XAdES-X-L form of the electronic signature and
     * the signed data objects, i.e. on the sequence formed as explained below:<br>
     * <p/>
     * One HashDataInfo element for each data object signed by the [XMLDSIG] signature. The result of application of the
     * transforms specified each HashDataInfo must be exactly the same as the octet stream that was originally used for
     * computing the digest value of the corresponding ds:Reference.<br>
     * <p/>
     * One HashDataInfo element for the ds:SignedInfo element. The result of application of the transforms specified in
     * this HashDataInfo must be exactly the same as the octet stream that was originally used for computing the
     * signature value of the [XMLDSIG] signature.<br>
     * <p/>
     * One HashDataInfo element for the SignedSignatureProperties element.<br>
     * One HashDataInfo element for the SignedDataObjectProperties element.<br>
     * One HashDataInfo element for the ds:SignatureValue element.<br>
     * One HashDataInfo element per each SignatureTimeStamp property.<br>
     * One HashDataInfo element for the CompleteCertificateRefs property.<br>
     * One HashDataInfo element for the CompleteRevocationRefs property.<br>
     * One HashDataInfo element for the CertificatesValues property (add this property previously if not already
     * present).<br>
     * One HashDataInfo element for the RevocationValues property (add this property previously if not already present).<br>
     * One HashDataInfo element per each SigAndRefsTimeStamp property (if present).<br>
     * One HashDataInfo element per each property RefsOnlyTimeStamp (if present).<br>
     * One HashDataInfo element per each any previous XAdESArchiveTimestamp property (if present).
     *
     * @see AdvancedSignature#getArchiveTimestampData(eu.europa.ec.markt.dss.validation102853.TimestampToken)
     */
    @Override
    public byte[] getArchiveTimestampData(TimestampToken timestampToken) {

        String canonicalizationMethod = timestampToken == null ? XMLDSIG_DEFAULT_CANONICALIZATION_METHOD : timestampToken.getCanonicalizationMethod();

        byte[] canonicalizedValue = null;

        /**
         * 8.2.1 Not distributed case<br>
         *
         * When xadesv141:ArchiveTimeStamp and all the unsigned properties covered by its time-stamp token have the same
         * parent, this property uses the Implicit mechanism for all the time-stamped data objects. The input to the
         * computation of the digest value MUST be built as follows:
         */
        try {

            /**
             * 1) Initialize the final octet stream as an empty octet stream.
             */
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();

            /**
             * 2) Take all the ds:Reference elements in their order of appearance within ds:SignedInfo referencing whatever
             * the signer wants to sign including the SignedProperties element. Process each one as indicated below:<br>
             * - Process the retrieved ds:Reference element according to the reference processing model of XMLDSIG.<br>
             * - If the result is a XML node set, canonicalize it. If ds:Canonicalization is present, the algorithm
             * indicated by this element is used. If not, the standard canonicalization method specified by XMLDSIG is
             * used.<br>
             * - Concatenate the resulting octets to the final octet stream.
             */

            /**
             * The references are already calculated {@see #checkIntegrity()}
             */

            InputStream decodedInput = new ByteArrayInputStream((referencesDigestOutputStream).toByteArray());

            IOUtils.copy(decodedInput, buffer);
            /**
             * 3) Take the following XMLDSIG elements in the order they are listed below, canonicalize each one and
             * concatenate each resulting octet stream to the final octet stream:<br>
             * - The ds:SignedInfo element.<br>
             * - The ds:SignatureValue element.<br>
             * - The ds:KeyInfo element, if present.
             */

            Element signedInfo = DSSXMLUtils.getElement(signatureElement, XPATH_SIGNED_INFO);
            canonicalizedValue = getC14nValue(signedInfo, canonicalizationMethod);
            buffer.write(canonicalizedValue);

            Element signatureValue = DSSXMLUtils.getElement(signatureElement, XPATH_SIGNATURE_VALUE);
            canonicalizedValue = getC14nValue(signatureValue, canonicalizationMethod);
            buffer.write(canonicalizedValue);

            Element keyInfo = DSSXMLUtils.getElement(signatureElement, XPATH_KEY_INFO);
            canonicalizedValue = getC14nValue(keyInfo, canonicalizationMethod);
            buffer.write(canonicalizedValue);

            /**
             * 4) Take the unsigned signature properties that appear before the current xadesv141:ArchiveTimeStamp in the
             * order they appear within the xades:UnsignedSignatureProperties, canonicalize each one and concatenate each
             * resulting octet stream to the final octet stream. While concatenating the following rules apply:
             */
            Element unsignedSignaturePropertiesNode = getUnsignedSignatureProperties(signatureElement);

            // The archive timestamp need to be identified to know if it must be taken into account or not.
            int archiveTimeStampCount = 0;

            NodeList unsignedProperties = unsignedSignaturePropertiesNode.getChildNodes();
            for (int ii = 0; ii < unsignedProperties.getLength(); ii++) {

                Node node = unsignedProperties.item(ii);
                String localName = node.getLocalName();
                if (localName.equals("CertificateValues")) {

                    /**
                     * - The xades:CertificateValues property MUST be added if it is not already present and the ds:KeyInfo
                     * element does not contain the full set of certificates used to validate the electronic signature.
                     */

                } else if (localName.equals("RevocationValues")) {

                    /**
                     * - The xades:RevocationValues property MUST be added if it is not already present and the ds:KeyInfo
                     * element does not contain the revocation information that has to be shipped with the electronic
                     * signature
                     */

                } else if (localName.equals("AttrAuthoritiesCertValues")) {

                    /**
                     * - The xades:AttrAuthoritiesCertValues property MUST be added if not already present and the following
                     * conditions are true: there exist an attribute certificate in the signature AND a number of
                     * certificates that have been used in its validation do not appear in CertificateValues. Its content
                     * will satisfy with the rules specified in clause 7.6.3.
                     */

                } else if (localName.equals("AttributeRevocationValues")) {

                    /**
                     * - The xades:AttributeRevocationValues property MUST be added if not already present and there the
                     * following conditions are true: there exist an attribute certificate AND some revocation data that have
                     * been used in its validation do not appear in RevocationValues. Its content will satisfy with the rules
                     * specified in clause 7.6.4.
                     */
                } else if (XMLE_ARCHIVE_TIME_STAMP.equals(localName) || XMLE_ARCHIVE_TIME_STAMP_V2.equals(localName)) {

                    if (timestampToken == null || timestampToken.getDSSId() <= archiveTimeStampCount) {

                        break;
                    }
                    archiveTimeStampCount++;
                }
                canonicalizedValue = getC14nValue(node, canonicalizationMethod);
                buffer.write(canonicalizedValue);
            }
            /**
             * 5) Take all the ds:Object elements except the one containing xades:QualifyingProperties element.
             * Canonicalize each one and concatenate each resulting octet stream to the final octet stream. If
             * ds:Canonicalization is present, the algorithm indicated by this element is used. If not, the standard
             * canonicalization method specified by XMLDSIG is used.
             */
            boolean xades141 = true;
            if (timestampToken != null && ArchiveTimestampType.XAdES.equals(timestampToken.getArchiveTimestampType())) {

                xades141 = false;
            }
            if (xades141) {

                NodeList objects = getObjects();
                for (int ii = 0; ii < objects.getLength(); ii++) {

                    Node node = objects.item(ii);
                    Node qualifyingProperties = DSSXMLUtils.getElement(node, "./xades:QualifyingProperties");
                    if (qualifyingProperties != null) {

                        continue;
                    }
                    canonicalizedValue = getC14nValue(node, canonicalizationMethod);
                    buffer.write(canonicalizedValue);
                }
            }

            // *** Log ArchiveTimestamp canonicalised string
            // if (LOG.isLoggable(Level.INFO)) LOG.info("ArchiveTimestamp canonicalised string:\n" + buffer.toString());
            return buffer.toByteArray();
        } catch (IOException e) {

            throw new DSSException("Error when computing the archive data", e);
        }
    }

    private Element getUnsignedSignatureProperties(Element signatureEl) {

        Element unsignedSignaturePropertiesNode = DSSXMLUtils.getElement(signatureEl, XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
        if (unsignedSignaturePropertiesNode == null) {

            Element qualifyingProperties = DSSXMLUtils.getElement(signatureEl, XPATH_QUALIFYING_PROPERTIES);
            Element unsignedProperties = DSSXMLUtils.getElement(qualifyingProperties, XPATH_UNSIGNED_PROPERTIES);
            if (unsignedProperties == null) {

                unsignedProperties = qualifyingProperties.getOwnerDocument().createElementNS(XADES_NAMESPACE, "UnsignedProperties");
                qualifyingProperties.appendChild(unsignedProperties);
            }
            unsignedSignaturePropertiesNode = unsignedProperties.getOwnerDocument().createElementNS(XADES_NAMESPACE, "UnsignedSignatureProperties");
            unsignedProperties.appendChild(unsignedSignaturePropertiesNode);
        }
        return unsignedSignaturePropertiesNode;
    }

    @Override
    public String getId() {

        try {

            if (id == null) {

                Node idElement = DSSXMLUtils.getNode(signatureElement, "./@Id");
                if (idElement != null) {

                    id = idElement.getTextContent();
                } else {

                    MessageDigest digest = MessageDigest.getInstance("MD5");
                    digest.update(Long.toString(getSigningTime().getTime()).getBytes());
                    CertificateToken certToken = getSigningCertificate().getCertToken();
                    digest.update(certToken.getCertificate().getEncoded());
                    id = Hex.encodeHexString(digest.digest());
                }
            }
            return id;
        } catch (Exception e) {

            throw new RuntimeException(e);
        }
    }

    @Override
    public List<TimestampReference> getTimestampedReferences() {

        final List<TimestampReference> references = new ArrayList<TimestampReference>();
        try {

            NodeList list = DSSXMLUtils.getNodeList(signatureElement, XPATH_CERT_DIGEST);
            for (int jj = 0; jj < list.getLength(); jj++) {

                final Element element = (Element) list.item(jj);
                TimestampReference signingCertReference = createCertificateTimestampReference(element);
                references.add(signingCertReference);
            }

            Node completeCertificateRefsNode = DSSXMLUtils.getElement(signatureElement, XPATH_COMPLETE_CERTIFICATE_REFS);
            if (completeCertificateRefsNode != null) {

                final NodeList nodes = DSSXMLUtils.getNodeList(completeCertificateRefsNode, XPATH__COMPLETE_CERTIFICATE_REFS__CERT_DIGEST);
                for (int ii = 0; ii < nodes.getLength(); ii++) {

                    final Element element = (Element) nodes.item(ii);
                    TimestampReference reference = createCertificateTimestampReference(element);
                    references.add(reference);
                }
            }
            final Node completeRevocationRefsNode = DSSXMLUtils.getElement(signatureElement, XPATH_COMPLETE_REVOCATION_REFS);
            if (completeRevocationRefsNode != null) {

                final NodeList nodes = DSSXMLUtils.getNodeList(completeRevocationRefsNode, "./*/*/xades:DigestAlgAndValue");
                for (int ii = 0; ii < nodes.getLength(); ii++) {

                    final Element element = (Element) nodes.item(ii);
                    String digestAlgorithm = DSSXMLUtils.getNode(element, XPATH__DIGEST_METHOD_ALGORITHM).getTextContent();
                    digestAlgorithm = DigestAlgorithm.forXML(digestAlgorithm).getName();
                    String digestValue = DSSXMLUtils.getElement(element, XPATH__DIGEST_VALUE).getTextContent();
                    TimestampReference reference = new TimestampReference();
                    reference.setCategory(TimestampCategory.REVOCATION);
                    reference.setDigestAlgorithm(digestAlgorithm);
                    reference.setDigestValue(digestValue);
                    references.add(reference);
                }
            }
            return references;
        } catch (XPathExpressionException e) {

            throw new EncodingException(MSG.TIMESTAMP_X1_DATA_ENCODING, e);
        }
    }

    /**
     * @param element
     * @return
     * @throws DOMException
     * @throws XPathExpressionException
     */
    private TimestampReference createCertificateTimestampReference(final Element element) throws DOMException, XPathExpressionException {

        String digestAlgorithm = DSSXMLUtils.getNode(element, XPATH__DIGEST_METHOD_ALGORITHM).getTextContent();
        DigestAlgorithm digestAlgorithmObj = DigestAlgorithm.forXML(digestAlgorithm);
        if (!usedCertificatesDigestAlgorithms.contains(digestAlgorithmObj)) {

            usedCertificatesDigestAlgorithms.add(digestAlgorithmObj);
        }
        String digestValue = DSSXMLUtils.getElement(element, XPATH__DIGEST_VALUE).getTextContent();
        TimestampReference reference = new TimestampReference();
        reference.setCategory(TimestampCategory.CERTIFICATE);
        reference.setDigestAlgorithm(digestAlgorithmObj.getName());
        reference.setDigestValue(digestValue);
        return reference;
    }

    @Override
    public Set<DigestAlgorithm> getUsedCertificatesDigestAlgorithms() {

        return usedCertificatesDigestAlgorithms;
    }

    @Override
    public boolean isLevelReached(SignatureFormat signatureFormat) {
        //TODO
        throw new UnsupportedOperationException("Not implemented yet");
    }
}
