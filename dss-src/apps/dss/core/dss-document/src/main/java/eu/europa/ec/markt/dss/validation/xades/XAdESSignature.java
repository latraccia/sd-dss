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

package eu.europa.ec.markt.dss.validation.xades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.Data;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
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
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.EncodingException;
import eu.europa.ec.markt.dss.exception.EncodingException.MSG;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.xades.ExternalFileURIDereferencer;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.CRLRef;
import eu.europa.ec.markt.dss.validation.CertificateRef;
import eu.europa.ec.markt.dss.validation.OCSPRef;
import eu.europa.ec.markt.dss.validation.PolicyValue;
import eu.europa.ec.markt.dss.validation.SignatureForm;
import eu.europa.ec.markt.dss.validation.X500PrincipalMatcher;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSource;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken;
import eu.europa.ec.markt.dss.validation.x509.TimestampToken.TimestampType;

/**
 * Parse an XAdES structure
 *
 * @version $Revision: 2911 $ - $Date: 2013-11-08 17:25:14 +0100 (ven., 08 nov. 2013) $
 */

public class XAdESSignature implements AdvancedSignature {

    private static final Logger LOG = Logger.getLogger(XAdESSignature.class.getName());

    public static final String XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";

    public static final String XMLDSIG_DEFAULT_CANONICALIZATION_METHOD = CanonicalizationMethod.INCLUSIVE;

    public static final String XPATH_SIGNED_INFO = "./ds:SignedInfo";

    public static final String XPATH_SIGNATURE_VALUE = "./ds:SignatureValue";

    public static final String XPATH_KEY_INFO = "./ds:KeyInfo";

    public static final String XPATH_X509_CERTIFICATE = XPATH_KEY_INFO + "/ds:X509Data/ds:X509Certificate";

    public static final String XPATH_OBJECT = "./ds:Object";

    public static final String XPATH__CANONICALIZATION_METHOD = "./ds:CanonicalizationMethod";

    public static final String XPATH_QUALIFYING_PROPERTIES = XPATH_OBJECT + "/xades:QualifyingProperties";

    public static final String XPATH_SIGNED_PROPERTIES = XPATH_QUALIFYING_PROPERTIES + "/xades:SignedProperties";

    public static final String XPATH_SIGNED_SIGNATURE_PROPERTIES = XPATH_SIGNED_PROPERTIES + "/xades:SignedSignatureProperties";

    public static final String XPATH_SIGNING_CERTIFICATE_CERT = XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SigningCertificate/xades:Cert";

    public static final String XPATH_UNSIGNED_PROPERTIES = XPATH_QUALIFYING_PROPERTIES + "/xades:UnsignedProperties";

    public static final String XPATH_UNSIGNED_SIGNATURE_PROPERTIES = XPATH_UNSIGNED_PROPERTIES + "/xades:UnsignedSignatureProperties";

    public static final String XPATH_SIGNATURE_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:SignatureTimeStamp";

    public static final String XPATH_COMPLETE_CERTIFICATE_REFS = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:CompleteCertificateRefs";

    public static final String XPATH_COMPLETE_REVOCATION_REFS = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:CompleteRevocationRefs";

    public static final String XPATH_SIG_AND_REFS_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:SigAndRefsTimeStamp";

    public static final String XPATH_CERTIFICATE_VALUES = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:CertificateValues";

    public static final String XPATH_REVOCATION_VALUES = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:RevocationValues";

    public static final String XPATH_ENCAPSULATED_X509_CERTIFICATE = XPATH_CERTIFICATE_VALUES + "/xades:EncapsulatedX509Certificate";

    public static final String XPATH_ARCHIVE_TIMESTAMP = XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades141:ArchiveTimeStamp";

    private final Element signatureElement;

    static {

        Init.init();
    }

    /**
     * This attribute is used when validate the ArchiveTimeStamp (XAdES-A).
     */
    private ByteArrayOutputStream referencesDigestOutputStream = new ByteArrayOutputStream();

    /**
     * @return the signatureElement
     */
    public Element getSignatureElement() {

        return signatureElement;
    }

    /**
     * The default constructor for XAdESSignature.
     *
     * @param signatureElement
     */
    public XAdESSignature(Element signatureElement) {

        if (signatureElement == null) {

            throw new NullPointerException("Must provide a signatureElement");
        }
        this.signatureElement = signatureElement;
    }

    @Override
    public SignatureForm getSignatureFormat() {

        return SignatureForm.XAdES;
    }

    @Override
    public String getSignatureAlgorithm() {

        return DSSXMLUtils.getElement(signatureElement, "./ds:SignedInfo/ds:SignatureMethod").getAttribute("Algorithm");
    }

    @Override
    public XAdESCertificateSource getCertificateSource() {

        return new XAdESCertificateSource(signatureElement, false);
    }

    @Override
    public CertificateSource getExtendedCertificateSource() {

        return new XAdESCertificateSource(signatureElement, true);
    }

    @Override
    public XAdESCRLSource getCRLSource() {

        return new XAdESCRLSource(signatureElement);
    }

    @Override
    public XAdESOCSPSource getOCSPSource() {

        return new XAdESOCSPSource(signatureElement);
    }

    @Override
    public X509Certificate getSigningCertificate() {

        List<X509Certificate> certificates = getCertificateSource().getCertificates();
        return getSigningCertificate(certificates);
    }

    /**
     * Returns the reference to the signing certificate if exists in the list set in parameter. For optimisation reasons
     * this method caches the result after the first call
     *
     * @param certificates
     * @return
     */
    public X509Certificate getSigningCertificate(List<X509Certificate> certificates) {

        /**
         * Although SigningCertificate element can contain multiple certificates (it is possible to include certificates
         * from the certification chain), only one is the signer's certificate.
         */
        /**
         * TODO (Bob:2013.08.23) The check of the digest of the certificate need to be done following the standard:<br>
         * ETSI TS 101 903 V1.4.2 (2010-12)<br>
         * G.2.2.5 Checking SigningCertificate
         */

        final NodeList list = DSSXMLUtils.getNodeList(signatureElement, XPATH_SIGNING_CERTIFICATE_CERT);
        for (int i = 0; i < list.getLength(); i++) {

            final Element signatureCertElement = (Element) list.item(i);
            final Element issuerDNElement = DSSXMLUtils.getElement(signatureCertElement, "./xades:IssuerSerial/ds:X509IssuerName");
            final String issuerDNBare = issuerDNElement.getTextContent();
            final String issuerDN = X500PrincipalMatcher.maybePatchDN(issuerDNBare); // ECDX-59 (see method doc)
            final X500Name issuerName = new X500Name(issuerDN);

            final Element issuerSerialElement = DSSXMLUtils.getElement(signatureCertElement, "./xades:IssuerSerial/ds:X509SerialNumber");
            final BigInteger issuerSerial = new BigInteger(issuerSerialElement.getTextContent());

            for (final X509Certificate sourceCertificate : certificates) {

                final BigInteger sourceSerial = sourceCertificate.getSerialNumber();
                if (!sourceSerial.equals(issuerSerial)) {
                    continue;
                }

                final X500Principal sourcePrincipal = sourceCertificate.getIssuerX500Principal();
                final String sourceDNBare = sourcePrincipal.getName();
                final String sourceDN = X500PrincipalMatcher.maybePatchDN(sourceDNBare); // ECDX-59 (see method doc)
                final X500Name sourceName = new X500Name(sourceDN);
                if (!X500PrincipalMatcher.viaAny(sourceName, issuerName)) {
                    continue;
                }

                return sourceCertificate;
            }
        }
        return null;
    }

    @Override
    public Date getSigningTime() {

        try {

            Element signingTimeEl = DSSXMLUtils.getElement(signatureElement, XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SigningTime");
            if (signingTimeEl == null) {
                return null;
            }
            String text = signingTimeEl.getTextContent();
            DatatypeFactory factory = DatatypeFactory.newInstance();
            XMLGregorianCalendar cal = factory.newXMLGregorianCalendar(text);
            return cal.toGregorianCalendar().getTime();
        } catch (DOMException e) {
            throw new RuntimeException(e);
        } catch (DatatypeConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public PolicyValue getPolicyId() {

        Element policyId = DSSXMLUtils.getElement(signatureElement, XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SignaturePolicyIdentifier");
        if (policyId != null) {
         /* There is a policy */
            Element el = DSSXMLUtils.getElement(policyId, "./xades:SignaturePolicyId/xades:SigPolicyId/xades:Identifier");
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
    public String getLocation() {

        return null;
    }

    @Override
    public String[] getClaimedSignerRoles() {

        NodeList list = DSSXMLUtils
              .getNodeList(signatureElement, XPATH_SIGNED_SIGNATURE_PROPERTIES + "/xades:SignerRole/xades:ClaimedRoles/xades:ClaimedRole");

        if (list.getLength() == 0) {
            return null;
        }

        String[] roles = new String[list.getLength()];
        for (int i = 0; i < list.getLength(); i++) {
            roles[i] = ((Element) list.item(i)).getTextContent();
        }

        return roles;

    }

    @Override
    public String getContentType() {

        return "text/xml";
    }

    private TimestampToken makeTimestampToken(Element el, TimestampToken.TimestampType timestampType) throws XPathExpressionException {

        Element timestampTokenNode = DSSXMLUtils.getElement(el, "./xades:EncapsulatedTimeStamp");
        try {

            byte[] tokenbytes = DSSUtils.base64Decode(timestampTokenNode.getTextContent());
            TimeStampToken tstoken = new TimeStampToken(new CMSSignedData(tokenbytes));
            return new TimestampToken(tstoken, timestampType);
        } catch (Exception e) {

            throw new RuntimeException(e);
        }
    }

    // private List<TimestampToken> findTimestampTokens(String elementName, TimestampToken.TimestampType timestampType)
    // throws XPathExpressionException {
    // NodeList timestampsNodes = this.signatureElement.getElementsByTagName(elementName);
    // List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
    //
    // for (int i = 0; i < timestampsNodes.getLength(); i++) {
    // TimestampToken tstoken = makeTimestampToken((Element) timestampsNodes.item(i), timestampType);
    // if (tstoken != null) {
    // signatureTimestamps.add(tstoken);
    // }
    // }
    //
    // return signatureTimestamps;
    // }
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

        return DSSXMLUtils.getElement(signatureElement, XAdESSignature.XPATH_QUALIFYING_PROPERTIES);
    }

    public Element getSignedProperties() {

        return DSSXMLUtils.getElement(signatureElement, XAdESSignature.XPATH_SIGNED_PROPERTIES);
    }

    public Element getSignedSignatureProperties() {

        return DSSXMLUtils.getElement(signatureElement, XAdESSignature.XPATH_SIGNED_SIGNATURE_PROPERTIES);
    }

    public Element getUnsignedSignatureProperties() {

        return DSSXMLUtils.getElement(signatureElement, XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
    }

    public Element getUnsignedProperties() {

        return DSSXMLUtils.getElement(signatureElement, XPATH_UNSIGNED_PROPERTIES);
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
    public List<TimestampToken> getSignatureTimestamps() {

        try {

            List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
            NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, XPATH_SIGNATURE_TIMESTAMP);
            for (int i = 0; i < timestampsNodes.getLength(); i++) {

                TimestampToken tstoken = makeTimestampToken((Element) timestampsNodes.item(i), TimestampType.SIGNATURE_TIMESTAMP);
                if (tstoken != null) {

                    signatureTimestamps.add(tstoken);
                }
            }

            return signatureTimestamps;
        } catch (XPathExpressionException e) {

            throw new EncodingException(MSG.SIGNATURE_TIMESTAMP_ENCODING);
        }
    }

    @Override
    public List<TimestampToken> getTimestampsX1() {

        try {
            List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
            NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:SigAndRefsTimeStamp");
            for (int i = 0; i < timestampsNodes.getLength(); i++) {
                TimestampToken tstoken = makeTimestampToken((Element) timestampsNodes.item(i),
                      TimestampToken.TimestampType.VALIDATION_DATA_TIMESTAMP);
                if (tstoken != null) {
                    signatureTimestamps.add(tstoken);
                }
            }

            return signatureTimestamps;
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.TIMESTAMP_X1_ENCODING);
        }
    }

    @Override
    public List<TimestampToken> getTimestampsX2() {

        try {
            List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
            NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:RefsOnlyTimeStamp");
            for (int i = 0; i < timestampsNodes.getLength(); i++) {
                TimestampToken tstoken = makeTimestampToken((Element) timestampsNodes.item(i),
                      TimestampToken.TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
                if (tstoken != null) {
                    signatureTimestamps.add(tstoken);
                }
            }

            return signatureTimestamps;
        } catch (XPathExpressionException e) {
            throw new EncodingException(MSG.TIMESTAMP_X2_ENCODING);
        }
    }

    @Override
    public List<TimestampToken> getArchiveTimestamps() {

        try {

            List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();
            NodeList timestampsNodes = DSSXMLUtils.getNodeList(signatureElement, XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades141:ArchiveTimeStamp");
            for (int i = 0; i < timestampsNodes.getLength(); i++) {

                TimestampToken tstoken = makeTimestampToken((Element) timestampsNodes.item(i), TimestampToken.TimestampType.ARCHIVE_TIMESTAMP);
                if (tstoken != null) {

                    signatureTimestamps.add(tstoken);
                }
            }
            return signatureTimestamps;
        } catch (XPathExpressionException e) {

            throw new EncodingException(MSG.ARCHIVE_TIMESTAMP_ENCODING);
        }
    }

    /*
     * Returns the list of certificates encapsulated in the signature
     *
     * @see eu.europa.ec.markt.dss.validation.AdvancedSignature#getCertificates()
     */
    @Override
    public List<X509Certificate> getCertificates() {

        return getCertificateSource().getCertificates();
    }

    /*
     * Returns the list of certificates encapsulated in the KeyInfo segment
     */
    public List<X509Certificate> getKeyInfoCertificates() {

        return getCertificateSource().getKeyInfoCertificates();
    }

    @Override
    public boolean checkIntegrity(DSSDocument detachedDocument) throws DSSException {

        X509Certificate signingCert = getSigningCertificate();
        if (signingCert != null) {

            PublicKey publicKey = signingCert.getPublicKey();
            KeySelector keySelector = KeySelector.singletonKeySelector(publicKey);

            /**
             * Creating a Validation Context<br>
             * We create an XMLValidateContext instance containing input parameters for validating the signature. Since we
             * are using DOM, we instantiate a DOMValidateContext instance (a subclass of XMLValidateContext), and pass it
             * two parameters, a KeyValueKeySelector object and a reference to the Signature element to be validated (which
             * is the first entry of the NodeList we generated earlier):
             */
            DOMValidateContext valContext = new DOMValidateContext(keySelector, signatureElement);
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
                XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());

                /**
                 * We then invoke the unmarshalXMLSignature method of the factory to unmarshal an XMLSignature object, and
                 * pass it the validation context we created earlier:
                 */
                XMLSignature signature = factory.unmarshalXMLSignature(valContext);

                // Austrian specific signature
                // org.apache.xml.security.signature.XMLSignature signature_ = null;
                // try {
                // signature_ = new org.apache.xml.security.signature.XMLSignature(signatureElement, "");
                // } catch (Exception e) {
                //
                // throw new DSSException(e);
                // }
                // signature.addResourceResolver(new XPointerResourceResolver(signatureElement));

                /**
                 * In case of org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI() provider, the ID attributes need to be set
                 * manually.<br>
                 * The DSSXMLUtils.recursiveIdBrowse(...) method do not take into account the XML outside of the Signature
                 * tag. It prevents some signatures o be validated.<br>
                 * TODO: Bob (20130610) This must be corrected.
                 */
                DSSXMLUtils.recursiveIdBrowse(valContext, signatureElement);

                /**
                 * Validating the XML Signature<br>
                 * Now we are ready to validate the signature. We do this by invoking the validate method on the
                 * XMLSignature object, and pass it the validation context as follows:
                 */
                boolean coreValidity = false;
                try {

                    coreValidity = signature.validate(valContext);
                } catch (XMLSignatureException e) {

                    // corValidity is false
                }

                /**
                 * If the XMLSignature.validate method returns false, we can try to narrow down the cause of the failure.
                 * There are two phases in core XML Signature validation: <br>
                 * - Signature validation (the cryptographic verification of the signature)<br>
                 * - Reference validation (the verification of the digest of each reference in the signature)<br>
                 * Each phase must be successful for the signature to be valid. To check if the signature failed to
                 * cryptographically validate, we can check the status, as follows:
                 */

                try {

                    signature.getSignatureValue().validate(valContext);
                } catch (XMLSignatureException e) {

                    // this just computes references
                }

                @SuppressWarnings("unchecked") List<Reference> references = signature.getSignedInfo().getReferences();
                for (Reference reference : references) {

                    try {

                        reference.validate(valContext);
                    } catch (XMLSignatureException e) {

                    }
                    Data data = reference.getDereferencedData();
                    InputStream digestInputStream = reference.getDigestInputStream();
                    if (data != null) {

                        // The references are saved for later treatment in -A level.
                        try {

                            // !!! to be commented
                            // LOG.setLevel(Level.FINE);
                            // LOG.fine("Reference: " + reference.getId());
                            // IOUtils.copy(digestInputStream, System.out);
                            // System.out.println("");
                            IOUtils.copy(digestInputStream, referencesDigestOutputStream);
                        } catch (IOException e) {
                        }
                    }
                }
                return coreValidity;
            } catch (MarshalException e) {

                throw new DSSException(e.toString());
            }
        } else {

            throw new DSSException("Unabled to proceed with the signature cryptographic verification. There is no signing certificate!");
        }
    }

    @Override
    public List<AdvancedSignature> getCounterSignatures() {

        // see ETSI TS 101 903 V1.4.2 (2010-12) pp. 38/39/40

        try {
            NodeList counterSigs = DSSXMLUtils.getNodeList(signatureElement, XPATH_UNSIGNED_SIGNATURE_PROPERTIES + "/xades:CounterSignature");
            if (counterSigs == null) {
                return null;
            }

            List<AdvancedSignature> xadesList = new ArrayList<AdvancedSignature>();

            for (int i = 0; i < counterSigs.getLength(); i++) {
                Element counterSigEl = (Element) counterSigs.item(i);
                Element signatureEl = DSSXMLUtils.getElement(counterSigEl, "./ds:Signature");

                // Verify that the element is a proper signature by trying to build a XAdESSignature out of it
                XAdESSignature xCounterSig = new XAdESSignature(signatureEl);

                // Verify that there is a ds:Reference element with a Type set to:
                // http://uri.etsi.org/01903#CountersignedSignature
                // (as per the XAdES spec)
                XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
                XMLSignature signature = factory.unmarshalXMLSignature(new DOMStructure(signatureEl));

                LOG.info("Verifying countersignature References");
                for (Object refobj : signature.getSignedInfo().getReferences()) {
                    Reference ref = (Reference) refobj;
                    if (ref.getType() != null && ref.getType().equals("http://uri.etsi.org/01903#CountersignedSignature")) {
                        // Ok, this seems to be a CounterSignature

                        // Verify that the digest is that of the signature value
                        if (ref.validate(new DOMValidateContext(xCounterSig.getSigningCertificate().getPublicKey(),
                              DSSXMLUtils.getElement(signatureElement, XPATH_SIGNATURE_VALUE)))) {

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
            throw new EncodingException(MSG.COUNTERSIGNATURE_ENCODING);
        } catch (XMLSignatureException e) {
            throw new EncodingException(MSG.COUNTERSIGNATURE_ENCODING);
        }

    }

    @Override
    public List<CertificateRef> getCertificateRefs() {

        Element signingCertEl = DSSXMLUtils.getElement(signatureElement, XPATH_COMPLETE_CERTIFICATE_REFS + "/xades:CertRefs");
        if (signingCertEl == null) {
            return null;
        }

        List<CertificateRef> certIds = new ArrayList<CertificateRef>();
        NodeList certIdnodes = DSSXMLUtils.getNodeList(signingCertEl, "./xades:Cert");
        for (int i = 0; i < certIdnodes.getLength(); i++) {
            Element certId = (Element) certIdnodes.item(i);
            Element issuerNameEl = DSSXMLUtils.getElement(certId, "./xades:IssuerSerial/ds:X509IssuerName");
            Element issuerSerialEl = DSSXMLUtils.getElement(certId, "./xades:IssuerSerial/ds:X509SerialNumber");
            Element digestAlgorithmEl = DSSXMLUtils.getElement(certId, "./xades:CertDigest/ds:DigestMethod");
            Element digestValueEl = DSSXMLUtils.getElement(certId, "./xades:CertDigest/ds:DigestValue");

            CertificateRef genericCertId = new CertificateRef();
            if (issuerNameEl != null && issuerSerialEl != null) {
                genericCertId.setIssuerName(issuerNameEl.getTextContent());
                genericCertId.setIssuerSerial(issuerSerialEl.getTextContent());
            }

            String algorithm = digestAlgorithmEl.getAttribute("Algorithm");
            genericCertId.setDigestAlgorithm(getShortAlgoName(algorithm));

            genericCertId.setDigestValue(DSSUtils.base64Decode(digestValueEl.getTextContent()));
            certIds.add(genericCertId);
        }

        return certIds;
    }

    private String getShortAlgoName(String longAlgoName) {

        // TODO by meyerfr 20130201: in DigestMethod is another constant. I would centralise this method there, otherwise
        // it will be overlooked when introducing something new!
        if (DigestMethod.SHA1.equals(longAlgoName)) {
            return "SHA1";
        } else if (DigestMethod.SHA256.equals(longAlgoName)) {
            return "SHA256";
        } else if (DigestMethod.SHA512.equals(longAlgoName)) {
            return "SHA512";
        } else if (DigestMethod.RIPEMD160.equals(longAlgoName)) {
            return "RIPEMD160";
        } else {
            throw new RuntimeException("Algorithm " + longAlgoName + " not supported");
        }
    }

    @Override
    public List<CRLRef> getCRLRefs() {

        List<CRLRef> certIds = new ArrayList<CRLRef>();

        Element signingCertEl = DSSXMLUtils.getElement(signatureElement, XPATH_COMPLETE_REVOCATION_REFS + "/xades:CRLRefs");
        if (signingCertEl != null) {

            NodeList certIdnodes = DSSXMLUtils.getNodeList(signingCertEl, "./xades:CRLRef");
            for (int i = 0; i < certIdnodes.getLength(); i++) {
                Element certId = (Element) certIdnodes.item(i);
                Element digestAlgorithmEl = DSSXMLUtils.getElement(certId, "./xades:DigestAlgAndValue/ds:DigestMethod");
                Element digestValueEl = DSSXMLUtils.getElement(certId, "./xades:DigestAlgAndValue/ds:DigestValue");

                String algorithm = digestAlgorithmEl.getAttribute("Algorithm");
                String digestAlgo = getShortAlgoName(algorithm);

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
        Element signingCertEl = DSSXMLUtils.getElement(signatureElement, XPATH_COMPLETE_REVOCATION_REFS + "/xades:OCSPRefs");
        if (signingCertEl != null) {

            NodeList certIdnodes = DSSXMLUtils.getNodeList(signingCertEl, "./xades:OCSPRef");
            for (int i = 0; i < certIdnodes.getLength(); i++) {
                Element certId = (Element) certIdnodes.item(i);
                Element digestAlgorithmEl = DSSXMLUtils.getElement(certId, "./xades:DigestAlgAndValue/ds:DigestMethod");
                Element digestValueEl = DSSXMLUtils.getElement(certId, "./xades:DigestAlgAndValue/ds:DigestValue");

                if (digestAlgorithmEl == null || digestValueEl == null) {
                    throw new NotETSICompliantException(NotETSICompliantException.MSG.XADES_DIGEST_ALG_AND_VALUE_ENCODING);
                }

                String algorithm = digestAlgorithmEl.getAttribute("Algorithm");
                String digestAlgo = getShortAlgoName(algorithm);

                certIds.add(new OCSPRef(digestAlgo, DSSUtils.base64Decode(digestValueEl.getTextContent()), false));
            }
        }
        return certIds;
    }

    @Override
    public List<X509CRL> getCRLs() {

        XAdESCRLSource source = getCRLSource();
        return source.getContainedCRLs();
    }

    @Override
    public List<BasicOCSPResp> getOCSPs() {

        return getOCSPSource().getContainedOCSPResponses();
    }

    /**
     * This method returns the array of canonicalised bytes with the given canonicalisation method.
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
     * This method returns the array of canonicalised bytes with the given canonicalisation method.
     *
     * @param nodeList
     * @param canonicalizationMethod
     * @return
     */
    private byte[] getC14nValue(List<Node> nodeList, String canonicalizationMethod) {

        try {

            Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
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
        return getC14nValue(signatureValue, SignatureExtension.timestampCanonicalizationMethod);
    }

    @Override
    public byte[] getTimestampX1Data() {

        String canonicalizationMethod = XMLDSIG_DEFAULT_CANONICALIZATION_METHOD;
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
        return getC14nValue(timeStampNodesXadesX2, SignatureExtension.timestampCanonicalizationMethod);
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
     * @see eu.europa.ec.markt.dss.validation.AdvancedSignature#getArchiveTimestampData(int, eu.europa.ec.markt.dss.signature.DSSDocument)
     */
    @Override
    public byte[] getArchiveTimestampData(int index, DSSDocument originalData) {

        // the originalData is not used with XAdES signature

        String canonicalizationMethod = XMLDSIG_DEFAULT_CANONICALIZATION_METHOD;
        Element canonicalizationMethodEl = DSSXMLUtils.getElement(signatureElement, XPATH_ARCHIVE_TIMESTAMP + XPATH__CANONICALIZATION_METHOD);
        if (canonicalizationMethodEl != null) {

            canonicalizationMethod = canonicalizationMethodEl.getTextContent();
        }

        byte[] cannonicalizedValue = null;

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

            // XMLStructure xmlStructure = new DOMStructure(signatureElement);
            // XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());
            // DOMXMLSignature domXmlSignature = (DOMXMLSignature) factory.unmarshalXMLSignature(xmlStructure);
            // for (Object reference : domXmlSignature.getSignedInfo().getReferences()) {
            //
            // InputStream data = ((DOMReference) reference).getDigestInputStream();
            // if (data != null) {
            //
            // IOUtils.copy(data, buffer);
            // }
            // }

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
            cannonicalizedValue = getC14nValue(signedInfo, canonicalizationMethod);
            buffer.write(cannonicalizedValue);

            Element signatureValue = DSSXMLUtils.getElement(signatureElement, XPATH_SIGNATURE_VALUE);
            cannonicalizedValue = getC14nValue(signatureValue, canonicalizationMethod);
            buffer.write(cannonicalizedValue);

            Element keyInfo = DSSXMLUtils.getElement(signatureElement, XPATH_KEY_INFO);
            cannonicalizedValue = getC14nValue(keyInfo, canonicalizationMethod);
            buffer.write(cannonicalizedValue);

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
                } else if (localName.equals("ArchiveTimeStamp")) {

                    if (archiveTimeStampCount++ >= index) {

                        continue;
                    }
                }
                cannonicalizedValue = getC14nValue(node, canonicalizationMethod);
                buffer.write(cannonicalizedValue);
            }
            /**
             * 5) Take all the ds:Object elements except the one containing xades:QualifyingProperties element.
             * Canonicalize each one and concatenate each resulting octet stream to the final octet stream. If
             * ds:Canonicalization is present, the algorithm indicated by this element is used. If not, the standard
             * canonicalization method specified by XMLDSIG is used.
             */
            NodeList objects = getObjects();
            for (int ii = 0; ii < objects.getLength(); ii++) {

                Node node = objects.item(ii);
                Node qualifyingProperties = DSSXMLUtils.getElement(node, "./xades:QualifyingProperties");
                if (qualifyingProperties != null) {

                    continue;
                }
                cannonicalizedValue = getC14nValue(node, canonicalizationMethod);
                buffer.write(cannonicalizedValue);
            }
            if (LOG.isLoggable(Level.INFO)) {
                LOG.info("ArchiveTimestamp cannonicalized string:\n" + buffer.toString());
            }
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

            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(Long.toString(getSigningTime().getTime()).getBytes());
            digest.update(getSigningCertificate().getEncoded());
            return Hex.encodeHexString(digest.digest());
        } catch (Exception e) {

            throw new RuntimeException(e);
        }
    }
}
