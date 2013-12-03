package eu.europa.ec.markt.dss.signature.xades;

import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;
import java.util.logging.Level;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.SignatureParameters.Policy;
import eu.europa.ec.markt.dss.validation.xades.XAdESSignature;
import eu.europa.ec.markt.tsl.jaxb.xades.AnyType;
import eu.europa.ec.markt.tsl.jaxb.xades.CertIDListType;
import eu.europa.ec.markt.tsl.jaxb.xades.CertIDType;
import eu.europa.ec.markt.tsl.jaxb.xades.ClaimedRolesListType;
import eu.europa.ec.markt.tsl.jaxb.xades.DataObjectFormatType;
import eu.europa.ec.markt.tsl.jaxb.xades.DigestAlgAndValueType;
import eu.europa.ec.markt.tsl.jaxb.xades.IdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.ObjectIdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.QualifyingPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xades.SignaturePolicyIdType;
import eu.europa.ec.markt.tsl.jaxb.xades.SignaturePolicyIdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.SignedDataObjectPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xades.SignedPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xades.SignedSignaturePropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xades.SignerRoleType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.CanonicalizationMethodType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.DigestMethodType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.KeyInfoType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.ObjectType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.ReferenceType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.SignatureMethodType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.SignatureType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.SignatureValueType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.SignedInfoType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.TransformType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.TransformsType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.X509DataType;

/**
 * This class implements all the necessary mechanisms to build each form of the XML signature.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
public abstract class SignatureBuilder extends XAdESBuilder {

    /*
     * Indicates if the signature was already built. (Two steps building)
     */
    protected boolean built = false;
    /*
     * This is the variable which represents the JAXB root element of the signature. It is used to marshall.
     */
    protected JAXBElement<SignatureType> signature;

    /*
     * This variable represents JAXB signature object.
     */
    protected SignatureType signatureT;

    /*
     * This variable represents JAXB SignedProperties object.
     */
    protected SignedPropertiesType sPropertiesT;

    /*
     * This is the reference to the original document to sign
     */
    protected DSSDocument origDoc;

    protected String signedInfoCanonicalizationMethod;
    protected String reference2CanonicalizationMethod;

    /**
     * Creates the signature according to the packaging
     *
     * @param params   The set of parameters relating to the structure and process of the creation or extension of the
     *                 electronic signature.
     * @param document The original document to sign.
     * @return
     */
    public static SignatureBuilder getSignatureBuilder(SignatureParameters params, DSSDocument document) {

        switch (params.getSignaturePackaging()) {
            case ENVELOPED:
                return new EnvelopedSignatureBuilder(params, document);
            case ENVELOPING:
                return new EnvelopingSignatureBuilder(params, document);
            case DETACHED:
                return new DetachedSignatureBuilder(params, document);
            default:

                throw new IllegalArgumentException("Unsupported packaging " + params.getSignaturePackaging());
        }
    }

    /**
     * The default constructor for SignatureBuilder.
     *
     * @param params  The set of parameters relating to the structure and process of the creation or extension of the
     *                electronic signature.
     * @param origDoc The original document to sign.
     */
    public SignatureBuilder(SignatureParameters params, DSSDocument origDoc) {

        this.params = params;
        this.origDoc = origDoc;
    }

    /**
     * This is the main method which is called to build the XML signature
     *
     * @return A byte array is returned with XML that represents the canonicalized <ds:SignedInfo> segment of signature.
     *         This data are used to define the <ds:SignatureValue> element.
     * @throws CertificateEncodingException
     * @throws JAXBException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     *
     * @throws InvalidCanonicalizerException
     * @throws CanonicalizationException
     * @throws IOException
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws DSSException
     */
    public byte[] build() throws DSSException {

        signatureT = xmlDSigFactory.createSignatureType();
        signature = xmlDSigFactory.createSignature(signatureT);

        signatureT.setId("sigId-" + params.getDeterministicId());

        signatureT.setSignatureValue(createSignatureValue());

        signatureT.setKeyInfo(createKeyInfo());

        signatureT.getObject().add(createObject());

        /**
         * We create <ds:SignedInfo> segment only now because we need first to define the SignedProperties block to
         * calculate the digest of references.
         */
        SignedInfoType signedInfoT = createSignedInfo();
        signatureT.setSignedInfo(signedInfoT);

        // Preparation of SignedInfo
        try {

            byte[] string = normaliseSignatureNS(signature);
            Document domDocument = DSSXMLUtils.buildDOM(string);

            final Element signatureDOM = (Element) domDocument.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);
            final XAdESSignature xadesSignature = new XAdESSignature(signatureDOM);
            final Element domSignedInfo = xadesSignature.getSignedInfo();
            final Canonicalizer c14n = Canonicalizer.getInstance(signedInfoCanonicalizationMethod);
            byte[] canonicalizeSubTree = c14n.canonicalizeSubtree(domSignedInfo);
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine("Canonicalized SignedInfo         -->" + new String(canonicalizeSubTree));
            }
            built = true;
            return canonicalizeSubTree;
        } catch (InvalidCanonicalizerException e) {
            throw new DSSException(e);
        } catch (CanonicalizationException e) {
            throw new DSSException(e);
        } catch (ParserConfigurationException e) {
            throw new DSSException(e);
        } catch (IOException e) {
            throw new DSSException(e);
        } catch (SAXException e) {
            throw new DSSException(e);
        }
    }

    /**
     * @param jexbElement
     * @return
     */
    protected byte[] normaliseSignatureNS(JAXBElement<?> jexbElement) {

        StringWriter stringWriter = new StringWriter();
        try {

            marshaller.marshal(jexbElement, stringWriter);
        } catch (JAXBException e) {

            throw new DSSException(e);
        }
        String string = stringWriter.toString();

        // string = string.replace("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>", "");
        string = string.replace("xmlns:ns2", "xmlns:ds");
        string = string.replace("<ns2:", "<ds:");
        string = string.replace("</ns2:", "</ds:");
        if (LOG.isLoggable(Level.FINE)) {

            LOG.log(Level.FINE, "Normalised NS                     -->" + string);
        }
        return string.getBytes();
    }

    /**
     * Creates CanonicalizationMethod JAXB object.
     *
     * @return
     */
    protected CanonicalizationMethodType createCanonicalizationMethod(String canonicalizationMethod) {

        final CanonicalizationMethodType canonicalizationMethodT = xmlDSigFactory.createCanonicalizationMethodType();
        canonicalizationMethodT.setAlgorithm(canonicalizationMethod);
        return canonicalizationMethodT;
    }

    /**
     * Creates the digest value of the original document
     *
     * @return byte representation of the digest of the original document to sign.
     * @throws DSSException
     */
    protected byte[] createDigest(byte[] bytes) throws DSSException {

        try {

            final MessageDigest digest = MessageDigest.getInstance(params.getDigestAlgorithm().getName());
            digest.update(bytes);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {

            throw new DSSException(e);
        }
    }

    /**
     * Creates KeyInfoType JAXB object
     *
     * @return
     * @throws DSSException
     */
    protected KeyInfoType createKeyInfo() throws DSSException {

        KeyInfoType keyInfoT = xmlDSigFactory.createKeyInfoType();
        List<Object> objects = keyInfoT.getContent();

        X509DataType x509DataT = xmlDSigFactory.createX509DataType();
        JAXBElement<X509DataType> x509Data = xmlDSigFactory.createX509Data(x509DataT);

        List<Object> certificates = x509DataT.getX509IssuerSerialOrX509SKIOrX509SubjectName();

        for (X509Certificate certificate : params.getCertificateChain()) {

            try {

                certificates.add(xmlDSigFactory.createX509DataTypeX509Certificate(certificate.getEncoded()));
            } catch (CertificateEncodingException e) {

                throw new DSSException("Error certificate encoding when create KeyInfoType JAXB Object.", e);
            }
        }
        objects.add(x509Data);
        return keyInfoT;
    }

    /**
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     *
     * @throws DSSException
     */
    protected ObjectType createObject() throws DSSException {

        ObjectType objectT = xmlDSigFactory.createObjectType();

        QualifyingPropertiesType qProperties = createQualifyingProperties();

        objectT.getContent().add(xadesFactory.createQualifyingProperties(qProperties));
        return objectT;
    }

    protected abstract QualifyingPropertiesType createQualifyingProperties() throws DSSException;

    /**
     * @return
     */
    protected abstract ReferenceType createReference1() throws DSSException;

    /**
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     *
     * @throws JAXBException
     * @throws InvalidCanonicalizerException
     * @throws SAXException
     * @throws IOException
     * @throws ParserConfigurationException
     * @throws CanonicalizationException
     */
    protected ReferenceType createReference2() throws DSSException {

        ReferenceType referenceT2 = xmlDSigFactory.createReferenceType();

        DigestMethodType digestMethodT = xmlDSigFactory.createDigestMethodType();
        digestMethodT.setAlgorithm(params.getDigestAlgorithm().getXmlId());
        referenceT2.setDigestMethod(digestMethodT);

        referenceT2.setType(XADES_TYPE);
        referenceT2.setURI("#xades-" + params.getDeterministicId());
        TransformsType transformsT = xmlDSigFactory.createTransformsType();
        TransformType transformT = xmlDSigFactory.createTransformType();
        transformT.setAlgorithm(reference2CanonicalizationMethod);
        transformsT.getTransform().add(transformT);
        referenceT2.setTransforms(transformsT);
        // We create the digest value of <SignedProperties> segment
        try {

            JAXBElement<SignedPropertiesType> signedProperties = xadesFactory.createSignedProperties(sPropertiesT);
            byte toBeCanonicalisedBytes[] = normaliseSignatureNS(signedProperties);
            Canonicalizer c14n = Canonicalizer.getInstance(reference2CanonicalizationMethod);
            byte canonicalizedBytes[] = c14n.canonicalize(toBeCanonicalisedBytes);
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine("Canonicalisation method           -->" + reference2CanonicalizationMethod);
            }
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine("Canonicalised SignedProperties NS -->" + new String(canonicalizedBytes));
            }
            MessageDigest digest_;
            digest_ = MessageDigest.getInstance(params.getDigestAlgorithm().getName());
            digest_.update(canonicalizedBytes);
            byte[] digestValue_ = digest_.digest();
            referenceT2.setDigestValue(digestValue_);
        } catch (InvalidCanonicalizerException e) {

            throw new DSSException(e);
        } catch (CanonicalizationException e) {

            throw new DSSException(e);
        } catch (ParserConfigurationException e) {

            throw new DSSException(e);
        } catch (IOException e) {

            throw new DSSException(e);
        } catch (SAXException e) {

            throw new DSSException(e);
        } catch (NoSuchAlgorithmException e) {

            throw new DSSException(e);
        }
        return referenceT2;
    }

    /**
     * @return
     */
    protected SignatureMethodType createSignatureMethode() {

        SignatureMethodType signatureMethodT = xmlDSigFactory.createSignatureMethodType();
        final SignatureAlgorithm signatureAlgo = SignatureAlgorithm.getAlgorithm(params.getEncryptionAlgorithm(), params.getDigestAlgorithm());
        signatureMethodT.setAlgorithm(signatureAlgo.getXMLId());
        return signatureMethodT;
    }

    /**
     * @return
     */
    protected SignatureValueType createSignatureValue() {

        SignatureValueType signatureValueT = xmlDSigFactory.createSignatureValueType();
        signatureValueT.setId("value-" + params.getDeterministicId());
        return signatureValueT;
    }

    /**
     * Creates the SignedInfo JAXB object representation
     *
     * @return
     * @throws InvalidAlgorithmParameterException
     *
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws SAXException
     * @throws ParserConfigurationException
     * @throws CanonicalizationException
     * @throws InvalidCanonicalizerException
     * @throws JAXBException
     */
    protected SignedInfoType createSignedInfo() throws DSSException {

        SignedInfoType signedInfoT = xmlDSigFactory.createSignedInfoType();
        signedInfoT.setSignatureMethod(createSignatureMethode());
        signedInfoT.setCanonicalizationMethod(createCanonicalizationMethod(signedInfoCanonicalizationMethod));

        signedInfoT.getReference().add(createReference1());
        signedInfoT.getReference().add(createReference2());
        return signedInfoT;
    }

    /**
     * Creates the Transform JAXB object representation
     *
     * @param canonicalizationMethod
     * @param xPath
     * @return
     */
    protected TransformType createTransform(String canonicalizationMethod, String xPath) {

        TransformType transformT = xmlDSigFactory.createTransformType();
        transformT.setAlgorithm(canonicalizationMethod);
        if (!xPath.isEmpty()) {

            List<Object> objects = transformT.getContent();
            objects.add(xmlDSigFactory.createTransformTypeXPath(xPath));
        }
        return transformT;
    }

    /**
     * Creates the QualifyingProperties JAXB object representation
     *
     * @param dataFormatRef
     * @param dataFormatMimetype
     * @return
     * @throws DSSException
     */
    protected QualifyingPropertiesType createXAdESQualifyingProperties(String dataFormatRef, String dataFormatMimetype) throws DSSException {

        // QualifyingProperties
        QualifyingPropertiesType qPropertiesT = xadesFactory.createQualifyingPropertiesType();

        sPropertiesT = xadesFactory.createSignedPropertiesType();
        qPropertiesT.setSignedProperties(sPropertiesT);

        sPropertiesT.setId("xades-" + params.getDeterministicId());

        SignedSignaturePropertiesType signedSignatureProperties = xadesFactory.createSignedSignaturePropertiesType();
        sPropertiesT.setSignedSignatureProperties(signedSignatureProperties);

        // SigningTime
        GregorianCalendar signingTime = new GregorianCalendar(TimeZone.getTimeZone("Z"));
        signingTime.setTime(params.getSigningDate());

        XMLGregorianCalendar xmlGregorianCalendar = _dataFactory.newXMLGregorianCalendar(signingTime);
        xmlGregorianCalendar.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
        signedSignatureProperties.setSigningTime(xmlGregorianCalendar);

        X509Certificate signingCertificate = params.getSigningCertificate();
        CertIDType signingCertificateId = getCertID(signingCertificate, DigestAlgorithm.SHA1);
        CertIDListType signingCertificates = xadesFactory.createCertIDListType();
        signingCertificates.getCert().add(signingCertificateId);
        signedSignatureProperties.setSigningCertificate(signingCertificates);

        SignedDataObjectPropertiesType dataObjectProperties = new SignedDataObjectPropertiesType();
        DataObjectFormatType dataFormat = new DataObjectFormatType();
        dataFormat.setObjectReference(dataFormatRef);
        dataFormat.setMimeType(dataFormatMimetype);
        dataObjectProperties.getDataObjectFormat().add(dataFormat);
        sPropertiesT.setSignedDataObjectProperties(dataObjectProperties);

        // SignerRole
        if (params.getClaimedSignerRole() != null) {

            SignerRoleType signerRole = xadesFactory.createSignerRoleType();
            ClaimedRolesListType claimedRoles = xadesFactory.createClaimedRolesListType();

            // Add only one role
            AnyType role = xadesFactory.createAnyType();
            role.getContent().add(params.getClaimedSignerRole());
            claimedRoles.getClaimedRole().add(role);
            signerRole.setClaimedRoles(claimedRoles);
            signedSignatureProperties.setSignerRole(signerRole);
        }
        qPropertiesT.setTarget("#sigId-" + params.getDeterministicId());

        Policy policy = params.getSignaturePolicy();
        if (policy != null && policy.getId() != null) {

            SignaturePolicyIdType policyId = xadesFactory.createSignaturePolicyIdType();
            SignaturePolicyIdentifierType policyIdentifier = xadesFactory.createSignaturePolicyIdentifierType();
            if (policy.getId() != "") { // explicit

                ObjectIdentifierType objectId = xadesFactory.createObjectIdentifierType();
                IdentifierType identifierT = xadesFactory.createIdentifierType();
                identifierT.setValue(policy.getId());
                objectId.setIdentifier(identifierT);
                policyId.setSigPolicyId(objectId);
                if (policy.getDigestAlgo() != null && policy.getHashValue() != null) {

                    DigestAlgAndValueType hash = xadesFactory.createDigestAlgAndValueType();
                    DigestMethodType digestAlgo = xmlDSigFactory.createDigestMethodType();
                    digestAlgo.setAlgorithm(policy.getDigestAlgo().getName());
                    hash.setDigestMethod(digestAlgo);
                    hash.setDigestValue(policy.getHashValue());
                    policyId.setSigPolicyHash(hash);
                }
                policyIdentifier.setSignaturePolicyId(policyId);
            } else { // implicit

                policyIdentifier.setSignaturePolicyImplied("");
            }
            qPropertiesT.getSignedProperties().getSignedSignatureProperties().setSignaturePolicyIdentifier(policyIdentifier);
        }
        return createXAdES_EPESQualifyingProperties(qPropertiesT);
    }

    /*
     * Creates Qualifying Properties JAXB object model with the signature policy (EPES)
     *
     * @see eu.europa.ec.markt.dss.signature.xades.XAdESProfileBES#
     * createXAdESQualifyingProperties(eu.europa.ec.markt.dss .signature.SignatureParameters, java.lang.String,
     * java.lang.String)
     */
    private QualifyingPropertiesType createXAdES_EPESQualifyingProperties(QualifyingPropertiesType qPropertiesT) throws DSSException {

        Policy policy = params.getSignaturePolicy();
        if (policy != null && policy.getId() != null) {

            SignaturePolicyIdType policyId = xadesFactory.createSignaturePolicyIdType();
            SignaturePolicyIdentifierType policyIdentifier = xadesFactory.createSignaturePolicyIdentifierType();
            if (policy.getId() != "") { // explicit

                ObjectIdentifierType objectId = xadesFactory.createObjectIdentifierType();
                IdentifierType identifierT = xadesFactory.createIdentifierType();
                identifierT.setValue(policy.getId());
                objectId.setIdentifier(identifierT);
                policyId.setSigPolicyId(objectId);
                if (policy.getDigestAlgo() != null && policy.getHashValue() != null) {

                    DigestAlgAndValueType hash = xadesFactory.createDigestAlgAndValueType();
                    DigestMethodType digestAlgo = xmlDSigFactory.createDigestMethodType();
                    digestAlgo.setAlgorithm(policy.getDigestAlgo().getName());
                    hash.setDigestMethod(digestAlgo);
                    hash.setDigestValue(policy.getHashValue());
                    policyId.setSigPolicyHash(hash);
                }
                policyIdentifier.setSignaturePolicyId(policyId);
                qPropertiesT.getSignedProperties().getSignedSignatureProperties().setSignaturePolicyIdentifier(policyIdentifier);
            } else { // implicit

                policyIdentifier.setSignaturePolicyImplied("");
                qPropertiesT.getSignedProperties().getSignedSignatureProperties().setSignaturePolicyIdentifier(policyIdentifier);
            }
        }
        return qPropertiesT;
    }

    /**
     * Adds signature value to the signature and returns XML signature (InMemoryDocument)
     *
     * @param signatureValue - Encoded value of the signature
     * @return
     * @throws DSSException
     */
    public abstract DSSDocument signDocument(final byte[] signatureValue) throws DSSException;
}