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

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.security.auth.x500.X500Principal;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.OID;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException;
import eu.europa.ec.markt.dss.exception.NotETSICompliantException.MSG;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.ProfileException;
import eu.europa.ec.markt.dss.validation.PolicyValue;
import eu.europa.ec.markt.dss.validation.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.bean.SigningCertificate;
import eu.europa.ec.markt.dss.validation102853.cades.CMSDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.condition.Condition;
import eu.europa.ec.markt.dss.validation102853.condition.PolicyIdCondition;
import eu.europa.ec.markt.dss.validation102853.condition.QcStatementCondition;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.ObjectFactory;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlArchiveTimestamps;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlCertificate;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlCertificateChainType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlChainCertificate;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlClaimedRoles;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlContentTimestamps;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlDigestAlgAndValueType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlInfoType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlIssuerDistinguishedName;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlMessage;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlPolicy;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlQCStatement;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlQualifiers;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlRefsOnlyTimestamps;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlRevocationType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSigAndRefsTimestamps;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignature;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignedObjectsType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSignedSignature;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSigningCertificateType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlSubjectDistinguishedName;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlTimestampType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlTimestamps;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.XmlUsedCertificates;
import eu.europa.ec.markt.dss.validation102853.pades.PDFDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.report.ValidationReport;
import eu.europa.ec.markt.dss.validation102853.toolbox.PublicKeyUtils;
import eu.europa.ec.markt.dss.validation102853.xades.XMLDocumentValidator;

/**
 * Validate the signed document
 *
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
public abstract class SignedDocumentValidator {

    private static final Logger LOG = Logger.getLogger(SignedDocumentValidator.class.getName());

    /*
     * The factory used to create DiagnosticData
     */
    protected static final ObjectFactory DIAGNOSTIC_DATA_OBJECT_FACTORY = new ObjectFactory();

    /**
     * This is the pool of certificates used in the validation process. The pools present in the certificate verifier are merged and added
     * to this pool.
     */
    protected CertificatePool validationCertPool = new CertificatePool();

    /**
     * This is the unique timestamp Id. It is unique within one validation process.
     */
    private int timestampIndex = 1;

    /**
     * The document to be validated (with the signatures)
     */
    protected DSSDocument document;

    /**
     * In case of a detached signature this is the signed document.
     */
    protected DSSDocument externalContent;

    /**
     * The reference to the certificate verifier. The current DSS implementation proposes
     * {@link CommonCertificateVerifier}. This verifier encapsulates the references to different sources used in the signature validation
     * process.
     */
    private CertificateVerifier certVerifier;

    /**
     * This variable contains the reference to the diagnostic data.
     */
    protected DiagnosticData dData;

    /**
     * This is the simple report generated at the end of the validation process.
     */
    protected SimpleReport simpleReport;

    /**
     * This is the detailed report of the validation.
     */
    ValidationReport detailedReport;

    private final Condition qcp = new PolicyIdCondition(OID._0_4_0_1456_1_2.getName());

    private final Condition qcpplus = new PolicyIdCondition(OID._0_4_0_1456_1_1.getName());

    private final Condition qccompliance = new QcStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance);

    private final Condition qcsscd = new QcStatementCondition(ETSIQCObjectIdentifiers.id_etsi_qcs_QcSSCD);

    private static final String MIMETYPE = "mimetype";

    // private static final String MIMETYPE_ASIC_S = "application/vnd.etsi.asic-s+zip";
    private static final String PATTERN_SIGNATURES_XML = "META-INF/(.*)(?i)signature(.*).xml";

    private static final String PATTERN_SIGNATURES_P7S = "META-INF/(.*)(?i)signature(.*).p7s";

    /**
     * Guess the document format and return an appropriate document
     *
     * @param document The instance of DSSDocument to be validated
     * @return returns the specific instance of SignedDocumentValidator in terms of the document type
     */
    public static SignedDocumentValidator fromDocument(final DSSDocument document) throws IOException {

        InputStream input = null;
        try {

            if (document.getName() != null && document.getName().toLowerCase().endsWith(".xml")) {

                try {

                    return new XMLDocumentValidator(document);
                } catch (ParserConfigurationException e) {
                    throw new IOException("Not a valid XML", e);
                } catch (SAXException e) {
                    throw new IOException("Not a valid XML", e);
                }
            }

            input = new BufferedInputStream(document.openStream());
            input.mark(5);
            byte[] preamble = new byte[5];
            int read = input.read(preamble);
            input.reset();
            if (read < 5) {

                throw new RuntimeException("Not a signed document");
            }
            String preambleString = new String(preamble);
            byte[] xmlPreamble = new byte[]{'<', '?', 'x', 'm', 'l'};
            byte[] xmlUtf8 = new byte[]{-17, -69, -65, '<', '?'};
            if (Arrays.equals(preamble, xmlPreamble) || Arrays.equals(preamble, xmlUtf8)) {

                try {

                    return new XMLDocumentValidator(document);
                } catch (ParserConfigurationException e) {
                    throw new IOException("Not a valid XML", e);
                } catch (SAXException e) {
                    throw new IOException("Not a valid XML", e);
                }
            } else if (preambleString.equals("%PDF-")) {

                return new PDFDocumentValidator(document);
            } else if (preamble[0] == 'P' && preamble[1] == 'K') {

                try {

                    input.close();
                } catch (IOException e) {
                }
                input = null;
                return getInstanceForAsics(document);
            } else if (preambleString.getBytes()[0] == 0x30) {

                try {

                    return new CMSDocumentValidator(document);
                } catch (CMSException e) {
                    throw new IOException("Not a valid CAdES file", e);
                }
            } else {
                throw new RuntimeException("Document format not recognized/handled");
            }
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                }
            }
        }
    }

    /**
     * @param document
     * @return
     * @throws IOException
     */
    private static SignedDocumentValidator getInstanceForAsics(DSSDocument document) throws IOException {

        ZipInputStream asics = new ZipInputStream(document.openStream());

        try {

            String dataFileName = "";
            ByteArrayOutputStream dataFile = null;
            ByteArrayOutputStream signatures = null;
            ZipEntry entry;

            boolean cadesSigned = false;
            boolean xadesSigned = false;

            while ((entry = asics.getNextEntry()) != null) {
                if (entry.getName().matches(PATTERN_SIGNATURES_P7S)) {
                    if (xadesSigned) {
                        throw new NotETSICompliantException(MSG.MORE_THAN_ONE_SIGNATURE);
                    }
                    signatures = new ByteArrayOutputStream();
                    IOUtils.copy(asics, signatures);
                    signatures.close();
                    cadesSigned = true;
                } else if (entry.getName().matches(PATTERN_SIGNATURES_XML)) {
                    if (cadesSigned) {
                        throw new NotETSICompliantException(MSG.MORE_THAN_ONE_SIGNATURE);
                    }
                    signatures = new ByteArrayOutputStream();
                    IOUtils.copy(asics, signatures);
                    signatures.close();
                    xadesSigned = true;
                } else if (entry.getName().equalsIgnoreCase(MIMETYPE)) {
                    ByteArrayOutputStream mimetype = new ByteArrayOutputStream();
                    IOUtils.copy(asics, mimetype);
                    mimetype.close();
                    // Mime type implementers MAY use
                    // "application/vnd.etsi.asic-s+zip" to identify this format
                    // or MAY
                    // maintain the original mimetype of the signed data object.
                } else if (entry.getName().indexOf("/") == -1) {
                    if (dataFile == null) {

                        dataFile = new ByteArrayOutputStream();
                        IOUtils.copy(asics, dataFile);
                        dataFile.close();
                        dataFileName = entry.getName();
                    } else {
                        throw new ProfileException("ASiC-S profile support only one data file");
                    }
                }
            }

            if (xadesSigned) {
                ASiCXMLDocumentValidator xmlValidator = new ASiCXMLDocumentValidator(new InMemoryDocument(signatures.toByteArray()),
                      dataFile.toByteArray(), dataFileName);
                return xmlValidator;
            } else if (cadesSigned) {
                CMSDocumentValidator pdfValidator = new CMSDocumentValidator(new InMemoryDocument(signatures.toByteArray()));
                pdfValidator.setExternalContent(new InMemoryDocument(dataFile.toByteArray()));
                return pdfValidator;
            } else {
                throw new RuntimeException("Is not xades nor cades signed");
            }

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        } finally {
            try {
                asics.close();
            } catch (IOException e) {
            }
        }

    }

    /*
     * In case of ASiC, this is the signature
     */
    public DSSDocument getDocument() {

        return document;
    }

    /**
     * @return the externalContent
     */
    public DSSDocument getExternalContent() {

        return externalContent;
    }

    /**
     * Retrieves the signatures found in the document
     *
     * @return a list of AdvancedSignatures for validation purposes
     */
    public abstract List<AdvancedSignature> getSignatures();

    /**
     * To carry out the validation process of the signature(s) some external sources of certificates and of revocation data can be needed.
     * The certificate verifier is used to pass these values. Note that once this setter is called any change in the content of the
     * <code>CommonTrustedCertificateSource</code> or in adjunct certificate source is not taken into account.
     *
     * @param certVerifier
     */
    public void setCertificateVerifier(final CertificateVerifier certVerifier) {

        this.certVerifier = certVerifier;

        TrustedCertificateSource trustedCertSource = certVerifier.getTrustedCertSource();
        if (trustedCertSource != null) {

            validationCertPool.merge(trustedCertSource.getCertificatePool());
        }
        CertificateSource adjunctCertSource = certVerifier.getAdjunctCertSource();
        if (adjunctCertSource != null) {

            validationCertPool.merge(adjunctCertSource.getCertificatePool());
        }
    }

    /**
     * Sets the Document containing the original content to sign, for detached signature scenarios.
     *
     * @param externalContent the externalContent to set
     */
    public void setExternalContent(final DSSDocument externalContent) {

        this.externalContent = externalContent;
    }

    /**
     * Validates the document and all its signatures. The default constraint file is used.
     */
    public ValidationReport validateDocument() {

        return validateDocument((InputStream) null);
    }

    /**
     * Validates the document and all its signatures. The default constraint file is used.
     */
    public ValidationReport validateDocument(URL validationPolicyURL) {
        if (validationPolicyURL == null) {
            return validateDocument((InputStream) null);
        } else {
            try {
                return validateDocument(validationPolicyURL.openStream());
            } catch (IOException e) {
                throw new DSSException(e);
            }
        }
    }

    /**
     * Validates the document and all its signatures. The policyResourcePath specifies the constraint file. If null or
     * empty the default file is used.
     *
     * @param policyResourcePath is located against the classpath (getClass().getResourceAsStream), and NOT the
     *                           filesystem
     */
    public ValidationReport validateDocument(final String policyResourcePath) {

        if (policyResourcePath == null) {
            return validateDocument((InputStream) null);
        } else {
            return validateDocument(getClass().getResourceAsStream(policyResourcePath));
        }
    }

    /**
     * Validates the document and all its signatures. The policyDataPath specifies the constraint file. If null or empty
     * the default file is used.
     *
     * @param policyDataStream
     */
    public ValidationReport validateDocument(final InputStream policyDataStream) {

        LOG.info("Document validation...");

        final DiagnosticData diagnosticDataJB = generateDiagnosticData();

        // Comment before release !!!
        // ValidationResourceManager.enableSaveDiagnosticData();
        // ValidationResourceManager.setDiagnosticDataFolder("");
        // End !!!

        ValidationResourceManager.saveDiagnosticData(diagnosticDataJB);

        final Document diagnosticData = ValidationResourceManager.convert(diagnosticDataJB);

        final Document policyData = ValidationResourceManager.loadPolicyData(policyDataStream);
        // TODO 130619 by meyerfr: create an interface for process executor and derive a BSCProcessExecutor from that
        final ProcessExecutor executor = getProcessExecutor(diagnosticData, policyData);
        detailedReport = executor.execute();
        simpleReport = executor.getSimpleReport();
        return detailedReport;
    }

    protected ProcessExecutor getProcessExecutor(Document diagnosticData, Document policyData) {
        return new ProcessExecutor(diagnosticData, policyData);
    }

    /**
     * This method generates the diagnostic data. This is the set of all data extracted from the signature, associated
     * certificates and trusted lists. The diagnostic data contains also the results of basic computations (hash check,
     * signature integrity, certificates chain...
     */
    private DiagnosticData generateDiagnosticData() {

        dData = DIAGNOSTIC_DATA_OBJECT_FACTORY.createDiagnosticData();
        dData.setDocumentName(document.getAbsolutePath());
        // dData.setDocumentType("");
        if (this instanceof XMLDocumentValidator) {

            dData.setSignatureFormat("XAdES");
        } else if (this instanceof PDFDocumentValidator) {

            dData.setSignatureFormat("PAdES");
        } else if (this instanceof CMSDocumentValidator) {

            dData.setSignatureFormat("CAdES");
        } else if (this instanceof ASiCXMLDocumentValidator) {

            dData.setSignatureFormat("ASiC-S");
        }
        final Set<DigestAlgorithm> usedCertificatesDigestAlgorithms = new HashSet<DigestAlgorithm>();

        final Set<CertificateToken> usedCertPool = new HashSet<CertificateToken>();
      /*
       * For each signature present in the file to be validated the extraction of diagnostic data is launched.
       */
        for (final AdvancedSignature signature : getSignatures()) {

            final ValidationContext valContext = new SignatureValidationContext(signature, certVerifier, validationCertPool);
            final XmlSignature xmlSignature = validateSignature(signature, valContext);
            final Set<CertificateToken> signatureCertPool = valContext.getProcessedCertificates();
            usedCertPool.addAll(signatureCertPool);
            usedCertificatesDigestAlgorithms.addAll(signature.getUsedCertificatesDigestAlgorithms());
            dData.getSignature().add(xmlSignature);
        }
        dealUsedCertificates(usedCertificatesDigestAlgorithms, usedCertPool);
        return dData;
    }

    /**
     * Main method for validating a signature. The diagnostic data is extracted.
     *
     * @param signature Signature to be validated (can be XAdES, CAdES, PAdES.
     * @return The JAXB object containing all diagnostic data pertaining to the signature
     */
    private XmlSignature validateSignature(final AdvancedSignature signature, final ValidationContext valContext) throws DSSException {

      /*
       * TODO: (Bob 20130424) The the certToValidate parameter must be added.
       */
        final XmlSignature xmlSignature = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignature();

        try {

            final CertificateToken signingToken = dealSignature(signature, xmlSignature);

            valContext.setCertificateToValidate(signingToken);

            valContext.validate();

            dealPolicy(signature, xmlSignature);

            dealCertificateChain(xmlSignature, signingToken);

            dealTimestamps(xmlSignature, valContext.getTimestampTokens());

            dealContentTimestamps(signature, xmlSignature);

            dealSigAndRefsTimestamp(xmlSignature, valContext.getSigAndRefsTimestamps());

            dealRefsOnlyTimestamp(xmlSignature, valContext.getRefsOnlyTimestamps());

            dealArchiveTimestamp(xmlSignature, valContext.getArchiveTimestamps());
        } catch (Exception e) {

            LOG.warning(e.toString() + "\n" + e.getStackTrace()[0].toString());
            String errorMessage = xmlSignature.getErrorMessage();
            if (errorMessage == null || errorMessage.isEmpty()) {

                xmlSignature.setErrorMessage(e.toString());
            } else {

                errorMessage += "<br>" + e.toString();
            }
        }
        return xmlSignature;
    }

    /**
     * @param xmlSignature
     * @param timestampTokens
     */
    private void dealTimestamps(XmlSignature xmlSignature, List<TimestampToken> timestampTokens) {

        if (!timestampTokens.isEmpty()) {

            XmlTimestamps xmlTimestamps = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlTimestamps();
            for (TimestampToken token : timestampTokens) {

                XmlTimestampType xmlTimestampToken = xmlForTimestamp(token, TimestampType.SIGNATURE_TIMESTAMP);
                xmlTimestamps.getTimestamp().add(xmlTimestampToken);
            }
            xmlSignature.setTimestamps(xmlTimestamps);
        }
    }

    /**
     * @param signature
     * @param xmlSignature
     */
    private void dealContentTimestamps(AdvancedSignature signature, XmlSignature xmlSignature) {

        List<TimestampToken> contentTimestampTokens = signature.getContentTimestamps();
        if (!contentTimestampTokens.isEmpty()) {

            XmlContentTimestamps xmlContentTimestamps = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlContentTimestamps();
            for (TimestampToken timestampToken : contentTimestampTokens) {

                XMLGregorianCalendar calendar = DSSUtils.createXMGregorianCalendar(timestampToken.getGenerationTime());
                xmlContentTimestamps.getProductionTime().add(calendar);
            }
            xmlSignature.setContentTimestamps(xmlContentTimestamps);
        }
    }

    private void dealSigAndRefsTimestamp(XmlSignature xmlSignature, List<TimestampToken> timestampTokens) {

        if (!timestampTokens.isEmpty()) {

            XmlSigAndRefsTimestamps xmlSigAndRefsTimestamps = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSigAndRefsTimestamps();
            for (TimestampToken token : timestampTokens) {

                XmlTimestampType xmlTimestampToken = xmlForTimestamp(token, TimestampType.VALIDATION_DATA_TIMESTAMP);
                xmlSigAndRefsTimestamps.getTimestamp().add(xmlTimestampToken);
            }
            xmlSignature.setSigAndRefsTimestamps(xmlSigAndRefsTimestamps);
        }
    }

    private void dealRefsOnlyTimestamp(XmlSignature xmlSignature, List<TimestampToken> timestampTokens) {

        if (!timestampTokens.isEmpty()) {

            XmlRefsOnlyTimestamps xmlRefsOnlyTimestamps = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlRefsOnlyTimestamps();
            for (TimestampToken token : timestampTokens) {

                XmlTimestampType xmlTimestampToken = xmlForTimestamp(token, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
                xmlRefsOnlyTimestamps.getTimestamp().add(xmlTimestampToken);
            }
            xmlSignature.setRefsOnlyTimestamps(xmlRefsOnlyTimestamps);
        }
    }

    private void dealArchiveTimestamp(XmlSignature xmlSignature, List<TimestampToken> timestampTokens) {

        if (!timestampTokens.isEmpty()) {

            XmlArchiveTimestamps xmlArchiveTimestamps = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlArchiveTimestamps();
            for (TimestampToken token : timestampTokens) {

                XmlTimestampType xmlTimestampToken = xmlForTimestamp(token, TimestampType.ARCHIVE_TIMESTAMP);
                xmlArchiveTimestamps.getTimestamp().add(xmlTimestampToken);
            }
            xmlSignature.setArchiveTimestamps(xmlArchiveTimestamps);
        }
    }

    /**
     * @param token
     * @return
     */
    private XmlTimestampType xmlForTimestamp(TimestampToken token, TimestampType timestampCategory) {

        TimestampToken timestampToken = (TimestampToken) token;
        XmlTimestampType xmlTimestampToken = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlTimestampType();
        xmlTimestampToken.setId(timestampIndex++);
        xmlTimestampToken.setCategory(timestampCategory.name());
        xmlTimestampToken.setProductionTime(DSSUtils.createXMGregorianCalendar(timestampToken.getGenerationTime()));
        xmlTimestampToken.setAlgoUsedToSignThisToken(timestampToken.getSignatureAlgo());
        String oid = timestampToken.getSignatureAlgoOID();
        if (oid != null) {

            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(oid);
            xmlTimestampToken.setAlgoOIDUsedToSignThisToken(oid);
            xmlTimestampToken.setEncryptionAlgoUsedToSignThisToken(signatureAlgorithm.getEncryptionAlgo().getName());
            xmlTimestampToken.setDigestAlgoUsedToSignThisToken(signatureAlgorithm.getDigestAlgo().getName());
        }
        String keyLength = getSigningKeyLength(timestampToken);
        xmlTimestampToken.setKeyLengthUsedToSignThisToken(keyLength);

        xmlTimestampToken.setSignedDataDigestAlgo(timestampToken.getSignedDataDigestAlgo().getName());
        xmlTimestampToken.setEncodedSignedDataDigestValue(timestampToken.getEncodedSignedDataDigestValue());
        xmlTimestampToken.setReferenceDataFound(timestampToken.isSignedDataFound());
        xmlTimestampToken.setReferenceDataIntact(timestampToken.isSignedDataIntact());
        xmlTimestampToken.setSignatureIntact(timestampToken.isSignatureIntact());
        XmlSigningCertificateType xmlTSSignCert = xmlForSigningCertificate(timestampToken);
        xmlTimestampToken.setSigningCertificate(xmlTSSignCert);

        CertificateToken issuerToken = timestampToken.getIssuerToken();
        if (issuerToken != null) {
            XmlCertificateChainType xmlCertChainType = xmlForCertificateChain(issuerToken);
            xmlTimestampToken.setCertificateChain(xmlCertChainType);
        }

        List<TimestampReference> timestampReferences = token.getTimestampedReferences();
        if (timestampReferences != null && !timestampReferences.isEmpty()) {

            XmlSignedObjectsType xmlSignedObjectsType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignedObjectsType();
            List<XmlDigestAlgAndValueType> xmlDigestAlgAndValueList = xmlSignedObjectsType.getDigestAlgAndValue();

            for (TimestampReference timestampReference : timestampReferences) {

                TimestampCategory timestampedCategory = timestampReference.getCategory();
                if (TimestampCategory.SIGNATURE.equals(timestampedCategory)) {

                    XmlSignedSignature xmlSignedSignature = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignedSignature();
                    xmlSignedSignature.setId(timestampReference.getSignatureId());
                    xmlSignedObjectsType.setSignedSignature(xmlSignedSignature);
                } else {

                    XmlDigestAlgAndValueType xmlDigestAlgAndValue = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlDigestAlgAndValueType();
                    xmlDigestAlgAndValue.setDigestMethod(timestampReference.getDigestAlgorithm());
                    xmlDigestAlgAndValue.setDigestValue(timestampReference.getDigestValue());
                    xmlDigestAlgAndValue.setCategory(timestampedCategory.name());
                    xmlDigestAlgAndValueList.add(xmlDigestAlgAndValue);
                }
            }
            xmlTimestampToken.setSignedObjects(xmlSignedObjectsType);
        }
        return xmlTimestampToken;
    }

    /**
     * @param issuerToken
     * @return
     */
    private XmlCertificateChainType xmlForCertificateChain(CertificateToken issuerToken) {

        XmlCertificateChainType xmlCertChainType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlCertificateChainType();
        List<XmlChainCertificate> certChainTokens = xmlCertChainType.getChainCertificate();
        do {

            XmlChainCertificate xmlCertToken = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlChainCertificate();
            xmlCertToken.setId(issuerToken.getDSSId());
            List<CertificateSourceType> list = issuerToken.getSource();
            if (list.size() > 0) {

                xmlCertToken.setSource(list.get(0).name());
            } else {

                xmlCertToken.setSource("UNKNOWN");
            }
            certChainTokens.add(xmlCertToken);
            if (issuerToken.isTrusted() || issuerToken.isSelfSigned()) {

                break;
            }
            issuerToken = issuerToken.getIssuerToken();
        } while (issuerToken != null);
        return xmlCertChainType;
    }

    /**
     * @param usedCertificatesDigestAlgorithms
     *
     * @param usedCertTokens
     */
    private void dealUsedCertificates(final Set<DigestAlgorithm> usedCertificatesDigestAlgorithms, final Set<CertificateToken> usedCertTokens) {

        final XmlUsedCertificates xmlUsedCerts = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlUsedCertificates();
        dData.setUsedCertificates(xmlUsedCerts);
        for (final CertificateToken certToken : usedCertTokens) {

            final XmlCertificate xmlCert = dealCertificateDetails(usedCertificatesDigestAlgorithms, certToken);
            // !!! Log the certificate
            // if (LOG.isLoggable(Level.INFO)) {
            //
            // LOG.info("PEM for certificate: " + certToken.getAbbreviation() + "--->");
            // try {
            //
            // final String pem = DSSUtils.convertToPEM(certToken.getCertificate());
            // LOG.info("\n" + pem);
            // } catch (CertificateEncodingException e) {
            // }
            // }
            dealQCStatement(certToken, xmlCert);
            dealTrustedService(certToken, xmlCert);
            dealRevocationData(certToken, xmlCert);
            dealCertificateValidationInfo(certToken, xmlCert);
            xmlUsedCerts.getCertificate().add(xmlCert);
        }
    }

    /**
     * This method deals with the Qualified Certificate Statements. The retrieved information is transformed to the JAXB
     * object.<br>
     * Qualified Certificate Statements, the following Policies are checked:<br>
     * - Qualified Certificates Policy "0.4.0.1456.1.1” (QCP);<br>
     * - Qualified Certificates Policy + "0.4.0.1456.1.2" (QCP+);<br>
     * - Qualified Certificates Compliance "0.4.0.1862.1.1";<br>
     * - Qualified Certificates SCCD "0.4.0.1862.1.4";<br>
     *
     * @param certToken
     * @param xmlCert
     */
    private void dealQCStatement(final CertificateToken certToken, final XmlCertificate xmlCert) {

        if (!certToken.isTrusted()) {

            System.out.println("--> QCStatement for: " + certToken.getAbbreviation());
            final X509Certificate cert = certToken.getCertificate();
            final XmlQCStatement xmlQCS = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlQCStatement();
            xmlQCS.setQCP(qcp.check(cert));
            xmlQCS.setQCPPlus(qcpplus.check(cert));
            xmlQCS.setQCC(qccompliance.check(cert));
            xmlQCS.setQCSSCD(qcsscd.check(cert));
            xmlCert.setQCStatement(xmlQCS);
        }
    }

    /**
     * This method deals with the certificate validation extra information. The retrieved information is transformed to
     * the JAXB object.
     *
     * @param certToken
     * @param xmlCert
     */
    private void dealCertificateValidationInfo(final CertificateToken certToken, final XmlCertificate xmlCert) {

        final List<String> list = certToken.getValidationInfo();
        if (list.size() > 0) {

            final XmlInfoType xmlInfo = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlInfoType();
            for (String message : list) {

                final XmlMessage xmlMessage = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlMessage();
                xmlMessage.setId(0);
                xmlMessage.setValue(message);
                xmlInfo.getMessage().add(xmlMessage);
            }
            xmlCert.setInfo(xmlInfo);
        }
    }

    /**
     * This method deals with the certificate's details. The retrieved information is transformed to the JAXB object.
     *
     * @param certToken
     * @return
     */
    private XmlCertificate dealCertificateDetails(final Set<DigestAlgorithm> usedCertificatsDigestAlgorithms, final CertificateToken certToken) {

        final XmlCertificate xmlCert = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlCertificate();

        xmlCert.setId(certToken.getDSSId());
        final XmlSubjectDistinguishedName xmlSubject = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSubjectDistinguishedName();
        xmlSubject.setFormat(X500Principal.CANONICAL);
        xmlSubject.setValue(certToken.getSubjectX500Principal().getName(X500Principal.CANONICAL));
        xmlCert.setSubjectDistinguishedName(xmlSubject);

        final XmlIssuerDistinguishedName xmlIssuer = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlIssuerDistinguishedName();
        xmlIssuer.setFormat(X500Principal.CANONICAL);
        xmlIssuer.setValue(certToken.getIssuerX500Principal().getName(X500Principal.CANONICAL));
        xmlCert.setIssuerDistinguishedName(xmlIssuer);
        xmlCert.setSerialNumber(certToken.getSerialNumber());

        for (final DigestAlgorithm digestAlgorithm : usedCertificatsDigestAlgorithms) {

            final XmlDigestAlgAndValueType xmlDigestAlgAndValue = new XmlDigestAlgAndValueType();
            xmlDigestAlgAndValue.setDigestMethod(digestAlgorithm.getName());
            xmlDigestAlgAndValue.setDigestValue(certToken.getDigestValue(digestAlgorithm));
            xmlCert.getDigestAlgAndValue().add(xmlDigestAlgAndValue);
        }
        xmlCert.setIssuerCertificate(certToken.getIssuerTokenDSSId());
        xmlCert.setNotAfter(DSSUtils.createXMGregorianCalendar(certToken.getNotAfter()));
        xmlCert.setNotBefore(DSSUtils.createXMGregorianCalendar(certToken.getNotBefore()));
        final PublicKey publicKey = certToken.getPublicKey();
        xmlCert.setPublicKeySize(PublicKeyUtils.getPublicKeySize(publicKey));
        xmlCert.setPublicKeyEncryptionAlgo(PublicKeyUtils.getPublicKeyEncryptionAlgo(publicKey));
        xmlCert.setAlgoUsedToSignThisToken(certToken.getSignatureAlgo());
        final String signatureAlgoOID = certToken.getSignatureAlgoOID();
        xmlCert.setAlgoOIDUsedToSignThisToken(signatureAlgoOID);
        final SignatureAlgorithm signatureAlgo = SignatureAlgorithm.forOID(signatureAlgoOID);
        xmlCert.setDigestAlgoUsedToSignThisToken(signatureAlgo.getDigestAlgo().getName());
        xmlCert.setEncryptionAlgoUsedToSignThisToken(signatureAlgo.getEncryptionAlgo().getName());
        final String keyLength = getSigningKeyLength((Token) certToken);
        xmlCert.setKeyLengthUsedToSignThisToken(keyLength);
        xmlCert.setSelfSigned(certToken.isSelfSigned());
        xmlCert.setTrusted(certToken.isTrusted());
        xmlCert.setTokenSignatureIntact(certToken.isSignatureIntact());

        return xmlCert;
    }

    /**
     * This method return a key length used to sign the given certificate token.
     *
     * @param certToken
     * @return
     */
    private String getSigningKeyLength(CertificateToken certToken) {

        String keyLength = "";
        if (certToken != null) {

            final PublicKey issuerPublicKey = certToken.getPublicKey();
            keyLength = String.valueOf(PublicKeyUtils.getPublicKeySize(issuerPublicKey));
        }
        return keyLength;
    }

    /**
     * This method return a key length used to sign the given certificate token.
     *
     * @param certToken
     * @return
     */
    private String getSigningKeyLength(Token certToken) {

        final CertificateToken issuerCertificateToken = certToken.getIssuerToken();
        String keyLength = "";
        if (issuerCertificateToken != null) {

            final PublicKey issuerPublicKey = issuerCertificateToken.getPublicKey();
            keyLength = String.valueOf(PublicKeyUtils.getPublicKeySize(issuerPublicKey));
        } else if (certToken.isSelfSigned()) {

            final PublicKey issuerPublicKey = ((CertificateToken) certToken).getPublicKey();
            keyLength = String.valueOf(PublicKeyUtils.getPublicKeySize(issuerPublicKey));
        }
        return keyLength;
    }

    /**
     * This method deals with the certificate chain. The retrieved information is transformed to the JAXB object.
     *
     * @param xmlSignature
     * @param signToken
     */
    private void dealCertificateChain(final XmlSignature xmlSignature, final CertificateToken signToken) {

        if (signToken != null) {

            final XmlCertificateChainType xmlCertChainType = xmlForCertificateChain(signToken);
            xmlSignature.setCertificateChain(xmlCertChainType);
        }
    }

    /**
     * This method deals with the trusted service information in case of trusted certificate. The retrieved information
     * is transformed to the JAXB object.
     *
     * @param certToken
     * @param xmlCert
     */
    private void dealTrustedService(final CertificateToken certToken, final XmlCertificate xmlCert) {

        if (certToken.isTrusted()) {

            return;
        }
        final CertificateToken trustAnchor = certToken.getTrustAnchor();
        if (trustAnchor == null) {

            return;
        }

        final Date notBefore = certToken.getNotBefore();

        final XmlTrustedServiceProviderType xmlTSP = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlTrustedServiceProviderType();
        final List<ServiceInfo> services = trustAnchor.getAssociatedTSPS();
        if (services == null) {

            return;
        }
        boolean first = true;
        for (final ServiceInfo serviceInfo : services) {

            if (first) {

                xmlTSP.setTSPName(serviceInfo.getTspName());
                xmlTSP.setTSPServiceName(serviceInfo.getServiceName());
                xmlTSP.setTSPServiceType(serviceInfo.getType());
                xmlTSP.setWellSigned(serviceInfo.isTlWellSigned());
                first = false;
            }
            final Date statusStartDate = serviceInfo.getStatusStartDate();
            Date statusEndDate = serviceInfo.getStatusEndDate();
            if (statusEndDate == null) {

                // TODO: Should be changed in the case it would be possible to carry out the validation process at a specific moment in the time (validation date)
                statusEndDate = new Date();
            }
            // The issuing time of the certificate should be into the validity period of the associated service
            if (notBefore.after(statusStartDate) && notBefore.before(statusEndDate)) {

                xmlTSP.setStatus(serviceInfo.getStatus());
                xmlTSP.setStartDate(DSSUtils.createXMGregorianCalendar(statusStartDate));
                xmlTSP.setEndDate(DSSUtils.createXMGregorianCalendar(serviceInfo.getStatusEndDate()));
                xmlTSP.setExpiredCertsRevocationInfo(DSSUtils.createXMGregorianCalendar(serviceInfo.getExpiredCertsRevocationInfo()));

                // Check of the associated conditions to identify the qualifiers
                final List<String> qualifiers = serviceInfo.getQualifiers(certToken.getCertificate());
                if (!qualifiers.isEmpty()) {

                    final XmlQualifiers xmlQualifiers = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlQualifiers();
                    for (String qualifier : qualifiers) {

                        xmlQualifiers.getQualifier().add(qualifier);
                    }
                    xmlTSP.setQualifiers(xmlQualifiers);
                }
                break;
            }
        }
        xmlCert.setTrustedServiceProvider(xmlTSP);
    }

    /**
     * This method deals with the revocation data of a certificate. The retrieved information is transformed to the JAXB
     * object.
     *
     * @param certToken
     * @param xmlCert
     */
    private void dealRevocationData(final CertificateToken certToken, final XmlCertificate xmlCert) {

        final XmlRevocationType xmlRevocation = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlRevocationType();
        final RevocationToken revocationToken = certToken.getRevocationToken();
        if (revocationToken != null) {

            Boolean revocationTokenStatus = revocationToken.getStatus();
            // revocationTokenStatus can be null when OCSP return Unknown. In this case we set status to false.
            xmlRevocation.setStatus(revocationTokenStatus == null ? false : revocationTokenStatus);
            xmlRevocation.setDateTime(DSSUtils.createXMGregorianCalendar(revocationToken.getRevocationDate()));
            xmlRevocation.setReason(revocationToken.getReason());
            xmlRevocation.setIssuingTime(DSSUtils.createXMGregorianCalendar(revocationToken.getIssuingTime()));
            xmlRevocation.setNextUpdate(DSSUtils.createXMGregorianCalendar(revocationToken.getNextUpdate()));
            xmlRevocation.setSource(revocationToken.getClass().getSimpleName());
            xmlRevocation.setSourceAddress(revocationToken.getSourceURI());

            final XmlSigningCertificateType xmlRevocationSignCert = xmlForSigningCertificate(revocationToken);
            xmlRevocation.setSigningCertificate(xmlRevocationSignCert);
            final String oid = revocationToken.getSignatureAlgoOID();
            final SignatureAlgorithm revocationSignatureAlgo = SignatureAlgorithm.forOID(oid);
            xmlRevocation.setAlgoOIDUsedToSignThisToken(oid);
            xmlRevocation.setAlgoUsedToSignThisToken(revocationToken.getSignatureAlgo());
            xmlRevocation.setEncryptionAlgoUsedToSignThisToken(revocationSignatureAlgo.getEncryptionAlgo().getName());
            final String keyLength = getSigningKeyLength(revocationToken);
            xmlRevocation.setKeyLengthUsedToSignThisToken(keyLength);
            xmlRevocation.setDigestAlgoUsedToSignThisToken(revocationSignatureAlgo.getDigestAlgo().getName());
            xmlRevocation.setReferenceDataFound(revocationToken.isSignatureIntact());
            xmlRevocation.setReferenceDataIntact(revocationToken.isSignatureIntact());
            xmlRevocation.setSignatureIntact(revocationToken.isSignatureIntact());

            final List<String> list = revocationToken.getValidationInfo();
            if (list.size() > 0) {

                final XmlInfoType xmlInfo = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlInfoType();
                for (String message : list) {

                    final XmlMessage xmlMessage = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlMessage();
                    xmlMessage.setId(0);
                    xmlMessage.setValue(message);
                    xmlInfo.getMessage().add(xmlMessage);
                }
                xmlRevocation.setInfo(xmlInfo);
            }
            xmlCert.setRevocation(xmlRevocation);
        }
    }

    /**
     * This method deals with the signature policy. The retrieved information is transformed to the JAXB object.
     *
     * @param signature
     * @param xmlSignature
     */
    private void dealPolicy(final AdvancedSignature signature, final XmlSignature xmlSignature) {

        final PolicyValue policy = signature.getPolicyId();
        if (policy != null) {

            final XmlPolicy xmlPolicy = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlPolicy();
            xmlPolicy.setId(policy.getSignaturePolicyId());
            xmlPolicy.setIdentified(true);
            xmlPolicy.setStatus(true);
            xmlSignature.setPolicy(xmlPolicy);
        }
    }

    /**
     * This method deals with the basic signature data. The retrieved information is transformed to the JAXB object. The
     * signing certificate token is returned if found.
     *
     * @param signature
     * @param xmlSignature
     * @return
     */
    private CertificateToken dealSignature(final AdvancedSignature signature, final XmlSignature xmlSignature) {

        final SigningCertificate signingCertificate = dealSigningCertificate(signature, xmlSignature);
        dealSignatureCryptographicIntegrity(signature, xmlSignature);
        xmlSignature.setId(signature.getId());
        xmlSignature.setDateTime(DSSUtils.createXMGregorianCalendar(signature.getSigningTime()));
        final SignatureProductionPlace signatureProductionPlace = signature.getSignatureProductionPlace();
        if (signatureProductionPlace != null) {

            final XmlSignatureProductionPlace xmlSignatureProductionPlace = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSignatureProductionPlace();
            signatureProductionPlace.setCountryName(signatureProductionPlace.getCountryName());
            signatureProductionPlace.setStateOrProvince(signatureProductionPlace.getStateOrProvince());
            signatureProductionPlace.setPostalCode(signatureProductionPlace.getPostalCode());
            signatureProductionPlace.setCity(signatureProductionPlace.getCity());
            xmlSignature.setSignatureProductionPlace(xmlSignatureProductionPlace);
        }

        final String[] claimedRoles = signature.getClaimedSignerRoles();
        if (claimedRoles != null) {

            XmlClaimedRoles xmlClaimedRoles = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlClaimedRoles();
            for (String claimedRole : claimedRoles) {

                xmlClaimedRoles.getClaimedRole().add(claimedRole);
            }
            xmlSignature.setClaimedRoles(xmlClaimedRoles);
        }

        xmlSignature.setEncryptionAlgoUsedToSignThisToken(signature.getEncryptionAlgo().getName());
        final String keyLength = getSigningKeyLength(signingCertificate.getCertToken());
        xmlSignature.setKeyLengthUsedToSignThisToken(keyLength);
        xmlSignature.setDigestAlgoUsedToSignThisToken(signature.getDigestAlgo().getName());
        return signingCertificate.getCertToken();
    }

    /**
     * This method verifies the cryptographic integrity of the signature: the references are identified, their digest is
     * checked and then the signature itself. The result of these verifications is transformed to the JAXB
     * representation.
     *
     * @param signature
     * @param xmlSignature
     */
    private void dealSignatureCryptographicIntegrity(final AdvancedSignature signature, final XmlSignature xmlSignature) {

        final SignatureCryptographicVerification scv = signature.checkIntegrity(this.externalContent);
        xmlSignature.setReferenceDataFound(scv.isReferenceDataFound());
        xmlSignature.setReferenceDataIntact(scv.isReferenceDataIntact());
        xmlSignature.setSignatureIntact(scv.isSignatureIntact());
        if (!scv.getErrorMessage().isEmpty()) {

            xmlSignature.setErrorMessage(scv.getErrorMessage());
        }
    }

    /**
     * This method finds the signing certificate and creates its JAXB object representation. The signing certificate used
     * to produce the main signature (signature being analysed). If the signToken is null (the signing certificate was
     * not found) then Id is set to 0.
     *
     * @param signature
     * @param xmlSignature
     * @return
     */
    private SigningCertificate dealSigningCertificate(final AdvancedSignature signature, final XmlSignature xmlSignature) {

        final SigningCertificate signCert = signature.getSigningCertificate();
        final XmlSigningCertificateType xmlSignCertType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSigningCertificateType();
        if (signCert.getCertToken() != null) {

            xmlSignCertType.setId(signCert.getCertToken().getDSSId());
        }
        xmlSignCertType.setDigestValueMatch(signCert.isDigestMatch());
        xmlSignCertType.setIssuerSerialMatch(signCert.isSerialNumberMatch());
        xmlSignature.setSigningCertificate(xmlSignCertType);
        return signCert;
    }

/*
    TODO: (Bob) Old code to be adapted when we are ready to handle the countersignatures.

    protected SignatureVerification[] verifyCounterSignatures(final AdvancedSignature signature, final ValidationContext ctx) {

        final List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();

        if (counterSignatures == null) {
            return null;
        }

        final List<SignatureVerification> counterSigVerifs = new ArrayList<SignatureVerification>();
        for (final AdvancedSignature counterSig : counterSignatures) {

            final Result counterSigResult;
            try {

                final SignatureCryptographicVerification scv = counterSig.checkIntegrity(getExternalContent());
                counterSigResult = new Result(scv.signatureIntact());
            } catch (DSSException e) {
                throw new RuntimeException(e);
            }
            final String counterSigAlg = counterSig.getEncryptionAlgo().getName();
            counterSigVerifs.add(new SignatureVerification(counterSigResult, counterSigAlg, signature.getId()));
        }

        final SignatureVerification[] ret = new SignatureVerification[counterSigVerifs.size()];
        return counterSigVerifs.toArray(ret);
    }
*/

    /**
     * This method creates the XML object representing the signing certificate used to sign the revocation data (OCSP or
     * CRL). If the signToken is null (the signing certificate was not found) then Id is set to 0.
     *
     * @param revocationToken
     * @return
     */
    protected XmlSigningCertificateType xmlForSigningCertificate(final RevocationToken revocationToken) {

        final XmlSigningCertificateType xmlSignCertType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSigningCertificateType();
        final CertificateToken certToken = revocationToken.getIssuerToken();
        if (certToken != null) {

            xmlSignCertType.setId(certToken.getDSSId());
        }
        /**
         * FIXME: The fact that it is not possible to validate the CAdES signature following the ETSI TS 102 853 standard
         * requires us set the DigestValueMatch and IssuerSerialMatch to the same value as the result of the signature
         * validation.
         */
        xmlSignCertType.setDigestValueMatch(revocationToken.isSignatureIntact());
        xmlSignCertType.setIssuerSerialMatch(revocationToken.isSignatureIntact());
        return xmlSignCertType;
    }

    /**
     * This method creates the XML object representing the signing certificate used to sign the timestamp token. If the
     * signToken is null (the signing certificate was not found) then Id is set to 0.
     *
     * @param timestampToken
     * @return
     */
    protected XmlSigningCertificateType xmlForSigningCertificate(final TimestampToken timestampToken) {

        final XmlSigningCertificateType xmlSignCertType = DIAGNOSTIC_DATA_OBJECT_FACTORY.createXmlSigningCertificateType();
        final CertificateToken certToken = timestampToken.getIssuerToken();
        if (certToken != null) {

            xmlSignCertType.setId(certToken.getDSSId());
        }
        /**
         * FIXME: The fact that it is not possible to validate the CAdES signature following the ETSI TS 102 853 standard
         * requires us set the DigestValueMatch and IssuerSerialMatch to the same value as the result of the signature
         * validation.
         */
        xmlSignCertType.setDigestValueMatch(timestampToken.isSignatureIntact());
        xmlSignCertType.setIssuerSerialMatch(timestampToken.isSignatureIntact());
        return xmlSignCertType;
    }

    /**
     * @return The diagnostic data generated by the validateDocument method
     */
    public DiagnosticData getDiagnosticData() {

        return dData;
    }

    /**
     * Returns the simple report. The method {@link #validateDocument()} or {@link #validateDocument(String)} must be
     * called first.
     *
     * @return
     */
    public SimpleReport getSimpleReport() {
        return simpleReport;
    }

    /**
     * Returns the detailed report. The method {@link #validateDocument()} or {@link #validateDocument(String)} must be
     * called first.
     *
     * @return
     */
    public ValidationReport getDetailedReport() {
        return detailedReport;
    }

    /**
     * Output to System.out the diagnosticData, detailledReport and SimpleReport.
     */
    public void printReports() {
        System.out.println("----------------Diagnostic data-----------------");
        System.out.println(ValidationResourceManager.jaxbMarshalToOutputStream(getDiagnosticData()).toString());

        System.out.println("----------------Validation report---------------");
        System.out.println(getDetailedReport());

        System.out.println("----------------Simple report-------------------");
        System.out.println(getSimpleReport());

        System.out.println("------------------------------------------------");
    }

}
