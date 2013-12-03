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
package eu.europa.ec.markt.dss.validation102853.report;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import org.bouncycastle.jce.X509Principal;
import org.w3c.dom.Document;

import com.lowagie.text.pdf.PdfPKCS7;
import eu.europa.ec.markt.dss.TSLConstant;
import eu.europa.ec.markt.dss.validation102853.CertificateQualification;
import eu.europa.ec.markt.dss.validation102853.ProcessExecutor;
import eu.europa.ec.markt.dss.validation102853.SignatureQualification;
import eu.europa.ec.markt.dss.validation102853.TLQualification;
import eu.europa.ec.markt.dss.validation102853.ValidationResourceManager;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlDom;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlNode;
import eu.europa.ec.markt.dss.validation102853.engine.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.engine.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.engine.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.engine.rules.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.engine.rules.RuleUtils;
import eu.europa.ec.markt.dss.validation102853.engine.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.dss.InvolvedServiceInfo;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.VConstraint;

/**
 * This class builds a SimpleReport XmlDom from the diagnostic data.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class SimpleReportBuilder {

    private final VConstraint constraintData;
    private final XmlDom diagnosticDataXmlDom;

    public SimpleReportBuilder(VConstraint constraintData, XmlDom diagnosticDataXmlDom) {
        this.constraintData = constraintData;
        this.diagnosticDataXmlDom = diagnosticDataXmlDom;
    }

    /**
     * This method generates the validation simpleReport.
     *
     * @param params
     * @return
     */
    public SimpleReport build(ProcessParameters params) {

        final XmlNode simpleReport = new XmlNode(NodeName.SIMPLE_REPORT);
        simpleReport.setNameSpace(ValidationResourceManager.DIAGNOSTIC_DATA_NAMESPACE);

        try {

            addPolicyNode(simpleReport);

            addValidationTime(params, simpleReport);

            addDocumentName(simpleReport);

            addSignatureFormat(simpleReport);

            addSignatures(params, simpleReport);
        } catch (Exception e) {

            if (!"WAS TREATED".equals(e.getMessage())) {

                notifyException(simpleReport, e);
            }
        }
        final Document reportDocument = ValidationResourceManager.xmlNodeIntoDom(simpleReport);
        return new SimpleReport(reportDocument);
    }

    private void addPolicyNode(XmlNode report) {
        final XmlNode policyNode = report.addChild(NodeName.POLICY);
        final String policyName = constraintData.getPolicyName();
        final String policyDescription = constraintData.getPolicyDescription();
        policyNode.addChild(NodeName.POLICY_NAME, policyName);
        policyNode.addChild(NodeName.POLICY_DESCRIPTION, policyDescription);
    }

    private void addValidationTime(ProcessParameters params, XmlNode report) {
        final Date validationTime = params.getCurrentTime();
        report.addChild(NodeName.VALIDATION_TIME, RuleUtils.formatDate(validationTime));
    }

    private void addDocumentName(XmlNode report) {
        final String documentName = diagnosticDataXmlDom.getValue("/DiagnosticData/DocumentName/text()");
        report.addChild(NodeName.DOCUMENT_NAME, documentName);
    }

    private void addSignatureFormat(XmlNode report) {
        final String signatureFormat = diagnosticDataXmlDom.getValue("/DiagnosticData/SignatureForm/text()");
        report.addChild(NodeName.SIGNATURE_FORMAT, signatureFormat);
    }

    private void addSignatures(ProcessParameters params, XmlNode simpleReport) throws Exception {
        final List<XmlDom> signatures = diagnosticDataXmlDom.getElements("/DiagnosticData/Signature");
        for (final XmlDom signature : signatures) {

            addSignature(params, simpleReport, signature);
        }
    }

    /**
     * @param params
     * @param simpleReport
     * @param diagnosticSignature the diagnosticSignature element in the diagnostic data
     * @throws Exception
     */
    private void addSignature(ProcessParameters params, XmlNode simpleReport, XmlDom diagnosticSignature) throws Exception {
        final XmlNode signatureNode = simpleReport.addChild(NodeName.SIGNATURE);

        final String signatureId = diagnosticSignature.getValue("./@Id");
        signatureNode.setAttribute(AttributeName.ID, signatureId);
        try {

            addSigningTime(diagnosticSignature, signatureNode);

            final String signCertId = diagnosticSignature.getValue("./SigningCertificate/@Id");
            final XmlDom signCert = params.getCertificate(signCertId);

            addSignedBy(signatureNode, signCert);

            XmlDom bvData = params.getBvData();
            final XmlDom bvConclusion = bvData.getElement("/BasicValidationData/Signature[@Id='%s']/Conclusion", signatureId);
            final XmlDom ltvDom = params.getLtvData();
            final XmlDom ltvConclusion = ltvDom.getElement("/LongTermValidationData/Signature[@Id='%s']/Conclusion", signatureId);
            final String ltvIndication = ltvConclusion.getValue("./Indication/text()");
            final String ltvSubIndication = ltvConclusion.getValue("./SubIndication/text()");
            final List<XmlDom> ltvInfoList = ltvConclusion.getElements("./Info");

            String indication = ltvIndication;
            String subIndication = ltvSubIndication;
            List<XmlDom> infoList = new ArrayList<XmlDom>();
            infoList.addAll(ltvInfoList);

            final String bvIndication = bvConclusion.getValue("./Indication/text()");
            final String bvSubIndication = bvConclusion.getValue("./SubIndication/text()");
            // boolean bvOk = Indication.VALID.equals(bvIndication)
            // || Indication.INDETERMINATE.equals(bvIndication)
            // && (SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(bvSubIndication) ||
            // SubIndication.OUT_OF_BOUNDS_NO_POE.equals(bvSubIndication) || SubIndication.REVOKED_NO_POE
            // .equals(bvSubIndication));

            final boolean noTimestamp = Indication.INDETERMINATE.equals(ltvIndication) && SubIndication.NO_TIMESTAMP.equals(ltvSubIndication);
            final boolean noValidTimestamp = Indication.INDETERMINATE.equals(ltvIndication) && SubIndication.NO_VALID_TIMESTAMP
                  .equals(ltvSubIndication);
            if (noTimestamp || noValidTimestamp) {

                final List<XmlDom> bvInfoList = bvConclusion.getElements("./Info");
                indication = bvIndication;
                subIndication = bvSubIndication;
                infoList = bvInfoList;
                if (noTimestamp) {

                    final XmlNode xmlNode = new XmlNode(NodeName.INFO, "### There is no timestamp within the signature.");
                    final Document xmlDocument = ValidationResourceManager.xmlNodeIntoDom(xmlNode);
                    final XmlDom xmlDom = new XmlDom(xmlDocument);
                    infoList.add(xmlDom);
                } else {

                    final XmlNode xmlNode = new XmlNode(NodeName.INFO, "### There is no valid timestamp within the signature.");
                    final Document xmlDocument = ValidationResourceManager.xmlNodeIntoDom(xmlNode);
                    final XmlDom xmlDom = new XmlDom(xmlDocument);
                    infoList.add(xmlDom);
                    infoList.addAll(ltvInfoList);
                }
            }
            signatureNode.addChild(NodeName.INDICATION, indication);
            if (!subIndication.isEmpty()) {

                signatureNode.addChild(NodeName.SUB_INDICATION, subIndication);
            }
            if (bvConclusion != null) {

                final List<XmlDom> errorMessages = diagnosticSignature.getElements("./ErrorMessage");
                for (XmlDom errorDom : errorMessages) {

                    String errorMessage = errorDom.getText();
                    final XmlNode xmlNode = new XmlNode(NodeName.INFO, errorMessage);
                    final Document xmlDocument = ValidationResourceManager.xmlNodeIntoDom(xmlNode);
                    final XmlDom xmlDom = new XmlDom(xmlDocument);
                    infoList.add(xmlDom);
                }
            }
            if (infoList != null) {

                for (final XmlDom xmlDom : infoList) {

                    signatureNode.addChild(xmlDom);
                }
            }
            addSignatureLevel(signatureNode, signCert);

        } catch (Exception e) {

            notifyException(signatureNode, e);
            throw new Exception("WAS TREATED", e);
        }
    }

    private void addSigningTime(XmlDom diagnosticSignature, XmlNode signatureNode) {
        signatureNode.addChild(NodeName.SIGNING_TIME, diagnosticSignature.getValue("./DateTime/text()"));
    }

    private void addSignedBy(XmlNode signatureNode, XmlDom signCert) {
        String signedBy = "?";
        if (signCert != null) {

            final String dn = signCert.getValue("./SubjectDistinguishedName/text()");
            final X509Principal principal = new X509Principal(dn);
            @SuppressWarnings("deprecation")
            final Vector<?> values = principal.getValues(PdfPKCS7.X509Name.CN);
            signedBy = (String) values.get(0);
            if (signedBy == null || signedBy.isEmpty()) {
                signedBy = dn;
            }
        }
        signatureNode.addChild(NodeName.SIGNED_BY, signedBy);
    }

    private void addSignatureLevel(XmlNode signatureNode, XmlDom signCert) {
        /**
         * Here we determine the type of the signature.
         */
        ProcessExecutor.SignatureType signatureType = ProcessExecutor.SignatureType.NA;
        if (signCert != null) {

            signatureType = getSignatureType(signCert);
        }
        signatureNode.addChild(NodeName.SIGNATURE_LEVEL, signatureType.name());
    }

    /**
     * This method returns the type of the qualification of the signature (signing certificate).
     *
     * @param signCert
     * @return
     */
    private ProcessExecutor.SignatureType getSignatureType(final XmlDom signCert) {

        final CertificateQualification certQualification = new CertificateQualification();
        certQualification.setQcp(signCert.getBoolValue("./QCStatement/QCP/text()"));
        certQualification.setQcpp(signCert.getBoolValue("./QCStatement/QCPPlus/text()"));
        certQualification.setQcc(signCert.getBoolValue("./QCStatement/QCC/text()"));
        certQualification.setQcsscd(signCert.getBoolValue("./QCStatement/QCSSCD/text()"));

        final TLQualification trustedListQualification = new TLQualification();

        final String caqc = InvolvedServiceInfo.getServiceTypeIdentifier(signCert);

        final List<String> qualifiers = InvolvedServiceInfo.getQualifiers(signCert);

        trustedListQualification.setCaqc(TSLConstant.CA_QC.equals(caqc));
        trustedListQualification.setQcCNoSSCD(InvolvedServiceInfo.isQC_NO_SSCD(qualifiers));
        trustedListQualification.setQcForLegalPerson(InvolvedServiceInfo.isQC_FOR_LEGAL_PERSON(qualifiers));
        trustedListQualification.setQcSSCDAsInCert(InvolvedServiceInfo.isQCSSCD_STATUS_AS_IN_CERT(qualifiers));
        trustedListQualification.setQcWithSSCD(qualifiers.contains(TSLConstant.QC_WITH_SSCD) || qualifiers.contains(TSLConstant.QC_WITH_SSCD_119612));

        final ProcessExecutor.SignatureType signatureType = SignatureQualification.getSignatureType(certQualification, trustedListQualification);
        return signatureType;
    }

    /**
     * @param signatureNode
     * @param exception
     */
    private static void notifyException(final XmlNode signatureNode, final Exception exception) {

        signatureNode.addChild(NodeName.INDICATION, Indication.INDETERMINATE);
        signatureNode.addChild(NodeName.SUB_INDICATION, "An unexpected error occurred during the signature validation process.");
        signatureNode.addChild(NodeName.INFO, exception.toString());
    }

}
