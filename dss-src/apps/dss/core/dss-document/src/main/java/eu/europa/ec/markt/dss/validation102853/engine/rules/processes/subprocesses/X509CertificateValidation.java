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

package eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses;

import java.util.Date;
import java.util.List;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlDom;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlNode;
import eu.europa.ec.markt.dss.validation102853.engine.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.engine.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.engine.rules.ExceptionMessage;
import eu.europa.ec.markt.dss.validation102853.engine.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.engine.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.engine.rules.NodeValue;
import eu.europa.ec.markt.dss.validation102853.engine.rules.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.engine.rules.RuleConstant;
import eu.europa.ec.markt.dss.validation102853.engine.rules.RuleUtils;
import eu.europa.ec.markt.dss.validation102853.engine.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.dss.ForLegalPerson;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.dss.QualifiedCertificate;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.dss.SSCD;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.VConstraint;

public class X509CertificateValidation implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage, RuleConstant {

    /**
     * The following variables are used only in order to simplify the writing of the rules!
     */

    /**
     * See {@link ProcessParameters#getDiagnosticData()}
     */
    private XmlDom diagnosticData;

    /**
     * See {@link ProcessParameters#getConstraintData()}
     */
    private VConstraint constraintData;

    /**
     * See {@link ProcessParameters#getCurrentTime()}
     */
    private Date currentTime;

    /**
     * See {@link ProcessParameters#getSignatureContext()}
     */
    private XmlDom signatureContext;

    /**
     * See {@link ProcessParameters#getContextElement()}
     */
    private XmlDom contextElement;

    // /**
    // * See {@link ProcessParameters#getContextName()}
    // */
    // private String contextName;

    /**
     * See {@link ProcessParameters#getSignCertId()}
     */
    private String signingCertId;

    /**
     * See {@link ProcessParameters#getSignCert()}
     */
    private XmlDom signingCert;

    /**
     * This node is used to add the constraint nodes.
     */
    private XmlNode subProcessNode;

    private void prepareParameters(final ProcessParameters params) {

        this.diagnosticData = params.getDiagnosticData();
        this.constraintData = params.getConstraintData();

        this.signatureContext = params.getSignatureContext();
        this.contextElement = params.getContextElement();
        this.currentTime = params.getCurrentTime();

        this.signingCertId = params.getSignCertId();
        this.signingCert = params.getSignCert();

        isInitialised(params);
    }

    private void isInitialised(final ProcessParameters params) {

        if (diagnosticData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
        }
        if (constraintData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "policyData"));
        }
        if (currentTime == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "currentTime"));
        }
        if (signatureContext == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "signatureContext"));
        }
        if (contextElement == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "contextElement"));
        }
        if (signingCertId == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "signCertId"));
        }
        if (signingCert == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "signCert"));
        }
    }

    /**
     * 5.3 X.509 Certificate Validation (XCV)<br>
     * This method carry out the XCV process.
     *
     * @param params      validation process parameters
     * @param processNode the <code>XmlNode</code> to be used to contain the validation information
     * @return
     */
    public boolean run(final ProcessParameters params, final XmlNode processNode) {

        if (processNode == null) {

            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "processNode"));
        }
        prepareParameters(params);

        subProcessNode = processNode.addChild(XCV);
        final XmlNode conclusionNode = new XmlNode(CONCLUSION);

        final boolean valid = process(params, conclusionNode);

        if (valid) {

            /**
             * 6) Return the chain with the indication VALID.
             */
            conclusionNode.addChild(INDICATION, VALID);
            conclusionNode.setParent(subProcessNode);
        } else {

            subProcessNode.addChild(conclusionNode);
            processNode.addChild(conclusionNode);
        }
        return valid;
    }

    /**
     * @param params         validation process parameters
     * @param conclusionNode the <code>XmlNode</code> to be used to contain the validation information
     * @return
     */
    private boolean process(final ProcessParameters params, final XmlNode conclusionNode) {

        /**
         * 5.3.4 Processing This process consists in the following steps:
         *
         * 1) Check that the current time is in the validity range of the signer's certificate. If this constraint is not
         * satisfied, abort the processing with the indication INDETERMINATE and the sub indication OUT_OF_BOUNDS_NO_POE.
         */
        XmlNode constraintNode = addConstraint(BBB_XCV_ICTIVRSC_LABEL, BBB_XCV_ICTIVRSC);

        final String formatedNotAfter = signingCert.getValue("./NotAfter/text()");
        final Date notAfter = RuleUtils.parseDate(formatedNotAfter);

        final String formatedNotBefore = signingCert.getValue("./NotBefore/text()");
        final Date notBefore = RuleUtils.parseDate(formatedNotBefore);

        final boolean certValidity = currentTime.compareTo(notBefore) >= 0 && currentTime.compareTo(notAfter) <= 0;
        final String expiredCertsRevocationInfo = signingCert.getValue("./TrustedServiceProvider/ExpiredCertsRevocationInfo/text()");
        Date expiredCertsRevocationInfoDate = null;
        if(!expiredCertsRevocationInfo.isEmpty()) {

            expiredCertsRevocationInfoDate = RuleUtils.parseDate(expiredCertsRevocationInfo);
        }
        if (expiredCertsRevocationInfoDate == null && !certValidity) {

            constraintNode.addChild(STATUS, KO);
            conclusionNode.addChild(INDICATION, INDETERMINATE);
            conclusionNode.addChild(SUB_INDICATION, OUT_OF_BOUNDS_NO_POE);
            conclusionNode.addChild(INFO, BBB_XCV_CTINIVRSC_LABEL);
            conclusionNode.addChild(INFO, formatedNotBefore).setAttribute(FIELD, NOT_BEFORE);
            conclusionNode.addChild(INFO, formatedNotAfter).setAttribute(FIELD, NOT_AFTER);
            return false;
        }
        constraintNode.addChild(STATUS, OK);
        if (expiredCertsRevocationInfoDate != null ) {

            constraintNode.addChild(INFO, expiredCertsRevocationInfo).setAttribute(FIELD, EXPIRED_CERTS_REVOCATION_INFO);
        }
        /**
         * 2) Build a new prospective certificate chain that has not yet been evaluated. The chain shall satisfy the
         * conditions of a prospective certificate chain as stated in [4], clause 6.1, using one of the trust anchors
         * provided in the inputs:
         *
         * a) If no new chain can be built, abort the processing with the current status and the last chain built or, if
         * no chain was built, with INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND.
         */

        constraintNode = addConstraint(BBB_XCV_CCCBB_LABEL, BBB_XCV_CCCBB);

        final String lastChainCertId = contextElement.getValue("./CertificateChain/ChainCertificate[last()]/@Id");
        final XmlDom lastChainCert = params.getCertificate(lastChainCertId);
        boolean isLastTrusted = false;
        if (lastChainCert != null) {

            isLastTrusted = lastChainCert.getBoolValue("./Trusted/text()");
        }
        if (!isLastTrusted) {

            constraintNode.addChild(STATUS, KO);
            conclusionNode.addChild(INDICATION, INDETERMINATE);
            conclusionNode.addChild(SUB_INDICATION, NO_CERTIFICATE_CHAIN_FOUND);
            conclusionNode.addChild(INFO, BBB_XCV_CCINT_LABEL);
            return false;
        }
        constraintNode.addChild(STATUS, OK);

        /**
         * b) Otherwise, add this chain to the set of prospected chains and go to step 3.
         *
         * 3) Run the Certification Path Validation [4], clause 6.1, with the following inputs:<br>
         * - the prospective chain built in the previous step,<br>
         * - the trust anchor used in the previous step,<br>
         * - the X.509 parameters provided in the inputs and<br>
         * - the current date/time.<br>
         * The validation shall include revocation checking for each certificate in the chain:
         */

        // boolean signingCertRevocationStatus = true;
        // boolean intermediateCARevocationStatus = true;

        final List<XmlDom> certChain = contextElement.getElements("./CertificateChain/ChainCertificate");
        for (final XmlDom certToken : certChain) {

            final String certId = certToken.getValue("./@Id");
            final XmlDom cert = params.getCertificate(certId);

            final boolean isTrusted = cert.getBoolValue("./Trusted/text()");
            if (isTrusted) {

                continue;
            }

            constraintNode = addConstraint(String.format(BBB_XCV_IRDPFC_LABEL, certId), BBB_XCV_IRDPFC);

            final XmlDom revocation = cert.getElement("./Revocation");
            if (revocation == null) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INDETERMINATE);
                conclusionNode.addChild(SUB_INDICATION, TRY_LATER);
                conclusionNode.addChild(INFO, String.format(BBB_XCV_NRDFC_LABEL, certId));
                return false;
            }
            constraintNode.addChild(STATUS, OK);
            // Preparation of information about revocation data and their freshness.
            boolean revocationFreshnessToBeChecked = constraintData.isRevocationFreshnessToBeChecked();
            boolean revocationFresh = !revocationFreshnessToBeChecked;

            final String revocationIssuingTimeString = revocation.getValue("./IssuingTime/text()");
            if (revocationFreshnessToBeChecked && !revocationIssuingTimeString.isEmpty()) {

                final Date revocationIssuingTime = RuleUtils.parseDate(revocationIssuingTimeString);
                final long revocationDeltaTime = currentTime.getTime() - revocationIssuingTime.getTime();

                if (revocationDeltaTime <= constraintData.getMaxRevocationFreshness()) {

                    revocationFresh = true;
                }
            }

            /**
             * a) If the certificate path validation returns a success indication and the revocation information used is
             * considered fresh, go to the next step.
             */

         /*
          * --> This is done when other conditions are not met
          */

            /**
             * b) If the certificate path validation returns a success indication and the revocation information used is
             * not considered fresh, abort the process with the indication INDETERMINATE, the sub indication TRY_LATER and
             * the content of the NEXT_UPDATE-field of the CRL used as the suggestion for when to try the validation again.
             */

            final boolean revocationStatus = revocation.getBoolValue("./Status/text()");
            final String revocationNextUpdate = revocation.getValue("./NextUpdate/text()");

            // If the revocation status equals false --> The process will finished so don't need to check the freshness.
            if (revocationStatus) {

                constraintNode = addConstraint(String.format(BBB_XCV_IRIF_LABEL, certId), BBB_XCV_IRIF);

                if (!revocationFresh) {

                    constraintNode.addChild(STATUS, KO);
                    conclusionNode.addChild(INDICATION, INDETERMINATE);
                    conclusionNode.addChild(SUB_INDICATION, TRY_LATER);
                    conclusionNode.addChild(INFO, String.format(BBB_XCV_TVA_LABEL, revocationNextUpdate));
                    conclusionNode.addChild(INFO, String.format(BBB_XCV_RIT_LABEL, revocationIssuingTimeString));
                    conclusionNode.addChild(INFO, String.format(BBB_XCV_MAORD_LABEL, constraintData.getFormatedMaxRevocationFreshness()));
                    return false;
                }
                constraintNode.addChild(STATUS, OK);
            }

            // The case of the signing certificate:
            if (signingCertId.equals(certId)) {

                constraintNode = addConstraint(BBB_XCV_ISCR_LABEL, BBB_XCV_ISCR);

                final String revocationReason = revocation.getValue("./Reason/text()");
                final String revocationDatetime = revocation.getValue("./DateTime/text()");

                /**
                 * c) If the certificate path validation returns a failure indication because the signer's certificate has
                 * been determined to be revoked, abort the process with the indication INDETERMINATE, the sub indication
                 * REVOKED_NO_POE, the validated chain, the revocation date and the reason for revocation.
                 */

                if (!revocationStatus && !revocationReason.equals(CRL_REASON_CERTIFICATE_HOLD)) {

                    // signingCertRevocationStatus = certRevocationStatus;

                    constraintNode.addChild(STATUS, KO);
                    conclusionNode.addChild(INDICATION, INDETERMINATE);
                    conclusionNode.addChild(SUB_INDICATION, REVOKED_NO_POE);
                    if (!revocationDatetime.isEmpty()) {

                        conclusionNode.addChild(INFO, revocationDatetime).setAttribute(FIELD, REVOCATION_TIME);
                    }
                    if (!revocationReason.isEmpty()) {

                        conclusionNode.addChild(INFO, revocationReason).setAttribute(FIELD, REVOCATION_REASON);
                    }
                    return false;
                }
                constraintNode.addChild(STATUS, OK);

                /**
                 * d) If the certificate path validation returns a failure indication because the signer's certificate has
                 * been determined to be on hold, abort the process with the indication INDETERMINATE, the sub indication
                 * TRY_LATER, the suspension time and, if available, the content of the NEXT_UPDATE-field of the CRL used as
                 * the suggestion for when to try the validation again.
                 */
                constraintNode = addConstraint(BBB_XCV_ISCOH_LABEL, BBB_XCV_ISCOH);

                if (!revocationStatus && revocationReason.equals(CRL_REASON_CERTIFICATE_HOLD)) {

                    constraintNode.addChild(STATUS, KO);
                    conclusionNode.addChild(INDICATION, INDETERMINATE);
                    conclusionNode.addChild(SUB_INDICATION, TRY_LATER);
                    conclusionNode.addChild(INFO, String.format(BBB_XCV_ST_LABEL, revocationDatetime));
                    conclusionNode.addChild(INFO, String.format(BBB_XCV_TVA_LABEL, revocationNextUpdate));
                    return false;
                }
                constraintNode.addChild(STATUS, OK);

                // The status of the trusted service is checked:

                constraintNode = addConstraint(CTS_WITSS_LABEL, CTS_ITSUS);

                final XmlDom trustedServiceProvider = cert.getElement("./TrustedServiceProvider");

                final String status = trustedServiceProvider.getValue("./Status/text()");
                constraintNode.addChild(STATUS, OK);
                constraintNode.addChild(INFO, status).setAttribute(FIELD, TRUSTED_SERVICE_STATUS);
                if (!SERVICE_STATUS_UNDERSUPERVISION.equals(status) && !SERVICE_STATUS_SUPERVISIONINCESSATION
                      .equals(status) && !SERVICE_STATUS_ACCREDITED.equals(status)) {

                    /**
                     * ...where the trust anchor is broken at a known date by initialising control-time to this date/time.<br>
                     */
                    if (status.isEmpty()) {

                        // Trusted service is unknown
                        // TODO: cannot continue
                    } else {

                        final Date statusDate = trustedServiceProvider.getTimeValue("./StartDate/text()");
                    }
                }

                // There is not need to check the revocation data for trusted and self-signed certificates
            } else {

                // For all certificates different from the signing certificate and trust anchor.

                /**
                 * e) If the certificate path validation returns a failure indication because an intermediate CA has been
                 * determined to be revoked, set the current status to INDETERMINATE/REVOKED_CA_NO_POE and go to step 2.
                 */

                constraintNode = addConstraint(String.format(BBB_XCV_IICR_LABEL, certId), BBB_XCV_IICR);

                if (!revocationStatus) {

                    // intermediateCARevocationStatus = certRevocationStatus;

                    constraintNode.addChild(STATUS, KO);
                    conclusionNode.addChild(INDICATION, INDETERMINATE);
                    conclusionNode.addChild(SUB_INDICATION, REVOKED_CA_NO_POE);
                    return false;
                }
                constraintNode.addChild(STATUS, OK);
            }

            // We check cryptographic constraints on the revocation data
            constraintNode = addConstraint(BBB_XCV_ARDCCM_LABEL, BBB_XCV_ARDCCM);

            final RevocationCryptographicConstraint cryptoConstraints = new RevocationCryptographicConstraint();
            final XmlDom contextElementBackup = params.getContextElement();
            params.setContextElement(revocation);
            final XmlNode infoNode = new XmlNode("");
            boolean cryptographicStatus = cryptoConstraints.run(params, infoNode);
            params.setContextElement(contextElementBackup);
            if (!cryptographicStatus) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, CRYPTO_CONSTRAINTS_FAILURE);
                conclusionNode.addChildrenOf(infoNode);
                return false;
            }
            constraintNode.addChild(STATUS, OK);

            /**
             * f) If the certificate path validation returns a failure indication with any other reason, go to step 2.
             */
            final boolean isSignatureIntact = cert.getBoolValue("./TokenSignatureIntact/text()");
            if (!isSignatureIntact) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INDETERMINATE);
                conclusionNode.addChild(SUB_INDICATION, NO_CERTIFICATE_CHAIN_FOUND);
                final XmlNode info = conclusionNode.addChild(INFO, XCV_SOCIS_LABEL);
                info.setAttribute(FIELD, CERT_ID);
                info.setAttribute(CERT_ID, certId);

                return false;
            }

            // --> DSS builds only one chain

        } // loop end

        /**
         * 4) Apply the Chain Constraints to the chain. Certificate meta-data shall be taken into account when checking
         * these constraints against the chain. If the chain does not match these constraints, set the current status to
         * INVALID/CHAIN_CONSTRAINTS_FAILURE and go to step 2.
         */

        constraintNode = addConstraint(BBB_XCV_ACCM_LABEL, BBB_XCV_ACCM);

        // --> DSS does not check these constraints
        final boolean chainConstraintStatus = true;

        if (!chainConstraintStatus) {

            constraintNode.addChild(STATUS, KO);
            conclusionNode.addChild(INDICATION, INVALID);
            conclusionNode.addChild(SUB_INDICATION, CHAIN_CONSTRAINTS_FAILURE);
            return false;
        }
        constraintNode.addChild(STATUS, OK);

        /**
         * A.2 Constraints on X.509 Certificate meta-data
         *
         * The following constraints are to be applied to the signer's certificate before considering it as valid for the
         * intended use.
         */

        final String nodeName = contextElement.getName();
        final boolean isTimestamp = TIMESTAMP.equals(nodeName);

        final QualifiedCertificate qc = new QualifiedCertificate(constraintData);
        final Boolean isQC = qc.run(isTimestamp, signingCert);
        if (isQC != null) { // The constraint is defined to true: <QualifiedCertificate>true</QualifiedCertificate>

            /**
             * Mandates the signer's certificate used in validating the signature to be a qualified certificate as defined
             * in Directive 1999/93/EC [9]. This status can be derived from:
             */

            constraintNode = addConstraint(BBB_XCV_CMDCIQC_LABEL, BBB_XCV_CMDCIQC);

            if (!isQC) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, CHAIN_CONSTRAINTS_FAILURE);
                conclusionNode.addChild(INFO, BBB_XCV_SCINQ_LABEL);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
        }

        final SSCD sscd = new SSCD(constraintData);
        final Boolean isSSCD = sscd.run(isTimestamp, signingCert);

        if (isSSCD != null) { // The constraint is defined to true: <SSCD>true</SSCD>

            /**
             * Mandates the end user certificate used in validating the signature to be supported by a secure signature
             * creation device (SSCD) as defined in Directive 1999/93/EC [9].
             */

            constraintNode = addConstraint(BBB_XCV_CMDCISSCD_LABEL, BBB_XCV_CMDCISSCD);

            if (!isSSCD) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, CHAIN_CONSTRAINTS_FAILURE);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
        }

        final ForLegalPerson forLegalPerson = new ForLegalPerson(constraintData);
        final Boolean isForLegalPerson = forLegalPerson.run(isTimestamp, signingCert);

        if (isForLegalPerson != null) { // The constraint is defined to true: <ForLegalPerson>true</ForLegalPerson>

            /**
             * Mandates the signer's certificate used in validating the signature to be issued by a certificate authority
             * issuing certificate as having been issued to a legal person.
             */

            constraintNode = addConstraint(BBB_XCV_CMDCIITLP_LABEL, BBB_XCV_CMDCIITLP);

            if (!isForLegalPerson) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, CHAIN_CONSTRAINTS_FAILURE);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
        }

        /**
         * 5) Apply the cryptographic constraints to the chain. If the chain does not match these constraints, set the
         * current status to INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE and go to step 2.
         */
        constraintNode = addConstraint(BBB_XCV_ACCCM_LABEL, BBB_XCV_ACCCM);

        boolean cryptographicStatus = false;
        final XmlNode infoContainerNode = new XmlNode("Container");

        for (final XmlDom certToken : certChain) {

            final String certificateId = certToken.getValue("./@Id");
            if (certificateId.equals(lastChainCertId) && isLastTrusted) {

                /**
                 * The trusted anchor is not checked. In the case of a certificate chain consisting of a single certificate
                 * which is trusted we need to set this variable to true.
                 */
                cryptographicStatus = true;
                continue;
            }

            final XmlDom certificate = params.getCertificate(certificateId);

            final XCVCryptographicConstraint cryptoConstraints = new XCVCryptographicConstraint();
            final ProcessParameters cryptoParams = new XCVCryptoConstraintParameters(params);
            cryptoParams.setContextElement(certificate);
            if (!certificateId.equals(signingCertId)) {

                cryptoParams.setContextName(CA_CERTIFICATE);
            }

            cryptographicStatus = cryptoConstraints.run(cryptoParams, infoContainerNode);
            if (!cryptographicStatus) {

                break;
            }

        }

        if (!cryptographicStatus) {

            constraintNode.addChild(STATUS, KO);

            conclusionNode.addChild(INDICATION, INDETERMINATE);
            conclusionNode.addChild(SUB_INDICATION, CRYPTO_CONSTRAINTS_FAILURE_NO_POE);
            conclusionNode.addChildrenOf(infoContainerNode);
            return false;
        }
        constraintNode.addChild(STATUS, OK);

        return true;
    }

    /**
     * @param label
     * @param nameId
     * @return
     */
    private XmlNode addConstraint(final String label, final String nameId) {

        final XmlNode constraintNode = subProcessNode.addChild(CONSTRAINT);
        constraintNode.addChild(NAME, label).setAttribute(NAME_ID, nameId);
        return constraintNode;
    }
}
