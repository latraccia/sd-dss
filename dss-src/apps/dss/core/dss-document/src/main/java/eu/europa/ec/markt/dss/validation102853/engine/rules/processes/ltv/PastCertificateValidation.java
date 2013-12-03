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

package eu.europa.ec.markt.dss.validation102853.engine.rules.processes.ltv;

import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.ValidationResourceManager;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlDom;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlNode;
import eu.europa.ec.markt.dss.validation102853.engine.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.engine.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.engine.rules.ExceptionMessage;
import eu.europa.ec.markt.dss.validation102853.engine.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.engine.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.engine.rules.NodeValue;
import eu.europa.ec.markt.dss.validation102853.engine.rules.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.engine.rules.RuleUtils;
import eu.europa.ec.markt.dss.validation102853.engine.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.Conclusion.Info;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.dss.ForLegalPerson;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.dss.QualifiedCertificate;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.dss.SSCD;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.VConstraint;

/**
 * 9.2 Additional Building blocks<br>
 *
 * 9.2.1 Past certificate validation<br>
 *
 * 9.2.1.1 Description<br>
 *
 * This process validates a certificate at a date/time which may be in the past. This may become necessary in the LTV
 * settings when a compromising event (for instance, the end-entity certificate expires) prevents the traditional
 * certificate validation algorithm (see clause 5.3) to asserting the validation status of a certificate (for instance,
 * in case the end-entity certificate is expired at the current time, the traditional validation algorithm will return
 * INDETERMINATE/OUT_OF_BOUNDS_NO_POE due to the step 1).<br>
 *
 * The rationale of the algorithm described below are given in [i.4] and can be summarised in the following: if a
 * certificate chain has been usable to validate a certificate at some date/time in the past, the same chain can be used
 * at the current time to derive the same validity status, provided each certificate in the chain satisfies one of the
 * following:<br>
 *
 * a) <b>The revocation status of the certificate can be ascertained at the current time</b> (typically if the
 * certificate is not yet expired and appropriate revocation status information is obtained at the current time).<br>
 *
 * b) <b>The revocation status of the certificate can be ascertained using "old" revocation status information</b> such
 * that the certificate (resp. the revocation status information) is proven to having existed at a date in the past when
 * the issuer of the certificate (resp. the revocation status information) was still considered reliable and under
 * control of its signing key. This particular date/time will be named <b><i>control-time</i></b>.<br>
 *
 * NOTE: Control-time is an internal variable that is used within the algorithms and not part of the core results of the
 * validation process.<br>
 *
 * <b>Assuming that the trust anchor is still accepted as such at current time</b>, the validation process will slide
 * the control-time from the current-time to some date in the past each time it encounters a certificate proven to be
 * revoked. In addition to the certificate chain, the process outputs the last value of control-time – the control-time
 * associated with the target certificate (the certificate to validate). Any object signed with the target certificate
 * and proven to exist before this control-time can be accepted as VALID. This assertion is the basis of the LTV
 * validation processes presented in the next clauses. For more readability, the sliding algorithm is presented in its
 * own building block (control-time sliding process) described in the next clause.<br>
 *
 * It is important to note that when all the certificates in the chain can be validated at the current time, the
 * control-time never slides and the algorithm boils down to the traditional certificate validation algorithm described
 * in clause 5.3. The process below builds a prospective certificate chain in a very same way as in clause 5.3 except
 * that the X.509 validation algorithm is performed at a determined date in the past (instead of the current date/time)
 * and without any revocation checking. For each such chain, the sliding algorithm is executed to calculate the
 * control-time.<br>
 *
 * @author bielecro
 */
public class PastCertificateValidation implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage {

    private static final Logger LOG = Logger.getLogger(PastCertificateValidation.class.getName());

    /**
     * See {@link ProcessParameters#getConstraintData()}
     */
    private VConstraint constraintData;

    // returned data
    private XmlNode pastCertValidationData;

    /**
     * @param params
     */
    private void prepareParameters(final ProcessParameters params) {

        this.constraintData = params.getConstraintData();
        isInitialised();
    }

    /**
     *
     */
    private void isInitialised() {

        if (constraintData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "policyData"));
        }
    }

    /**
     * This method carries out the Past certificate validation.
     *
     * Input<br>
     * - Signature or time-stamp token . Mandatory<br>
     * - Target certificate ............ Mandatory<br>
     * - X.509 Validation Parameters ... Mandatory<br>
     * - A set of POEs ................. Mandatory<br>
     * - Certificate meta-data ......... Optional<br>
     * - Chain Constraints ............. Optional<br>
     * - Cryptographic Constraints ..... Optional<br>
     *
     * 9.2.1.3 Output<br>
     * - VALID<br>
     * - INDETERMINATE CHAIN_CONSTRAINTS_FAILURE, NO_CERTIFICATE_CHAIN_FOUND, NO_POE (returned by ControlTimeSliding)
     *
     * @param params    validation process parameters
     * @param signature signature to be validated
     * @return
     */
    public PastCertificateValidationConclusion run(final ProcessParameters params, final XmlDom signature) {

        prepareParameters(params);
        LOG.fine(this.getClass().getSimpleName() + ": start.");

        pastCertValidationData = new XmlNode(PAST_CERT_VALIDATION_DATA);
        pastCertValidationData.setNameSpace(ValidationResourceManager.DIAGNOSTIC_DATA_NAMESPACE);

        PastCertificateValidationConclusion conclusion = process(params, signature);

        conclusion.setValidationData(pastCertValidationData);

        if (ProcessParameters.isLoggingEnabled()) {

            System.out.println("");
            System.out.println(pastCertValidationData.toString());
        }
        return conclusion;
    }

    /**
     * @param params    validation process parameters
     * @param signature signature to be validated
     * @return
     */
    private PastCertificateValidationConclusion process(final ProcessParameters params, final XmlDom signature) {

        final PastCertificateValidationConclusion conclusion = new PastCertificateValidationConclusion();

        final XmlDom certificateChain = signature.getElement("./CertificateChain");

        /**
         * 9.2.1.4 Processing<br>
         *
         * The following steps shall be performed:<br>
         *
         * 1) Build a new prospective certificate chain that has not yet been evaluated. The chain shall satisfy the
         * conditions of a prospective certificate chain as stated in [4], clause 6.1, using one of the trust anchors
         * provided in the inputs:<br>
         *
         * a) If no new chain can be built, abort the processing with the current status and the last chain built or, if
         * no chain was built, with INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND.<br>
         */

        // The current status is not used in this implementation because the DSS framework build just one chain.

        final String signingCertificateId = certificateChain.getValue("./ChainCertificate[1]/@Id");

        pastCertValidationData.setAttribute(ID, signingCertificateId);

        XmlNode constraintNode = addConstraint(BBB_XCV_CCCBB_LABEL, BBB_XCV_CCCBB);

        final String trustedAnchorId = certificateChain.getValue("./ChainCertificate[last()]/@Id");
        final XmlDom trustedAnchor = params.getCertificate(trustedAnchorId);
        boolean isLastTrusted = false;
        if (trustedAnchor != null) {

            isLastTrusted = trustedAnchor.getBoolValue("./Trusted/text()");
        }
        if (!isLastTrusted) {

            constraintNode.addChild(STATUS, KO);
            conclusion.setIndication(INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND);
            final Info info = conclusion.addInfo(PCV_TINTA_LABEL);
            info.addTo(constraintNode);
            return conclusion;
        }

        /**
         * b) Otherwise, go to the next step.
         */

        /**
         * 2) Run the Certification Path Validation [4], clause 6.1, with the following inputs:<br>
         * - the prospective chain built in the previous step,<br>
         * - the trust anchor used in the previous step,<br>
         * - the X.509 parameters provided in the inputs and<br>
         * - a date from the intersection of the validity intervals of all the certificates in the prospective chain.<br>
         * <b>The validation shall not include revocation checking</b>:<br>
         */
        final List<XmlDom> certChain = certificateChain.getElements("./ChainCertificate");
        if (certChain.size() < 2) {

            constraintNode.addChild(STATUS, KO);
            conclusion.setIndication(INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND);
            final Info info = conclusion.addInfo(PCV_TIOOCIC_LABEL);
            info.addTo(constraintNode);
            return conclusion;
        }
        Date intersectionNotBefore = null;
        Date intersectionNotAfter = null;
        for (XmlDom certToken : certChain) {

            final String certificateId = certToken.getValue("./@Id");
            final XmlDom certificate = params.getCertificate(certificateId);

            final boolean isTrusted = certificate.getBoolValue("./Trusted/text()");

            final Date notBefore = certificate.getTimeValue("./NotBefore/text()");
            final Date notAfter = certificate.getTimeValue("./NotAfter/text()");
            if (intersectionNotAfter == null) {

                intersectionNotAfter = notAfter;
            } else if (intersectionNotAfter.after(notAfter)) {

                intersectionNotAfter = notAfter;
            }
            if (intersectionNotBefore == null) {

                intersectionNotBefore = notBefore;
            } else if (intersectionNotBefore.before(notBefore)) {

                intersectionNotBefore = notBefore;
            }
            if (intersectionNotAfter.before(intersectionNotBefore)) {

                constraintNode.addChild(STATUS, KO);
                conclusion.setIndication(INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND);
                final Info info = conclusion.addInfo(String.format(XCV_IFCCIIPC_LABEL, notAfter, notAfter, certificateId));
                info.setAttribute(FIELD, CERT_ID);
                info.setAttribute(CERT_ID, certificateId);
                info.addTo(constraintNode);
                return conclusion;
            }
            if (isTrusted) {

                // There is not need to check the revocation data for the trusted certificate
                continue;
            }

            /**
             * RFC 5280:<br>
             * Note that clients MUST reject the certificate if it contains an unsupported critical extension.<br>
             * ../..<br>
             * The primary goal of path validation is to verify the binding between a subject distinguished name or a
             * subject alternative name and subject public key, as represented in the target certificate, based on the
             * public key of the trust anchor. In most cases, the target certificate will be an end entity certificate, but
             * the target certificate may be a CA certificate as long as the subject public key is to be used for a purpose
             * other than verifying the signature on a public key certificate. Verifying the binding between the name and
             * subject public key requires obtaining a sequence of certificates that support that binding. ../..<br>
             * To meet this goal, the path validation process verifies, among other things, that a prospective
             * certification path (a sequence of n certificates) satisfies the following conditions:
             *
             * (a) for all x in {1, ..., n-1}, the subject of certificate x is the issuer of certificate x+1;
             *
             * (b) certificate 1 is issued by the trust anchor;
             *
             * (c) certificate n is the certificate to be validated (i.e., the target certificate); and
             *
             * (d) for all x in {1, ..., n}, the certificate was valid at the time in question.
             *
             * A certificate MUST NOT appear more than once in a prospective certification path.<br>
             * When the trust anchor is provided in the form of a self-signed certificate, this self-signed certificate is
             * not included as part of the prospective certification path. Information about trust anchors is provided as
             * inputs to the certification path validation algorithm (Section 6.1.1).<br>
             *
             * This section presents the algorithm in four basic steps:<br>
             * (1) Initialisation,<br>
             * (2) basic certificate processing,<br>
             * (3) preparation for the next certificate, and<br>
             * (4) wrap-up.<br>
             * Steps (1) and (4) are performed exactly once. Step (2) is performed for all certificates in the path. Step
             * (3) is performed for all certificates in the path except the final certificate.<br>
             *
             * 6.1.1. Inputs<br>
             * This algorithm assumes that the following nine inputs are provided to the path processing logic (limited to
             * DSS use):<br>
             * (a) a prospective certification path of length n.<br>
             * (b) the current date/time.<br>
             * (d) trust anchor information, describing a CA that serves as a trust anchor for the certification path.(The
             * trust anchor information may be provided to the path processing procedure in the form of a self-signed
             * certificate...)<br>
             *
             * 6.1.3. Basic Certificate Processing<br>
             * The basic path processing actions to be performed for certificate i (for all i in [1..n]) are listed below.<br>
             * - (a) Verify the basic certificate information. The certificate MUST satisfy each of the following:<br>
             * - - (1) The signature on the certificate can be verified using working_public_key_algorithm, the
             * working_public_key, and the working_public_key_parameters.<br>
             * - - (2) The certificate validity period includes the current time.<br>
             * - - (3) At the current time, the certificate is not revoked. This may be determined by obtaining the
             * appropriate CRL (Section 6.3), by status information, or by out-of-band mechanisms.<br>
             * - - (4) The certificate issuer name is the working_issuer_name.<br>
             *
             */
            final boolean isSignatureIntact = certificate.getBoolValue("./TokenSignatureIntact/text()");
            if (!isSignatureIntact) {

                constraintNode.addChild(STATUS, KO);
                conclusion.setIndication(INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND);
                final Info info = conclusion.addInfo(XCV_SOCIS_LABEL);
                info.setAttribute(FIELD, CERT_ID);
                info.setAttribute(CERT_ID, certificateId);
                info.addTo(constraintNode);
                return conclusion;
            }
            // The revocation status is checked in ControlTimeSliding process.
        }
        constraintNode.addChild(STATUS, OK);

        /**
         * a) If the certificate path validation returns a success indication, go to the next step.<br>
         */
        // --> Go to 3)

        /**
         * b) If the certificate path validation returns a failure indication, go to step 1.<br>
         */
        // --> DSS builds only one chain

        /**
         * 3) Perform the control-time sliding process with the following inputs:<br>
         * - the prospective chain,<br>
         * - the set of POEs and<br>
         * - the cryptographic constraints.<br>
         */

        final ControlTimeSliding controlTimeSliding = new ControlTimeSliding();
        ControlTimeSlidingConclusion ctsConclusion = controlTimeSliding.run(params, certificateChain);

        pastCertValidationData.addChild(ctsConclusion.getValidationData());

        /**
         * If it outputs a success indication, go to the next step.<br>
         * Otherwise, set the current status to the returned indication and sub-indication and go back to step 1.<br>
         */

        constraintNode = addConstraint(PCV_ICTSC_LABEL, PCV_ICTSC);

        // --> DSS builds only one chain
        // From 1):
        // a) If no new chain can be built, abort the processing with the current status and the last chain built.

        final String ctsConclusionIndication = ctsConclusion.getIndication();
        if (!VALID.equals(ctsConclusionIndication)) {

            constraintNode.addChild(STATUS, KO);

            conclusion.setIndication(ctsConclusionIndication, ctsConclusion.getSubIndication());
            conclusion.addInfo(CTS_RBCTSSP_LABEL);
            return conclusion;
        }
        constraintNode.addChild(STATUS, OK);
        final Date controlTime = ctsConclusion.getControlTime();
        final String formatedControlTime = RuleUtils.formatDate(controlTime);
        constraintNode.addChild(INFO, formatedControlTime).setAttribute(FIELD, CONTROL_TIME);
        /**
         * 4) Apply the Chain Constraints to the chain. Certificate meta-data has to be taken into account when checking
         * these constraints against the chain. If the chain does not match these constraints, set the current status to
         * INVALID/CHAIN_CONSTRAINTS_FAILURE and go to step 1.<br>
         */

        final String attribute = signature.getValue("./@Category");
        final boolean isTimestamp = !attribute.isEmpty();

        /**
         * A.2 Constraints on X.509 Certificate meta-data
         *
         * The following constraints are to be applied to the signer's certificate before considering it as valid for the
         * intended use.
         */

        final XmlDom signingCertificate = params.getCertificate(signingCertificateId);

        final QualifiedCertificate qc = new QualifiedCertificate(constraintData);
        Boolean isQC = qc.run(isTimestamp, signingCertificate);

        if (isQC != null) { // The constraint is defined to true: <QualifiedCertificate>true</QualifiedCertificate>

            /**
             * Mandates the signer's certificate used in validating the signature to be a qualified certificate as defined
             * in Directive 1999/93/EC [9]. This status can be derived from:
             */
            constraintNode = addConstraint(BBB_XCV_CMDCIQC_LABEL, BBB_XCV_CMDCIQC);

            if (!isQC) {

                constraintNode.addChild(STATUS, KO);
                conclusion.setIndication(INVALID, CHAIN_CONSTRAINTS_FAILURE);
                conclusion.addInfo(BBB_XCV_SCINQ_LABEL);
                return conclusion;
            }
            constraintNode.addChild(STATUS, OK);
        }

        final SSCD sscd = new SSCD(constraintData);
        final Boolean isSSCD = sscd.run(isTimestamp, signingCertificate);

        if (isSSCD != null) { // The constraint is defined to true: <SSCD>true</SSCD>

            /**
             * Mandates the end user certificate used in validating the signature to be supported by a secure signature
             * creation device (SSCD) as defined in Directive 1999/93/EC [9].
             */
            addConstraint(BBB_XCV_CMDCISSCD_LABEL, BBB_XCV_CMDCISSCD);

            if (!isSSCD) {

                constraintNode.addChild(STATUS, KO);
                conclusion.setIndication(INVALID, CHAIN_CONSTRAINTS_FAILURE);
                return conclusion;
            }
            constraintNode.addChild(STATUS, OK);
        }

        final ForLegalPerson forLegalPerson = new ForLegalPerson(constraintData);
        final Boolean isForLegalPerson = forLegalPerson.run(isTimestamp, trustedAnchor);

        if (isForLegalPerson != null) { // The constraint is defined to true: <ForLegalPerson>true</ForLegalPerson>

            /**
             * Mandates the signer's certificate used in validating the signature to be issued by a certificate authority
             * issuing certificate as having been issued to a legal person.
             */
            addConstraint(BBB_XCV_CMDCIITLP_LABEL, BBB_XCV_CMDCIITLP);

            if (!isForLegalPerson) {

                constraintNode.addChild(STATUS, KO);
                conclusion.setIndication(INVALID, CHAIN_CONSTRAINTS_FAILURE);
                return conclusion;
            }
            constraintNode.addChild(STATUS, OK);
        }

        /**
         * 5) Terminate with the current status and, if VALID, the certificate chain and the calculated control-time
         * returned in step 3.
         */

        conclusion.setIndication(VALID);
        conclusion.addInfo(formatedControlTime).setAttribute(FIELD, CONTROL_TIME);
        conclusion.setControlTime(controlTime);
        return conclusion;
    }

    /**
     * @return
     */
    private XmlNode addConstraint(final String label, final String nameId) {

        XmlNode constraintNode = pastCertValidationData.addChild(CONSTRAINT);
        constraintNode.addChild(NAME, label).setAttribute(NAME_ID, nameId);
        return constraintNode;
    }
}
