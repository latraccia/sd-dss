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

package eu.europa.ec.markt.dss.validation102853.engine.rules.processes;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import org.w3c.dom.Document;

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
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.ltv.POEExtraction;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.ltv.PastSignatureValidation;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.ltv.PastSignatureValidationConclusion;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.VConstraint;

/**
 * 9.3 Long Term Validation Process<br>
 *
 * 9.3.1 Description<br>
 *
 * An AdES-A (Archival Electronic Signature) is built on an XL signature (EXtended Long Electronic Signature). Several
 * unsigned attributes may be present in such signatures:<br>
 *
 * • Time-stamp(s) on the signature value (AdES-T).<br>
 * • Attributes with references of validation data (AdES-C).<br>
 * • Time-stamp(s) on the references of validation data (AdES-XT2).<br>
 * • Time-stamp(s) on the references of validation data, the signature value and the signature time stamp (AdES-XT1).<br>
 * • Attributes with the values of validation data (AdES-XL).<br>
 * • Archive time-stamp(s) on the whole signature except the last archive time-stamp (AdES-A).<br>
 *
 * The process described in this clause is able to validate any of the forms above but also any basic form (namely BES
 * and EPES).<br>
 *
 * The process handles the AdES signature as a succession of layers of signatures. Starting from the most external layer
 * (e.g. the last archive-time-stamp) to the most inner layer (the signature value to validate), the process performs
 * the basic signature validation algorithm (see clause 8 for the signature itself and clause 7 for the time-stamps). If
 * the basic validation outputs INDETERMINATE/REVOKED_NO_POE, INDETERMINATE/OUT_OF_BOUNDS_NO_POE or
 * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, we perform the past certificate validation which will output a
 * control-time in the past. The layer is accepted as VALID, provided we have a proof of existence before this
 * control-time.<br>
 *
 * The process does not necessarily fail when an intermediate time-stamp gives the status INVALID or INDETERMINATE
 * unless some validation constraints force the process to do so. If the validity of the signature can be ascertained
 * despite some time-stamps which were ignored due to INVALID (or INDETERLINATE) status, the SVA shall report this
 * information to the DA. What the DA does with this information is out of the scope of the present document.
 *
 * @author bielecro
 */
public class LongTermValidation implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage {

    private static final Logger LOG = Logger.getLogger(LongTermValidation.class.getName());

    ProcessParameters params;

    // Primary inputs
    /**
     * See {@link ProcessParameters#getDiagnosticData()}
     *
     * @return
     */
    private XmlDom diagnosticData;

    /**
     * See {@link ProcessParameters#getConstraintData()}
     *
     * @return
     */
    private VConstraint constraintData;

    private XmlDom timestampValidationData; // Basic Building Blocks for timestamps

    private XmlDom adestValidationData;

    // returned data
    private XmlNode signatureNode;
    private XmlNode conclusionNode;

    // This object represents the set of POEs.
    private POEExtraction poe;

    private void prepareParameters(final XmlNode mainNode) {

        this.diagnosticData = params.getDiagnosticData();
        this.constraintData = params.getConstraintData();
        isInitialised(mainNode);
    }

    private void isInitialised(final XmlNode mainNode) {

        if (diagnosticData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
        }
        if (constraintData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "constraintData"));
        }
        if (adestValidationData == null) {

            /**
             * The execution of the Basic Validation process which creates the basic validation data.<br>
             */
            final AdESTValidation adestValidation = new AdESTValidation();
            adestValidationData = adestValidation.run(mainNode, params);

            // Basic Building Blocks for timestamps
            timestampValidationData = params.getTsData();
        }
        if (poe == null) {

            poe = new POEExtraction();
            params.setPOE(poe);
        }
    }

    /**
     * This method lunches the long term validation process.
     *
     * 9.3.2 Input<br>
     * Signature ..................... Mandatory<br>
     * Signed data object (s) ........ Optional<br>
     * Trusted-status Service Lists .. Optional<br>
     * Signature Validation Policies . Optional<br>
     * Local configuration ........... Optional<br>
     * A set of POEs ................. Optional<br>
     * Signer's Certificate .......... Optional<br>
     *
     * 9.3.3 Output<br>
     * The main output of this signature validation process is a status indicating the validity of the signature. This
     * status may be accompanied by additional information (see clause 4).<br>
     *
     * 9.3.4 Processing<br>
     * The following steps shall be performed:
     *
     * @param params
     * @return
     */
    public XmlDom run(final XmlNode mainNode, final ProcessParameters params) {

        this.params = params;
        prepareParameters(mainNode);
        LOG.fine(this.getClass().getSimpleName() + ": start.");

        XmlNode longTermValidationData = mainNode.addChild(LONG_TERM_VALIDATION_DATA);

        final List<XmlDom> signatures = diagnosticData.getElements("/DiagnosticData/Signature");

        for (final XmlDom signature : signatures) {

            final String signatureId = signature.getValue("./@Id");
            final XmlDom signatureTimestampValidationData = timestampValidationData.getElement("./Signature[@Id='%s']", signatureId);
            final XmlDom adestSignatureValidationData = adestValidationData.getElement("/AdESTValidationData/Signature[@Id='%s']", signatureId);

            signatureNode = longTermValidationData.addChild(SIGNATURE);
            signatureNode.setAttribute(ID, signatureId);

            conclusionNode = new XmlNode(CONCLUSION);

            try {

                final boolean valid = process(params, signature, signatureTimestampValidationData, adestSignatureValidationData);
                if (valid) {

                    conclusionNode.addFirstChild(INDICATION, VALID);
                }
            } catch (Exception e) {

                LOG.warning("Unexpected exception: " + e.toString());
                e.printStackTrace();
            }
            conclusionNode.setParent(signatureNode);
        }
        if (ProcessParameters.isLoggingEnabled()) {

            System.out.println("");
            System.out.println(longTermValidationData.toString());
        }
        final Document ltvDocument = ValidationResourceManager.xmlNodeIntoDom(longTermValidationData);
        final XmlDom ltvDom = new XmlDom(ltvDocument);
        params.setLtvData(ltvDom);
        return ltvDom;
    }

    /**
     * 9.3.4 Processing<br>
     *
     * The following steps shall be performed:<br>
     *
     * @param params
     * @param signature
     * @param signatureTimestampValidationData
     *
     * @param adestSignatureValidationData
     * @return
     */
    private boolean process(ProcessParameters params, XmlDom signature, XmlDom signatureTimestampValidationData, XmlDom adestSignatureValidationData) {

        /**
         * 1) POE initialisation: Add a POE for each object in the signature at the current time to the set of POEs.<br>
         *
         * NOTE 1: The set of POE in the input may have been initialised from external sources (e.g. provided from an
         * external archiving system). These POEs will be used without additional processing.<br>
         */
        // This means that the framework needs to extend the signature (add a LTV timestamp).
        // --> This is not done in the 102853 implementation. The DSS user can extend the signature by adding his own
        // code.

        final List<XmlDom> certificates = params.getCertPool().getElements("./Certificate");
        poe.initialisePOE(signature, certificates, params.getCurrentTime());

        /**
         * 2) Basic signature validation: Perform the validation process for AdES-T signatures (see clause 8) with all the
         * inputs, including the processing of any signed attributes/properties as specified.<br>
         */

        // --> This is done in the prepareParameters(ProcessParameters params) method.

        final XmlDom adestSignatureConclusion = adestSignatureValidationData.getElement("./Conclusion");
        final String adestSignatureIndication = adestSignatureConclusion.getValue("./Indication/text()");
        final String adestSignatureSubIndication = adestSignatureConclusion.getValue("./SubIndication/text()");

        /**
         * - If the validation outputs VALID<br>
         * - - If there is no validation constraint mandating the validation of the LTV attributes/properties, go to step
         * 9.<br>
         * - - Otherwise, go to step 3.<br>
         * TODO: 20130702 by bielecro: To notify ETSI --> There is no step 9.
         *
         */

        XmlNode constraintNode = addConstraint(signatureNode, PSV_IATVC_LABEL, PSV_IATVS);

        if (VALID.equals(adestSignatureIndication)) {

            constraintNode.addChild(STATUS, OK);
            final List<XmlDom> adestInfo = adestSignatureConclusion.getElements("./Info");
            constraintNode.addChildren(adestInfo);
            conclusionNode.addChildren(adestInfo);
            return true;
        }

        /**
         * - If the validation outputs one of the following:<br>
         * -- INDETERMINATE/REVOKED_NO_POE,<br>
         * -- INDETERMINATE/REVOKED_CA_NO_POE,<br>
         * -- INDETERMINATE/OUT_OF_BOUNDS_NO_POE or<br>
         * -- INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE,<br>
         * go to the next step.<br>
         *
         * - In all other cases, fail with returned code and information.<br>
         *
         * NOTE 2: We go to the LTV part of the validation process in the cases INDETERMINATE/REVOKED_NO_POE,
         * INDETERMINATE/REVOKED_CA_NO_POE, INDETERMINATE/OUT_OF_BOUNDS_NO_POE and INDETERMINATE/
         * CRYPTO_CONSTRAINTS_FAILURE_NO_POE because additional proof of existences may help to go from INDETERMINATE to a
         * determined status.<br>
         *
         * NOTE 3: Performing the LTV part of the algorithm even when the basic validation gives VALID may be useful in
         * the case the SVA is controlled by an archiving service. In such cases, it may be necessary to ensure that any
         * LTV attribute/property present in the signature is actually valid before making a decision about the archival
         * of the signature.<br>
         */
        final boolean finalStatus = INDETERMINATE.equals(adestSignatureIndication) && (RuleUtils
              .in(adestSignatureSubIndication, REVOKED_NO_POE, REVOKED_CA_NO_POE, OUT_OF_BOUNDS_NO_POE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE));
        if (!finalStatus) {

            conclusionNode.addChildrenOf(adestSignatureConclusion);
            constraintNode.addChild(STATUS, KO);
            constraintNode.addChild(INFO, adestSignatureIndication).setAttribute(FIELD, INDICATION);
            constraintNode.addChild(INFO, adestSignatureSubIndication).setAttribute(FIELD, SUB_INDICATION);
            return false;
        }
        constraintNode.addChild(STATUS, OK);
        constraintNode.addChild(INFO, adestSignatureIndication).setAttribute(FIELD, INDICATION);
        constraintNode.addChild(INFO, adestSignatureSubIndication).setAttribute(FIELD, SUB_INDICATION);

        /**
         * 3) If there is at least one long-term-validation attribute with a poeValue, process them, starting from the
         * last (the newest) one as follows: Perform the time-stamp validation process (see clause 7) for the time-stamp
         * in the poeValue:<br>
         * a) If VALID is returned and the cryptographic hash function used in the time-stamp
         * (MessageImprint.hashAlgorithm) is considered reliable at the generation time of the time-stamp: Perform the POE
         * extraction process with the signature, the long-term-validation attribute, the set of POEs and the
         * cryptographic constraints as inputs. Add the returned POEs to the set of POEs.<br>
         * b) Otherwise, perform past signature validation process with the following inputs: the time-stamp in the
         * poeValue, the status/sub-indication returned in step 3, the TSA's certificate, the X.509 validation parameters,
         * certificate meta-data, chain constraints, cryptographic constraints and the set of POEs. If it returns VALID
         * and the cryptographic hash function used in the time-stamp is considered reliable at the generation time of the
         * time-stamp, perform the POE extraction process and add the returned POEs to the set of POEs. In all other
         * cases:<br>
         * 􀀀 If no specific constraints mandating the validity of the attribute are specified in the validation
         * constraints, ignore the attribute and consider the next long-term-validation attribute.<br>
         * 􀀀 Otherwise, fail with the returned indication/sub-indication and associated explanations<br>
         */

        // TODO 20130702 by bielecro: This must be implemented with the new CAdES Baseline Profile.
        // This is the part of the new CAdES specification:
        // http://www.etsi.org/deliver/etsi_ts/101700_101799/101733/02.01.01_60/ts_101733v020101p.pdf

        /**
         * 4) If there is at least one archive-time-stamp attribute, process them, starting from the last (the newest)
         * one, as follows: perform the time-stamp validation process (see clause 7):
         */
        final XmlNode archiveTimestampsNode = signatureNode.addChild("ArchiveTimestamps");
        final List<XmlDom> archiveTimestamps = signature.getElements("./ArchiveTimestamps/Timestamp");
        if (archiveTimestamps.size() > 0) {

            dealWithTimestamp(archiveTimestampsNode, signatureTimestampValidationData, archiveTimestamps);
        }

        /**
         * 5) If there is at least one time-stamp attribute on the references, process them, starting from the last one
         * (the newest), as follows: perform the time-stamp validation process (see clause 7):<br>
         */

        final XmlNode refsOnlyTimestampsNode = signatureNode.addChild("RefsOnlyTimestamps");
        final List<XmlDom> refsOnlyTimestamps = signature.getElements("./RefsOnlyTimestamps/Timestamp");
        if (refsOnlyTimestamps.size() > 0) {

            dealWithTimestamp(refsOnlyTimestampsNode, signatureTimestampValidationData, refsOnlyTimestamps);
        }

        /**
         * 6) If there is at least one time-stamp attribute on the references and the signature value, process them,
         * starting from the last one, as follows: perform the time-stamp validation process (see clause 7):<br>
         */

        final XmlNode sigAndRefsTimestampsNode = signatureNode.addChild("SigAndRefsTimestamps");
        final List<XmlDom> sigAndRefsTimestamps = signature.getElements("./SigAndRefsTimestamps/Timestamp");
        if (sigAndRefsTimestamps.size() > 0) {

            dealWithTimestamp(sigAndRefsTimestampsNode, signatureTimestampValidationData, sigAndRefsTimestamps);
        }
        /**
         * 7) If there is at least one signature-time-stamp attribute, process them, in the order of their appearance
         * starting from the last one, as follows: Perform the time-stamp validation process (see clause 7)<br>
         */

        final XmlNode timestampsNode = signatureNode.addChild("Timestamps");
        final List<XmlDom> timestamps = signature.getElements("./Timestamps/Timestamp");
        if (timestamps.size() > 0) {

            dealWithTimestamp(timestampsNode, signatureTimestampValidationData, timestamps);
        }
        /**
         * 8) Past signature validation: perform the past signature validation process with the following inputs: the
         * signature, the status indication/sub-indication returned in step 2, the signer's certificate, the x.509
         * validation parameters, certificate meta-data, chain constraints, cryptographic constraints and the set of POEs.
         */

        PastSignatureValidation psvp = new PastSignatureValidation();

        PastSignatureValidationConclusion psvConclusion = psvp.run(params, signature, adestSignatureConclusion);

        signatureNode.addChild(psvConclusion.getValidationData());
        /**
         * If it returns VALID go to the next step. Otherwise, abort with the returned indication/sub-indication and
         * associated explanations.<br>
         */

        constraintNode = addConstraint(signatureNode, PSV_IPSVC_LABEL, PSV_IPSVC);

        if (!VALID.equals(psvConclusion.getIndication())) {

            constraintNode.addChild(STATUS, KO);
            constraintNode.addChild(INFO, psvConclusion.getIndication()).setAttribute(FIELD, INDICATION);
            constraintNode.addChild(INFO, psvConclusion.getSubIndication()).setAttribute(FIELD, SUB_INDICATION);

            conclusionNode.addChild(INDICATION, psvConclusion.getIndication());
            conclusionNode.addChild(SUB_INDICATION, psvConclusion.getSubIndication());
            return false;
        }
        constraintNode.addChild(STATUS, OK);

        /**
         * Data extraction: the SVA shall return the success indication VALID. In addition, the SVA should return
         * additional information extracted from the signature and/or used by the intermediate steps. In particular, the
         * SVA should return intermediate results such as the validation results of any time-stamp token or time-mark.
         * What the DA does with this information is out of the scope of the present document.<br>
         */
        return true;
    }

    /**
     * @param processNode
     * @param signatureTimestampValidationData
     *
     * @param timestamps
     * @throws DSSException
     */
    private void dealWithTimestamp(final XmlNode processNode, final XmlDom signatureTimestampValidationData,
                                   final List<XmlDom> timestamps) throws DSSException {

        Collections.sort(timestamps, new TimestampComparator());
        for (final XmlDom timestamp : timestamps) {

            final String timestampId = timestamp.getValue("./@Id");
            try {

                final XmlDom timestampConclusion = signatureTimestampValidationData
                      .getElement("./Timestamp[@Id='%s']/BasicBuildingBlocks/Conclusion", timestampId);
                final String timestampIndication = timestampConclusion.getValue("./Indication/text()");

                /**
                 * a) If VALID is returned and the cryptographic hash function used in the time-stamp
                 * (MessageImprint.hashAlgorithm) is considered reliable at the generation time of the time-stamp: Perform
                 * the POE extraction process with:<br>
                 * - the signature,<br>
                 * - the archive-time-stamp,<br>
                 * - the set of POEs and<br>
                 * - the cryptographic constraints as inputs.<br>
                 * Add the returned POEs to the set of POEs.
                 */
                if (VALID.equals(timestampIndication)) {

                    processNode.addChild("POEExtraction", OK);
                    extractPOEs(timestamp);
                } else {

                    /**
                     * b) Otherwise, perform past signature validation process with the following inputs:<br>
                     * - the archive time-stamp,<br>
                     * - the status/sub-indication returned in step 4,<br>
                     * - the TSA's certificate,<br>
                     * - the X.509 validation parameters,<br>
                     * - certificate meta-data, <br>
                     * - chain constraints,<br>
                     * - cryptographic constraints and<br>
                     * - the set of POEs.
                     */

                    final PastSignatureValidation psvp = new PastSignatureValidation();
                    final PastSignatureValidationConclusion psvConclusion = psvp.run(params, timestamp, timestampConclusion);

                    processNode.addChild(psvConclusion.getValidationData());

                    /**
                     * If it returns VALID and the cryptographic hash function used in the time-stamp is considered reliable
                     * at the generation time of the time-stamp, perform the POE extraction process and add the returned POEs
                     * to the set of POEs.
                     */
                    if (VALID.equals(psvConclusion.getIndication())) {

                        final boolean couldExtract = extractPOEs(timestamp);
                        if (couldExtract) {

                            continue;
                        }
                    }
                    /**
                     * In all other cases:<br>
                     * 􀀀 If no specific constraints mandating the validity of the attribute are specified in the validation
                     * constraints, ignore the attribute and consider the next archive-time-stamp attribute.<br>
                     */
                    /**
                     * --> Concerning DSS there is no specific constraints.
                     */
                    /**
                     * 􀀀 Otherwise, fail with the returned indication/sub-indication and associated explanations.<br>
                     *
                     * NOTE 4: If the signature is PAdES, document time-stamps replace archive-time-stamp attributes and the
                     * process "Extraction from a PDF document time-stamp" replaces the process
                     * "Extraction from an archive-time-stamp".<br>
                     */
                }
            } catch (Exception e) {
                throw new DSSException("Error for timestamp: id: " + timestampId, e);
            }
        }
    }

    /**
     * @param timestamp
     * @return
     * @throws DSSException
     */
    private boolean extractPOEs(final XmlDom timestamp) throws DSSException {

        final String digestAlgo = RuleUtils.canonicalizeDigestAlgo(timestamp.getValue("./SignedDataDigestAlgo/text()"));
        final Date algoExpirationDate = constraintData.getAlgorithmExpirationDate(digestAlgo);
        final Date timestampProductionTime = timestamp.getTimeValue("./ProductionTime/text()");
        if (algoExpirationDate == null || timestampProductionTime.before(algoExpirationDate)) {

            poe.addPOE(timestamp, params.getCertPool());
            return true;
        }
        return false;
    }

    /**
     * @return
     */
    private XmlNode addConstraint(XmlNode parentNode, final String label, final String nameId) {

        XmlNode constraintNode = parentNode.addChild(CONSTRAINT);
        constraintNode.addChild(NAME, label).setAttribute(NAME_ID, nameId);
        return constraintNode;
    }
}
