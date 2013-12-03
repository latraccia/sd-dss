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

import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.VConstraint;

/**
 * This class implements:<br>
 *
 * 8 Validation Process for AdES-T
 *
 * 8.1 Description<br>
 *
 * An AdES-T signature is built on BES or EPES signature and incorporates trusted time associated to the signature. The
 * trusted time may be provided by two different means:
 *
 * • A signature time-stamp unsigned property/attribute added to the electronic signature.
 *
 * • A time mark of the electronic signature provided by a trusted service provider.
 *
 * This clause describes a validation process for AdES-T signatures.
 *
 * @author bielecro
 */
public class AdESTValidation implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage {

    private static final Logger LOG = Logger.getLogger(AdESTValidation.class.getName());

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

    // Secondary inputs
    /**
     * See {@link ProcessParameters#getCurrentTime()}
     *
     * @return
     */
    private Date currentTime;

    /**
     * See {@link eu.europa.ec.markt.dss.validation102853.engine.rules.ProcessParameters#getBvData()}
     *
     * @return
     */
    private XmlDom basicValidationData;

    private XmlDom timestampValidationData; // Basic Building Blocks for timestamps

    // local helper variable
    Date bestSignatureTime;
    private XmlNode conclusionNode;

    private void prepareParameters(final XmlNode mainNode, final ProcessParameters params) {

        this.diagnosticData = params.getDiagnosticData();
        this.constraintData = params.getConstraintData();
        this.currentTime = params.getCurrentTime();
        isInitialised(mainNode, params);
    }

    /**
     * Checks if each necessary data needed to carry out the validation process is present. The process can be called
     * from different contexts. This method calls automatically the necessary sub processes to prepare all input data.
     *
     * @param params
     */
    private void isInitialised(final XmlNode mainNode, final ProcessParameters params) {

        if (diagnosticData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
        }
        if (constraintData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "policyData"));
        }
        if (currentTime == null) {

            currentTime = new Date();
            params.setCurrentTime(currentTime);
        }
        if (basicValidationData == null) {

            /**
             * The execution of the Basic Validation process which creates the basic validation data.<br>
             */
            final BasicValidation basicValidation = new BasicValidation();
            basicValidationData = basicValidation.run(mainNode, params);
        }
        if (timestampValidationData == null) {

            /**
             * This executes the Basic Building Blocks process for timestamps present in the signature.<br>
             * This process needs the diagnostic and policy data. It creates the timestamps validation data.
             */
            final TimestampValidation timeStampValidation = new TimestampValidation();
            timestampValidationData = timeStampValidation.run(mainNode, params);
        }
    }

    /**
     * This method runs the AdES-T validation process.
     *
     * 8.2 Inputs<br>
     * - Signature ..................... Mandatory<br>
     * - Signed data object (s) ........ Optional<br>
     * - Trusted-status Service Lists .. Optional<br>
     * - Signature Validation Policies . Optional<br>
     * - Local configuration ........... Optional<br>
     * - Signer's Certificate .......... Optional<br>
     *
     * 8.3 Outputs<BR>
     * The main output of the signature validation is a status indicating the validity of the signature. This status may
     * be accompanied by additional information (see clause 4).
     *
     * 8.4 Processing<BR>
     * The following steps shall be performed:
     *
     * @param params
     * @return
     */
    public XmlDom run(final XmlNode mainNode, final ProcessParameters params) {

        prepareParameters(mainNode, params);
        LOG.fine(this.getClass().getSimpleName() + ": start.");

        // This script is a validation process for AdES-T signatures.
        XmlNode adestValidationData = mainNode.addChild(ADEST_VALIDATION_DATA);

        /**
         * 1) Initialise the set of signature time-stamp tokens from the signature time-stamp properties/attributes
         * present in the signature and initialise the best-signature-time to the current time.
         *
         * NOTE 1: Best-signature-time is an internal variable for the algorithm denoting the earliest time when it can be
         * proven that a signature has existed.
         */

        // current time
        bestSignatureTime = currentTime;

        final List<XmlDom> signatures = diagnosticData.getElements("/DiagnosticData/Signature");

        for (final XmlDom signature : signatures) {

            final String signatureId = signature.getValue("./@Id");

            final XmlNode signatureNode = adestValidationData.addChild(SIGNATURE);
            signatureNode.setAttribute(ID, signatureId);

            conclusionNode = new XmlNode(CONCLUSION);

            final boolean valid = process(signature, signatureId, signatureNode);

            if (valid) {

                conclusionNode.addChild(INDICATION, VALID);
                final String formatedBestSignatureTime = RuleUtils.formatDate(bestSignatureTime);
                conclusionNode.addChild(INFO, formatedBestSignatureTime).setAttribute(FIELD, TIMESTAMP_PRODUCTION_TIME);

            }
            conclusionNode.setParent(signatureNode);
        }
        if (ProcessParameters.isLoggingEnabled()) {

            System.out.println("");
            System.out.println(adestValidationData.toString());
        }
        final Document atvDocument = ValidationResourceManager.xmlNodeIntoDom(adestValidationData);
        final XmlDom atvDom = new XmlDom(atvDocument);
        params.setAdestData(atvDom);
        return atvDom;
    }

    /**
     * @param signature
     * @param signatureId
     * @param signatureNode
     * @return
     */
    private boolean process(final XmlDom signature, final String signatureId, final XmlNode signatureNode) {

        /**
         * 2) Signature validation: Perform the validation process for BES signatures (see clause 6) with all the inputs,
         * including the processing of any signed attributes/properties as specified. If this validation outputs VALID,
         * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE or
         * INDETERMINATE/OUT_OF_BOUNDS_NO_POE, go to the next step. Otherwise, terminate with the returned status and
         * information.<br>
         * TODO: 20130702 by bielecro: To notify ETSI --> There is twice CRYPTO_CONSTRAINTS_FAILURE_NO_POE instead of
         * REVOKED_NO_POE.
         */

        final XmlNode bvdConstraintNode = addConstraint(signatureNode, ADEST_ROBVPIIC_LABEL, ADEST_ROBVPIIC);

        final XmlDom bvpConclusion = basicValidationData.getElement("/" + BASIC_VALIDATION_DATA + "/Signature[@Id='%s']/Conclusion", signatureId);
        final String bvpIndication = bvpConclusion.getValue("./Indication/text()");
        final String bvpSubIndication = bvpConclusion.getValue("./SubIndication/text()");

        if (!(VALID.equals(bvpIndication) || INDETERMINATE.equals(bvpIndication) && (RuleUtils
              .in(bvpSubIndication, CRYPTO_CONSTRAINTS_FAILURE_NO_POE, OUT_OF_BOUNDS_NO_POE, REVOKED_NO_POE)))) {

            bvdConstraintNode.addChild(STATUS, KO);
            conclusionNode.addChildrenOf(bvpConclusion);
            return false;
        }
        bvdConstraintNode.addChild(STATUS, OK);

        /**
         * NOTE 2: We continue the process in the case INDETERMINATE/REVOKED_NO_POE, because a proof that the signing
         * occurred before the revocation date may help to go from INDETERMINATE to VALID (step 5-a).
         *
         * NOTE 3: We continue the process in the case INDETERMINATE/OUT_OF_BOUNDS_NO_POE, because a proof that the
         * signing occurred before the issuance date (notBefore) of the signer's certificate may help to go from
         * INDETERMINATE to INVALID (step 5-b).
         *
         * NOTE 4: We continue the process in the case INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, because a proof
         * that the signing occurred before the time one of the algorithms used was no longer considered secure may help
         * to go from INDETERMINATE to VALID (step 5-c).
         */

        /**
         * 3) Verification of time-marks: the verification of time-marks is out of the scope of the present document. If
         * the SVA accepts a time-mark as trustworthy (based on out-of-band mechanisms) and if the indicated time is
         * before the best-signature-time, set best-signature-time to the indicated time.
         */

      /*
       * The DSS framework does not handle the time-marks.
       */

        // This is the list of acceptable timestamps
        final List<Integer> rightTimestamps = new ArrayList<Integer>();

        final List<XmlDom> timestamps = signature.getElements("./Timestamps/Timestamp");

        final Set<String> infoList = new LinkedHashSet<String>();
        boolean found = false;

        for (final XmlDom timestamp : timestamps) {

            final int timestampId = timestamp.getIntValue("./@Id");
            final String timestampIdLabel = "[" + timestampId + "]";
            final Date productionTime = timestamp.getTimeValue("./ProductionTime/text()");

            final XmlNode timestampNode = signatureNode.addChild(TIMESTAMP);
            timestampNode.setAttribute(ID, String.valueOf(timestampId));
            timestampNode.setAttribute(GENERATION_TIME, RuleUtils.formatDate(productionTime));

            /**
             * 4) Signature time-stamp validation: Perform the following steps:
             *
             * a) Message imprint verification: For each time-stamp token in the set of signature time-stamp tokens, do the
             * message imprint verification as specified in clauses 8.4.1 or 8.4.2 depending on the type of the signature.
             * If the verification fails, remove the token from the set.
             */

            XmlNode constraintNode = addConstraint(timestampNode, ADEST_IMIVC_LABEL, ADEST_IMIVC);

            final boolean isSignedDataIntact = timestamp.getBoolValue("./ReferenceDataIntact/text()");
            if (!isSignedDataIntact) {

                constraintNode.addChild(STATUS, KO);
                infoList.add(String.format("Timestamp %s message imprint verification failed.", timestampIdLabel));
                continue;
            }
            constraintNode.addChild(STATUS, OK);
            /**
             * b) Time-stamp token validation: For each time-stamp token remaining in the set of signature time-stamp
             * tokens, the SVA shall perform the time-stamp validation process (see clause 7):
             */

            constraintNode = addConstraint(timestampNode, ADEST_ITVPC_LABEL, ADEST_ITVPC);

            final XmlDom tspvData = timestampValidationData
                  .getElement("/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Id='%s']", signatureId, timestampId);
            final XmlDom tsvpConclusion = tspvData.getElement("./BasicBuildingBlocks/Conclusion");
            final String tsvpIndication = tsvpConclusion.getValue("./Indication/text()");

            /**
             * 􀀀 If VALID is returned and if the returned generation time is before best-signature-time, set
             * best-signature-time to this date and try the next token.
             *
             * 􀀀 In all remaining cases, remove the time-stamp token from the set of signature time-stamp tokens and try
             * the next token.
             */

            if (tsvpIndication.equals(VALID)) {

                if (productionTime.before(bestSignatureTime)) {

                    constraintNode.addChild(STATUS, OK);
                    bestSignatureTime = productionTime;
                    rightTimestamps.add(timestampId);
                    found = true;
                } else {

                    constraintNode.addChild(STATUS, KO);
                    infoList.add(String.format(ADEST_TVINCBIGT_LABEL, timestampIdLabel));
                }
                continue;
            }
            constraintNode.addChild(STATUS, KO);
            infoList.add(String.format(ADEST_TVINC_LABEL, timestampIdLabel));
            final List<XmlDom> infoListDom = tsvpConclusion.getElements("./Info");
            for (final XmlDom info : infoListDom) {

                final String attributeValue = info.getAttribute(FIELD);
                final String nodeValue = info.getText();
                if (true /* attributeValue.contains(AcceptableDigestAlgo */) {

                    infoList.add(attributeValue + "=" + nodeValue);
                } else {

                    infoList.add(attributeValue + "=" + nodeValue);
                }
            }
        }
        final XmlNode tvdConstraintNode = addConstraint(signatureNode, ADEST_ROVPFTIIC_LABEL, ADEST_ROVPFTIIC);

        if (!found) {

            tvdConstraintNode.addChild(STATUS, KO);
            conclusionNode.addChild(INDICATION, INDETERMINATE);
            if (timestamps.size() > 0) {

                tvdConstraintNode.addChild(INFO, NO_VALID_TIMESTAMP_LABEL);
                conclusionNode.addChild(SUB_INDICATION, NO_VALID_TIMESTAMP);
            } else {

                tvdConstraintNode.addChild(INFO, NO_TIMESTAMP_LABEL);
                conclusionNode.addChild(SUB_INDICATION, NO_TIMESTAMP);
            }
            for (String simpleInfo : infoList) {

                conclusionNode.addChild(INFO, simpleInfo);
            }
            return false;
        } else {

            tvdConstraintNode.addChild(STATUS, OK);
        }
        final String formatedBestSignatureTime = RuleUtils.formatDate(bestSignatureTime);
        tvdConstraintNode.addChild(INFO, formatedBestSignatureTime).setAttribute(FIELD, BEST_SIGNATURE_TIME);

        /**
         * 5) Comparing times:
         */

        final XmlDom infoDom = bvpConclusion.getElement("./Info");

        if (INDETERMINATE.equals(bvpIndication) && REVOKED_NO_POE.equals(bvpSubIndication)) {

            /**
             * a) If step 2 returned INDETERMINATE/REVOKED_NO_POE: If the returned revocation time is posterior to
             * best-signature-time, perform step 5d. Otherwise, terminate with INDETERMINATE/REVOKED_NO_POE. In addition to
             * the data items returned in steps 1 and 2, the SVA should notify the DA with the reason of the failure.
             */
            final XmlNode constraintNode = addConstraint(signatureNode, TSV_IRTPTBST_LABEL, TSV_IRTPTBST);

            final Date revocationDate = bvpConclusion.getTimeValue("./Info[@Field='RevocationTime']/text()");
            final String revocationReason = bvpConclusion.getValue("./Info[@Field='RevocationReason']/text()");

            if (bestSignatureTime.before(revocationDate)) {

                constraintNode.addChild(STATUS, OK);
            } else {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INDETERMINATE);
                conclusionNode.addChild(SUB_INDICATION, REVOKED_NO_POE);
                conclusionNode.addChild(infoDom);
                conclusionNode.addChild(INFO, formatedBestSignatureTime).setAttribute(FIELD, BEST_SIGNATURE_TIME);
                final String formatedRevocationDate = RuleUtils.formatDate(revocationDate);
                conclusionNode.addChild(INFO, formatedRevocationDate).setAttribute(FIELD, REVOCATION_TIME);
                conclusionNode.addChild(INFO, revocationReason).setAttribute(FIELD, REVOCATION_REASON);
                return false;
            }
        }

        if (INDETERMINATE.equals(bvpIndication) && OUT_OF_BOUNDS_NO_POE.equals(bvpSubIndication)) {

            /**
             * b) If step 2 returned INDETERMINATE/OUT_OF_BOUNDS_NO_POE: If best-signature-time is before the issuance date
             * of the signer's certificate, terminate with INVALID/NOT_YET_VALID. Otherwise, terminate with
             * INDETERMINATE/OUT_OF_BOUNDS_NO_POE. In addition to the data items returned in steps 1 and 2, the SVA should
             * notify the DA with the reason of the failure.
             */
            /**
             * NOTE 5: In the algorithm above, the signature-time-stamp protects the signature against the revocation of
             * the signer's certificate (step 5-a) but not against expiration. The latter case requires validating the
             * signer's certificate in the past (see clause 9).
             */
            final XmlNode constraintNode = addConstraint(signatureNode, TSV_IBSTAIDOSC_LABEL, TSV_IBSTAIDOSC);

            final Date notBefore = bvpConclusion.getTimeValue("./Info[@Field='NotBefore']/text()");
            final String formatedNotBefore = RuleUtils.formatDate(notBefore);
            if (bestSignatureTime.before(notBefore)) {

                constraintNode.addChild(STATUS, KO);
                constraintNode.addChild(INFO, formatedNotBefore).setAttribute(FIELD, NOT_BEFORE);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, NOT_YET_VALID);

                conclusionNode.addChild(infoDom);
                return false;
            } else {

                constraintNode.addChild(STATUS, KO);
                constraintNode.addChild(INFO, formatedNotBefore).setAttribute(FIELD, NOT_BEFORE);
                conclusionNode.addChild(INDICATION, INDETERMINATE);
                conclusionNode.addChild(SUB_INDICATION, OUT_OF_BOUNDS_NO_POE);

                conclusionNode.addChild(infoDom);
                final String _formated_time = RuleUtils.formatDate(bestSignatureTime);
                conclusionNode.addChild(INFO, _formated_time).setAttribute(FIELD, BEST_SIGNATURE_TIME);
                conclusionNode.addChild(INFO, ADEST_BSTIAIDSC_LABEL);
                return false;
            }
        }

        if (INDETERMINATE.equals(bvpIndication) && CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(bvpSubIndication)) {

            /**
             * c) If step 2 returned INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the material concerned by this
             * failure is the signature value or a signed attribute, check, if the algorithm(s) concerned were still
             * considered reliable at best-signature-time, continue with step d. Otherwise, terminate with
             * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
             */
            boolean ok = true;
            final List<XmlDom> conclusionInfoList = bvpConclusion.getElements("./Info");
            for (final XmlDom info : conclusionInfoList) {

                final String field = info.getValue("./@Field");
                if (field.contains("/AlgoExpirationDate")) { // Should be only on the signature value or a signed attribute.

                    final String expirationDateString = info.getValue("./text()");
                    if (!ALGORITHM_NOT_FOUND.equals(expirationDateString)) {

                        final Date expirationDate = RuleUtils.parseDate(RuleUtils.SDF_DATE, expirationDateString);
                        if (expirationDate.before(bestSignatureTime)) {

                            ok = false;
                        }
                    } else {

                        ok = false;
                    }
                }
            }

            final XmlNode constraintNode = addConstraint(signatureNode, TSV_WACRABST_LABEL, TSV_WACRABST);

            if (ok) {

                constraintNode.addChild(STATUS, OK);
            } else {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INDETERMINATE);
                conclusionNode.addChild(SUB_INDICATION, CRYPTO_CONSTRAINTS_FAILURE_NO_POE);

                conclusionNode.addChild(infoDom);
                return false;
            }
        }
        /**
         * d) For each time-stamp token remaining in the set of signature time-stamp tokens, check the coherence in the
         * values of the times indicated in the time-stamp tokens. They shall be posterior to the times indicated in any
         * time-stamp token computed on the signed data (i.e. any content-time-stamp signed attributes in CAdES or any
         * AllDataObjectsTimeStamp or IndividualDataObjectsTimeStamp signed present properties in XAdES). The SVA shall
         * apply the rules specified in RFC 3161 [11], clause 2.4.2 regarding the order of time-stamp tokens generated by
         * the same or different TSAs given the accuracy and ordering fields' values of the TSTInfo field, unless stated
         * differently by the Signature Constraints. If all the checks end successfully, go to the next step. Otherwise
         * return INVALID/TIMESTAMP_ORDER_FAILURE.
         */
        XmlNode constraintNode = addConstraint(signatureNode, TSV_ASTPTCT_LABEL, TSV_ASTPTCT);

        boolean _ok = true;
        for (XmlDom timestamp : timestamps) {

            final String timestampId = timestamp.getValue("./@Id");
            final Integer timestampIdValue = Integer.valueOf(timestampId);
            if (!rightTimestamps.contains(timestampIdValue)) {

                continue;
            }
            final Date productionTime = timestamp.getTimeValue("./ProductionTime/text()");
            final List<XmlDom> contentTimestamps = signature.getElements("./ContentTimestamps/ProductionTime");
            for (final XmlDom contentTimestamp : contentTimestamps) {

                final Date contentProductionTime = contentTimestamp.getTimeValue("./text()");
                if (contentProductionTime.after(productionTime)) {

                    if (_ok) {

                        constraintNode.addChild(STATUS, KO);
                        conclusionNode.addChild(INDICATION, INVALID);
                        conclusionNode.addChild(SUB_INDICATION, TIMESTAMP_ORDER_FAILURE);
                    }
                    final String _attribute = String
                          .format("/DiagnosticData/Signature[@Id='%s']/Timestamps/Timestamp[@Id='%s']/ProductionTime/text()", signatureId,
                                timestampId);
                    conclusionNode.addChild(INFO, contentProductionTime.toString()).setAttribute(FIELD, _attribute);
                    _ok = false;
                }
            }
        }
        if (_ok) {

            constraintNode.addChild(STATUS, OK);
        } else {

            return false;
        }

        /**
         * 6) Handling Time-stamp delay: If the validation constraints specify a time-stamp delay, do the following:
         */

        final Long timestampDelay = constraintData.getTimestampDelayTime();

        if (timestampDelay != null && timestampDelay > 0) {

            /**
             * a) If no signing-time property/attribute is present, fail with INDETERMINATE and an explanation that the
             * validation failed due to the absence of claimed signing time.
             */

            constraintNode = addConstraint(signatureNode, TSV_ISTPAP_LABEL, TSV_ISTPAP);

            long signingTimeValue = 0;
            try {

                final Date signingTime = signature.getTimeValue("./DateTime/text()");
                signingTimeValue = signingTime.getTime();
            } catch (Exception e) {
                // the signing-time is considered as absent.
            }
            if (signingTimeValue > 0) {

                constraintNode.addChild(STATUS, OK);
            } else {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INDETERMINATE);
                conclusionNode.addChild(INFO, ADEST_VFDTAOCST_LABEL);
                return false;
            }

            /**
             * b) If a signing-time property/attribute is present, check that the claimed time in the attribute plus the
             * timestamp delay is after the best-signature-time. If the check is successful, go to the next step.
             * Otherwise, fail with INVALID/SIG_CONSTRAINTS_FAILURE and an explanation that the validation failed due to
             * the time-stamp delay constraint.
             */

            constraintNode = addConstraint(signatureNode, TSV_ISTPTDABST_LABEL, TSV_ISTPTDABST);

            final long timestampDeltaTime = bestSignatureTime.getTime() - signingTimeValue;
            if (timestampDeltaTime <= timestampDelay) {

                constraintNode.addChild(STATUS, OK);
            } else {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                conclusionNode.addChild(INFO, ADEST_VFDTTDC_LABEL);
                return false;
            }
        }
        return true;
    }

    /**
     * @return
     */
    private XmlNode addConstraint(final XmlNode parent, final String label, final String nameId) {

        XmlNode constraintNode = parent.addChild(CONSTRAINT);
        constraintNode.addChild(NAME, label).setAttribute(NAME_ID, nameId);
        return constraintNode;
    }
}
