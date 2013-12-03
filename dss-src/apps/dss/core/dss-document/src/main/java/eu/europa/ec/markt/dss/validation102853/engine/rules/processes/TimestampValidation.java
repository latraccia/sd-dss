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
import eu.europa.ec.markt.dss.validation102853.engine.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses.CryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses.IdentificationOfTheSignersCertificate;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses.SAVCryptographicConstraint;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses.X509CertificateValidation;

/**
 * 7 Validation Process for Time-Stamps<br>
 * <br>
 * 7.1 Description<br>
 * <br>
 * This clause describes a process for the validation of an RFC 3161 [11] time-stamp token. An RFC 3161 [11] time-stamp
 * token is basically a CAdES-BES signature. Hence, the validation process is built in the validation process of a
 * CAdES-BES signature.<br>
 *
 * @author bielecro
 */
public class TimestampValidation implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage {

    private static final Logger LOG = Logger.getLogger(TimestampValidation.class.getName());

    private XmlDom diagnosticData;
    private XmlDom policyData;

    private void prepareParameters(final ProcessParameters params) {

        this.diagnosticData = params.getDiagnosticData();
        if (policyData != null) {

            this.policyData = params.getConstraintData();
        }
        isInitialised();
    }

    private void isInitialised() {

        if (diagnosticData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
        }
    }

    /**
     * 7.4 Processing<br>
     *
     * The following steps shall be performed:<br>
     *
     * 1) Token signature validation: perform the validation process for BES signature (see clause 6) with the time-stamp
     * token. In all the steps of this process, take into account that the signature to validate is a timestamp token
     * (e.g. to select TSA trust-anchors). If this step ends with a success indication, go to the next step. Otherwise,
     * fail with the indication and information returned by the validation process.<br>
     *
     * 2) Data extraction: in addition to the data items returned in step 1, the process shall return data items
     * extracted from the TSTInfo [11] (the generation time, the message imprint, etc.). These items may be used by the
     * SVA in the process of validating the AdES signature.
     *
     * @param params
     * @return
     */
    public XmlDom run(final XmlNode mainNode, final ProcessParameters params) {

        prepareParameters(params);
        LOG.fine(this.getClass().getSimpleName() + ": start.");

        final List<XmlDom> signatures = diagnosticData.getElements("/DiagnosticData/Signature");

        final XmlNode timestampValidationDataNode = mainNode.addChild(TIMESTAMP_VALIDATION_DATA);

        for (final XmlDom signature : signatures) {

            final List<XmlDom> timestamps = new ArrayList<XmlDom>();

            // Extraction of the content timestamps is not implemented by DSS
            // final List<XmlDom> contentTimestamps = signature.getElements("./ContentTimestamps/Timestamp");
            // timestamps.addAll(contentTimestamps);

            // Extraction of the signature timestamps.
            final List<XmlDom> signatureTimestamps = signature.getElements("./Timestamps/Timestamp");
            timestamps.addAll(signatureTimestamps);

            // Extraction of the SigAndRefs timestamps.
            final List<XmlDom> sigAndRefsTimestamps = signature.getElements("./SigAndRefsTimestamps/Timestamp");
            timestamps.addAll(sigAndRefsTimestamps);

            // Extraction of the RefsOnly timestamps.
            final List<XmlDom> refsOnlyTimestamps = signature.getElements("./RefsOnlyTimestamps/Timestamp");
            timestamps.addAll(refsOnlyTimestamps);

            // Extraction of the archive timestamps.
            final List<XmlDom> archiveTimestamps = signature.getElements("./ArchiveTimestamps/Timestamp");
            timestamps.addAll(archiveTimestamps);

            if (timestamps.isEmpty()) {

                continue;
            }

            // This defines the signature context of the execution of the following processes.
            params.setSignatureContext(signature);

            final String signatureId = signature.getValue("./@Id");
            final XmlNode signatureNode = timestampValidationDataNode.addChild(SIGNATURE);
            signatureNode.setAttribute(ID, signatureId);

            for (final XmlDom timestamp : timestamps) {

                // This defines the context of the execution of the following processes. The same sub-processes are used for
                // signature and timestamp validation.
                params.setContextName(TIMESTAMP_CERTIFICATE);
                params.setContextElement(timestamp);

                final String timestampId = timestamp.getValue("./@Id");
                final String timestampCategory = timestamp.getValue("./@Category");
                final XmlNode timestampNode = signatureNode.addChild(TIMESTAMP);
                timestampNode.setAttribute(ID, timestampId);
                timestampNode.setAttribute(CATEGORY, timestampCategory);

                /**
                 * 5. Basic Building Blocks
                 */
                final XmlNode basicBuildingBlocksNode = timestampNode.addChild(BASIC_BUILDING_BLOCKS);

                /**
                 * 5.1. Identification of the signer's certificate (ISC)
                 */
                final IdentificationOfTheSignersCertificate isc = new IdentificationOfTheSignersCertificate();
                final boolean iscValid = isc.run(params, basicBuildingBlocksNode);
                if (!iscValid) {

                    continue;
                }

                /**
                 * 5.2. Validation Context Initialisation (VCI)
                 */

            /*
             * --> Not needed for Timestamps validation. The constraints are already loaded during the execution of the
             * Basic Building Blocks process for the main signature.
             */

                /**
                 * 5.4 Cryptographic Verification (CV)
                 */
                final CryptographicVerification cv = new CryptographicVerification();
                final boolean cvValid = cv.run(params, basicBuildingBlocksNode);
                if (!cvValid) {

                    continue;
                }

                /**
                 * 5.5 Signature Acceptance Validation (SAV)
                 */

                final boolean savValid = runSAV(params, basicBuildingBlocksNode);
                if (!savValid) {

                    continue;
                }

                /**
                 * 5.3 X.509 Certificate Validation (XCV)
                 */
                final X509CertificateValidation xcv = new X509CertificateValidation();
                final boolean xcvValid = xcv.run(params, basicBuildingBlocksNode);
                if (!xcvValid) {

                    continue;
                }

                final XmlNode conclusionNode = basicBuildingBlocksNode.addChild(CONCLUSION);
                conclusionNode.addChild(INDICATION, VALID);
            }
        }
        if (ProcessParameters.isLoggingEnabled()) {

            System.out.println("");
            System.out.println(timestampValidationDataNode.toString());
        }
        final Document tsDocument = ValidationResourceManager.xmlNodeIntoDom(timestampValidationDataNode);
        final XmlDom tsDom = new XmlDom(tsDocument);
        params.setTsData(tsDom);
        return tsDom;
    }

    /**
     * The SAV process for a timestamp is far simpler than that of the principal signature. This is why a specific method
     * is dedicated to its treatment.
     *
     * @param params
     * @param processNode
     * @return
     */
    private boolean runSAV(final ProcessParameters params, final XmlNode processNode) {

        /**
         * 5.5 Signature Acceptance Validation (SAV)
         */

        final XmlNode subProcessNode = processNode.addChild(SAV);
        final XmlNode conclusionNode = new XmlNode(CONCLUSION);

        final boolean valid = processSAV(params, subProcessNode, conclusionNode);

        if (valid) {

            conclusionNode.addChild(INDICATION, VALID);
            conclusionNode.setParent(subProcessNode);
        } else {

            subProcessNode.addChild(conclusionNode);
            processNode.addChild(conclusionNode);
        }
        return valid;
    }

    /**
     * 5.5.4 Processing<br>
     *
     * This process consists in checking the Signature and Cryptographic Constraints against the signature. The general
     * principle is as follows: perform the following for each constraint:<br>
     *
     * • If the constraint necessitates processing a property/attribute in the signature, perform the processing of the
     * property/attribute as specified from clause 5.5.4.1 to 5.5.4.8. <b>--> The DSS framework does not handle the
     * constraints concerning timestamps.</b><br>
     *
     * • If at least one of the algorithms that have been used in validation of the signature or the size of the keys
     * used with such an algorithm is no longer considered reliable, return
     * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE together with the list of algorithms and key sizes, if applicable,
     * that are concerned and the time for each of the algorithms up to which the resp. algorithm was considered secure.
     *
     * @param params
     * @param processNode
     * @param conclusionNode
     * @return
     */
    private boolean processSAV(final ProcessParameters params, final XmlNode processNode, final XmlNode conclusionNode) {

        final XmlNode constraintNode = processNode.addChild(CONSTRAINT);
        constraintNode.addChild(NAME, BBB_SAV_ASCCM_LABEL).setAttribute(NAME_ID, BBB_SAV_ASCCM);

        final SAVCryptographicConstraint cryptoConstraints = new SAVCryptographicConstraint();
        // The context is already the same like the main process.
        // SAVCryptoConstraintParameters cryptoParams = new SAVCryptoConstraintParameters(params);
        // cryptoParams.setContextName(TIMESTAMP);

        final XmlNode infoContainerNode = new XmlNode("Container");
        final boolean cryptographicStatus = cryptoConstraints.run(params, infoContainerNode);

        if (cryptographicStatus) {

            constraintNode.addChild(STATUS, OK);
        } else {

            constraintNode.addChild(STATUS, KO);
            conclusionNode.addChild(SUB_INDICATION, CRYPTO_CONSTRAINTS_FAILURE_NO_POE);
            conclusionNode.addChild(INDICATION, INDETERMINATE);
            conclusionNode.addChildrenOf(infoContainerNode);
            return false;
        }
        return true;
    }
}
