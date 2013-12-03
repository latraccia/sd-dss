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

package eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses;

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
import eu.europa.ec.markt.dss.validation102853.engine.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.VConstraint;

public class SignatureAcceptanceValidation implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage {

    /**
     * The following variables are used only in order to simplify the writing of the rules!
     */

    /**
     * See {@link ProcessParameters#getConstraintData()}
     */
    private VConstraint constraintData;

    /**
     * See {@link ProcessParameters#getSignatureContext()}
     */
    private XmlDom signatureContext;

    /**
     * This node is used to add the constraint nodes.
     */
    private XmlNode subProcessNode;

    private void prepareParameters(final ProcessParameters params) {

        this.constraintData = params.getConstraintData();

        this.signatureContext = params.getSignatureContext();

        isInitialised();
    }

    private void isInitialised() {

        if (constraintData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "policyData"));
        }
        if (signatureContext == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "signatureContext"));
        }
    }

    public boolean run(final ProcessParameters params, final XmlNode processNode) {

        if (processNode == null) {

            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "processNode"));
        }
        prepareParameters(params);

        /**
         * 5.5 Signature Acceptance Validation (SAV)
         */

        subProcessNode = processNode.addChild(SAV);
        final XmlNode conclusionNode = new XmlNode(CONCLUSION);

        final boolean valid = process(params, conclusionNode);

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
     * @param params
     * @param conclusionNode
     * @return
     */
    private boolean process(final ProcessParameters params, final XmlNode conclusionNode) {

        /**
         * This process consists in checking the Signature and Cryptographic Constraints against the signature. The
         * general principle is as follows: perform the following for each constraint:
         *
         * • If the constraint necessitates processing a property/attribute in the signature, perform the processing of
         * the property/attribute as specified from clause 5.5.4.1 to 5.5.4.8.
         *
         * 5.5.4.1 Processing AdES properties/attributes This clause describes the application of Signature Constraints on
         * the content of the signature including the processing on signed and unsigned properties/attributes.
         *
         * <SigningCertificateChainConstraint><br>
         * <MandatedSignedQProperties>
         *
         * Indicates the mandated signed qualifying properties that are mandated to be present in the signature. This
         * includes:
         *
         * • signing-time
         */

        final boolean checkIfSigningTimeIsPresent = constraintData.shouldCheckIfSigningTimeIsPresent();
        if (checkIfSigningTimeIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_ISQPSTP_LABEL, BBB_SAV_ISQPSTP);

            final String signingTime = signatureContext.getValue("./DateTime/text()");
            if (signingTime.isEmpty()) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                conclusionNode.addChild(INFO, BBB_SAV_ISQPSTP_ANS_LABEL);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
            constraintNode.addChild(INFO, signingTime).setAttribute(FIELD, SIGNING_TIME);
        }

        /**
         * • content-hints<br>
         * • content-reference<br>
         * • content-identifier
         */

        /**
         * • commitment-type-indication
         */

        final boolean checkIfCommitmentTypeIndicationIsPresent = constraintData.shouldCheckIfCommitmentTypeIndicationIsPresent();
        if (checkIfCommitmentTypeIndicationIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_ISQPXTIP_LABEL, BBB_SAV_ISQPXTIP);
            final String _commitment_type_indication = signatureContext.getValue("./CommitmentTypeIndication/text()");
            if (_commitment_type_indication.isEmpty()) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
        }

        /**
         * • signer-location
         */

        final boolean checkIfSignerLocationIsPresent = constraintData.shouldCheckIfSignerLocationIsPresent();
        if (checkIfSignerLocationIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_ISQPSLP_LABEL, BBB_SAV_ISQPSLP);

            final String signProductionPlace = signatureContext.getValue("./SignatureProductionPlace/text()");
            if (signProductionPlace.isEmpty()) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
        }

        /**
         * • signer-attributes<br>
         * • content-time-stamp
         *
         * <MandatedUnsignedQProperties>
         *
         * ../..
         *
         * <OnRoles>
         */

        final boolean checkIfSignerRoleIsPresent = constraintData.shouldCheckIfSignerRoleIsPresent();
        if (checkIfSignerRoleIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_IRM_LABEL, BBB_SAV_IRM);

            final String requestedSignerRole = constraintData.getRequestedSignerRole();
            final String signerRole = signatureContext.getValue("./ClaimedRoles/ClaimedRole[1]/text()");

            if (!signerRole.equals(requestedSignerRole)) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                conclusionNode.addChild(INFO, requestedSignerRole);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
            conclusionNode.addChild(INFO, signerRole);
        }

        /**
         * 5.5.4.2 Processing signing certificate reference constraint<br>
         * If the SigningCertificate property contains references to other certificates in the path, the verifier shall
         * check each of the certificates in the certification path against these references as specified in steps 1 and 2
         * in clause 5.1.4.1 (resp clause 5.1.4.2) for XAdES (resp CAdES). Should this property contain one or more
         * references to certificates other than those present in the certification path, the verifier shall assume that a
         * failure has occurred during the verification. Should one or more certificates in the certification path not be
         * referenced by this property, the verifier shall assume that the verification is successful unless the signature
         * policy mandates that references to all the certificates in the certification path "shall" be present.
         *
         * ../..
         *
         * 5.5.4.3 Processing claimed signing time<br>
         * If the signature constraints contain constraints regarding this property, the verifying application shall
         * follow its rules for checking this signed property. Otherwise, the verifying application shall make the value
         * of this property/attribute available to its DA, so that it may decide additional suitable processing, which is
         * out of the scope of the present document.
         *
         * ../..
         */

        /**
         * 5.5.4.6 Processing Time-stamps on signed data objects<br>
         * If the signature constraints contain specific constraints for content-time-stamp attributes, the SVA shall
         * check that they are satisfied. To do so, the SVA shall do the following steps for each content-time-stamp
         * attribute:<br>
         * 1) Perform the Validation Process for AdES Time-Stamps as defined in clause 7 with the time-stamp token of the
         * content-time-stamp attribute.<br>
         * 2) Check the message imprint: check that the hash of the signed data obtained using the algorithm indicated in
         * the time-stamp token matches the message imprint indicated in the token.<br>
         * 3) Apply the constraints for content-time-stamp attributes to the results returned in the previous steps. If
         * any check fails, return INVALID/SIG_CONSTRAINTS_FAILURE with an explanation of the unverified constraint.
         */

        // The DSS framework doesn't handle at the level of the signature constraints any specific constraints for
        // content-time-stamp attributes.

        /**
         * ../..<br>
         * • If at least one of the algorithms that have been used in validation of the signature or the size of the keys
         * used with such an algorithm is no longer considered reliable, return
         * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE together with the list of algorithms and key sizes, if
         * applicable, that are concerned and the time for each of the algorithms up to which the resp. algorithm was
         * considered secure.
         */
        final XmlNode constraintNode = addConstraint(BBB_SAV_ASCCM_LABEL, BBB_SAV_ASCCM);

        final SAVCryptographicConstraint cryptoConstraints = new SAVCryptographicConstraint();
        final SAVCryptoConstraintParameters cryptoParams = new SAVCryptoConstraintParameters(params, SIGNATURE_TO_VALIDATE);
        final XmlNode infoContainerNode = new XmlNode("Container");
        final boolean cryptographicStatus = cryptoConstraints.run(cryptoParams, infoContainerNode);
        if (cryptographicStatus) {

            constraintNode.addChild(STATUS, OK);
        } else {

            constraintNode.addChild(STATUS, KO);
            conclusionNode.addChild(INDICATION, INDETERMINATE);
            conclusionNode.addChild(SUB_INDICATION, CRYPTO_CONSTRAINTS_FAILURE_NO_POE);
            conclusionNode.addChildrenOf(infoContainerNode);
            return false;
        }
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
