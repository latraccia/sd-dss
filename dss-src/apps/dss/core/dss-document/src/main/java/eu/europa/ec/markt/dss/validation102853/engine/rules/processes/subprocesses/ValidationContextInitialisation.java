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
import eu.europa.ec.markt.dss.validation102853.engine.rules.RuleConstant;
import eu.europa.ec.markt.dss.validation102853.engine.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.VConstraint;

public class ValidationContextInitialisation implements RuleConstant, Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage {

    /**
     * See {@link ProcessParameters#getDiagnosticData()}
     */
    private XmlDom diagnosticData;

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

        this.diagnosticData = params.getDiagnosticData();
        this.constraintData = params.getConstraintData();
        this.signatureContext = params.getSignatureContext();

        isInitialised();
    }

    private void isInitialised() {

        if (diagnosticData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
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
         * 5.2. Validation Context Initialisation (VCI)
         */

        subProcessNode = processNode.addChild(VCI);
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

        XmlNode constraintNode = addConstraint(BBB_VCI_IPK_LABEL, BBB_VCI_IPK);

        /**
         * info:<br>
         * There may be situation were a signer wants to explicitly indicate to a verifier that by signing the data, it
         * illustrates a type of commitment on behalf of the signer. The commitmentTypeIndication attribute conveys such
         * information.
         *
         * 5.2.4 Processing<br>
         * If the validation constraints and parameters have been initialised using an allowed set of signatureContext validation
         * policies [i.2], [i.3], and if the signatureContext has been created under one of these policies and also contains a
         * commitment type indication property/attribute, the specific commitment defined in the policy shall be selected
         * using this attribute. The clauses below describe the processing of these properties/attributes. The processing
         * of additional sources for initialisation (e.g. local configuration) is out of the scope of the present
         * document. This implies that a signatureContext policy referenced in a signatureContext shall be known to the verifier and
         * listed in the set of acceptable policies. If the policy is unknown to the verifier, accepting a commitment type
         * is not possible and may even be dangerous. In this case, the SVA shall return INVALID/UNKNOWN_COMMITMENT_TYPE.
         *
         * If the SVA cannot identify the policy to use, it shall return INDETERMINATE/NO_POLICY.
         */

        final String policyId = signatureContext.getValue("./Policy/Id/text()");
        if (policyId.isEmpty()) {

            if (constraintData == null) {

                addNoPolicyNode(constraintNode, conclusionNode);
                return false;
            }
            // The default policy is used to validate the signatureContext(s)
            final String policy = constraintData.getPolicyName();
            addPolicyNode(constraintNode, policy);
        } else if (constraintData != null) {

            if (constraintData.isAnyPolicyAcceptable()) {

                addPolicyNode(constraintNode, policyId);
            } else {

                if (constraintData.isPolicyAcceptable(policyId)) {

                    addPolicyNode(constraintNode, policyId);
                } else {

                    addNoPolicyNode(constraintNode, conclusionNode);
                    return false;
                }
            }
        } else {

            addNoPolicyNode(constraintNode, conclusionNode);
            return false;
        }

        /**
         * 5.2.4.1 Processing commitment type indication<br>
         * If this signed property is present, it allows identifying the commitment type and thus affects all rules for
         * validation, which depend on the commitment type that shall be used in the validation context initialisation.
         *
         * 5.2.4.1.1 XAdES Processing.<br>
         * If the signatureContext is a XAdES signatureContext, the SVA shall check that each xades:ObjectReference element within the
         * xades:CommitmentTypeIndication actually references a ds:Reference element present in the signatureContext. If any of
         * these elements does not refer to one of the ds:Reference elements, then the SVA shall assume that a format
         * failure has occurred during the verification and return INVALID/FORMAT_FAILURE with an indication that the
         * validation failed to an invalid commitment type property.
         *
         * 5.2.4.2 Processing Signature Policy Identifier<br>
         * If this signed property/attribute is present and it is not implied, the SVA shall perform the following checks.<br>
         * If any of these checks fail, then the SVA shall assume that a failure has occurred during the verification and
         * return INVALID/ POLICY_PROCESSING_ERROR with an indication that the validation failed to an invalid signatureContext
         * policy identifier property/attribute.
         */
        return true;
    }

    /**
     * @param constraintNode
     * @param policy
     */
    private void addPolicyNode(final XmlNode constraintNode, final String policy) {

        constraintNode.addChild(STATUS, OK);
        constraintNode.addChild(INFO, policy).setAttribute(FIELD, POLICY);
    }

    /**
     * @param constraintNode
     */
    private void addNoPolicyNode(final XmlNode constraintNode, final XmlNode conclusionNode) {

        constraintNode.addChild(STATUS, KO);
        conclusionNode.addChild(INDICATION, INDETERMINATE);
        conclusionNode.addChild(SUB_INDICATION, NO_POLICY);
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
