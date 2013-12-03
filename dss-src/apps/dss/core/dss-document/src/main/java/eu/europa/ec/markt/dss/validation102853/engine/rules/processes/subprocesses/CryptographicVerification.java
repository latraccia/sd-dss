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
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.Conclusion;

/**
 * This class executes the cryptographic signature verification. It can be for the document signatures or timestamp
 * signatures...
 *
 * @author bielecro
 */
public class CryptographicVerification implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage {

    private XmlDom contextElement;

    private Conclusion conclusion = new Conclusion();

    /**
     * This node is used to add the constraint nodes.
     */
    private XmlNode subProcessNode;

    private void prepareParameters(final ProcessParameters params) {

        this.contextElement = params.getContextElement();

        isInitialised();
    }

    private void isInitialised() {

        if (contextElement == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "signature"));
        }
    }

    /**
     * 5.4.4 Processing<br>
     * The first and second steps as well as the Data To Be Signed depend on the signature type. The technical details on
     * how to do this correctly are out of scope for the present document. See [10], [16], [12], [13], [14] and [15] for
     * details:
     *
     * @param params
     * @param processNode
     * @return
     */
    public boolean run(final ProcessParameters params, final XmlNode processNode) {

        if (processNode == null) {

            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "processNode"));
        }
        prepareParameters(params);

        /**
         * 5.4 Cryptographic Verification (CV)
         */
        subProcessNode = processNode.addChild(CV);
        final XmlNode conclusionNode = new XmlNode(CONCLUSION);

        final boolean valid = process(params, conclusionNode);
        if (valid) {

            conclusionNode.addChild(INDICATION, VALID);
            conclusionNode.setParent(subProcessNode);

            conclusion.setIndication(VALID);
        } else {

            conclusionNode.addChild(INDICATION, conclusion.getIndication());
            conclusionNode.addChild(SUB_INDICATION, conclusion.getSubIndication());

            subProcessNode.addChild(conclusionNode);
            processNode.addChild(conclusionNode);
        }

        return valid;
    }

    /**
     * 5.4.4 Processing<br>
     * The first and second steps as well as the Data To Be Signed depend on the signature type. The technical details on
     * how to do this correctly are out of scope for the present document. See [10], [16], [12], [13], [14] and [15] for
     * details:
     *
     * @param params
     * @param conclusionNode
     * @return
     */
    private boolean process(final ProcessParameters params, final XmlNode conclusionNode) {

        /**
         * 1) Obtain the signed data objects(s) if not provided in the inputs (e.g. by dereferencing an URI present in the
         * signature). If the signed data object (s) cannot be obtained, abort with the indication
         * INDETERMINATE/SIGNED_DATA_NOT_FOUND.
         */

        XmlNode constraintNode = addConstraint(BBB_CV_IRDOF_LABEL, BBB_CV_IRDOF);

        final boolean referenceDataFound = contextElement.getBoolValue("./ReferenceDataFound/text()");

        if (!referenceDataFound) {

            constraintNode.addChild(STATUS, KO);

            conclusion.setIndication(INDETERMINATE, SIGNED_DATA_NOT_FOUND);
            return false;
        }
        constraintNode.addChild(STATUS, OK);

        /**
         * 2) Check the integrity of the signed data objects. In case of failure, abort the signature validation process
         * with INVALID/HASH_FAILURE.
         */
        constraintNode = addConstraint(BBB_CV_IRDOI_LABEL, BBB_CV_IRDOI);

        final boolean referenceDataIntact = contextElement.getBoolValue("./ReferenceDataIntact/text()");

        if (!referenceDataIntact) {

            constraintNode.addChild(STATUS, KO);

            conclusion.setIndication(INVALID, HASH_FAILURE);
            return false;
        }
        constraintNode.addChild(STATUS, OK);

        /**
         * 3) Verify the cryptographic signature using the public key extracted from the signer's certificate in the
         * chain, the signature value and the signature algorithm extracted from the signature. If this cryptographic
         * verification outputs a success indication, terminate with VALID. Otherwise, terminate with
         * INVALID/SIG_CRYPTO_FAILURE.
         */

        constraintNode = addConstraint(BBB_CV_ISI_LABEL, BBB_CV_ISI);

        final boolean signatureIntact = contextElement.getBoolValue("./SignatureIntact/text()");

        if (!signatureIntact) {

            constraintNode.addChild(STATUS, KO);

            conclusion.setIndication(INVALID, SIG_CRYPTO_FAILURE);
            return false;
        }
        constraintNode.addChild(STATUS, OK);

        return true;
    }

    public Conclusion getConclusion() {

        return conclusion;
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
