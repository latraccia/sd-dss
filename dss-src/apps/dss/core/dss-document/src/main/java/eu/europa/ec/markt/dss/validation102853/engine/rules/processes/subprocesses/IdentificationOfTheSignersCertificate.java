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

public class IdentificationOfTheSignersCertificate implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage {

    /**
     * The following variables are used only in order to simplify the writing of the rules!
     */

    /**
     * See {@link ProcessParameters#getDiagnosticData()}
     */
    private XmlDom diagnosticData;

    /**
     * See {@link ProcessParameters#getContextElement()}
     */
    private XmlDom contextElement;

    /**
     * This node is used to add the constraint nodes.
     */
    private XmlNode subProcessNode;

    private void prepareParameters(final ProcessParameters params) {

        this.diagnosticData = params.getDiagnosticData();
        this.contextElement = params.getContextElement();

        isInitialised();
    }

    private void isInitialised() {

        if (diagnosticData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "diagnosticData"));
        }
        if (contextElement == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "contextElement"));
        }
    }

    /**
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
         * 5.1 Identification of the signer's certificate (ISC)
         */

        subProcessNode = processNode.addChild(ISC);
        final XmlNode conclusionNode = new XmlNode(CONCLUSION);

        final boolean valid = process(params, conclusionNode);

        if (valid) {

            // The signing certificate Id and the signing certificate were saved for further use.

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
         * 5.1.4 Processing
         */

        /**
         * The signing certificate Id and the signing certificate are reseted.
         */
        params.setSignCertId(null);
        params.setSignCert(null);

        XmlNode constraintNode = addConstraint(BBB_ICS_ISCI_LABEL, BBB_ICS_ISCI);

        final String signCertId = contextElement.getValue("./SigningCertificate/@Id");
        final XmlDom signCert = params.getCertificate(signCertId);

        if (signCert != null) {

            constraintNode.addChild(STATUS, OK);
            constraintNode.addChild(INFO, signCertId).setAttribute(FIELD, SIGNING_CERTIFICATE);
        } else {

            constraintNode.addChild(STATUS, KO);
            conclusionNode.addChild(INDICATION, INDETERMINATE);
            conclusionNode.addChild(SUB_INDICATION, NO_SIGNER_CERTIFICATE_FOUND);
            return false;
        }

        /**
         * 5.1.4.1 XAdES processing / 5.1.4.2 CAdES processing / 5.1.4.3 PAdES processing<br>
         *
         * For XAdES:<br>
         * The signing certificate shall be checked against all references present in the ds:SigningCertificate property,
         * if present, since one of these references shall be a reference to the signing certificate [1]. The following
         * steps shall be performed:
         *
         * 1) Take the first child of the property and check that the content of ds:DigestValue matches the result of
         * digesting the signing certificate with the algorithm indicated in ds:DigestMethod. If they do not match, take
         * the next child and repeat this step until a matching child element has been found or all children of the
         * element have been checked. If they do match, continue with step 2. If the last element is reached without
         * finding any match, the validation of this property shall be taken as failed and INVALID/FORMAT_FAILURE is
         * returned.
         */
        constraintNode = addConstraint(BBB_ICS_ICDVV_LABEL, BBB_ICS_ICDVV);

        final boolean digestValueMatch = contextElement.getBoolValue("./SigningCertificate/DigestValueMatch/text()");
        if (!digestValueMatch) {

            constraintNode.addChild(STATUS, KO);
            conclusionNode.addChild(INDICATION, INVALID);
            conclusionNode.addChild(SUB_INDICATION, FORMAT_FAILURE);
            return false;
        }
        constraintNode.addChild(STATUS, OK);

        /**
         * 2) If the ds:KeyInfo contains the ds:X509IssuerSerial element, check that the issuer and the serial number
         * indicated in that element and IssuerSerial from SigningCertificate are the same. If they do not match, the
         * validation of this property shall be taken as failed and INDETERMINATE is returned.
         */
        constraintNode = addConstraint(BBB_ICS_IIASNE_LABEL, BBB_ICS_IIASNE);

        final boolean issuerSerialMatch = contextElement.getBoolValue("./SigningCertificate/IssuerSerialMatch/text()");
        if (!issuerSerialMatch) {

            constraintNode.addChild(STATUS, KO);
            conclusionNode.addChild(INDICATION, INDETERMINATE);
            conclusionNode.addChild(SUB_INDICATION, NO_SIGNER_CERTIFICATE_FOUND);
            conclusionNode.addChild(INFO, BBB_ICS_INFO_IIASNE_LABEL);
            return false;
        }
        constraintNode.addChild(STATUS, OK);

        /**
         * The signing certificate Id and the signing certificate are saved for further use.
         */
        params.setSignCertId(signCertId);
        params.setSignCert(signCert);

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
