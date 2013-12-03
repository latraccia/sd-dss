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

import java.util.List;
import java.util.logging.Logger;

import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.ValidationResourceManager;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlDom;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlNode;
import eu.europa.ec.markt.dss.validation102853.engine.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.engine.rules.ExceptionMessage;
import eu.europa.ec.markt.dss.validation102853.engine.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.engine.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.engine.rules.NodeValue;
import eu.europa.ec.markt.dss.validation102853.engine.rules.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses.CryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses.IdentificationOfTheSignersCertificate;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses.SignatureAcceptanceValidation;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses.ValidationContextInitialisation;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses.X509CertificateValidation;

/**
 * This class creates the validation data (Basic Building Blocks) for all signatures.
 *
 * 5. Basic Building Blocks<br>
 * This clause presents basic building blocks that are useable in the signature validation process. Later clauses will
 * use these blocks to construct validation algorithms for specific scenarios.
 *
 * @author bielecro
 */
public class BasicBuildingBlocks implements NodeName, NodeValue, AttributeName, Indication, ExceptionMessage {

    private static final Logger LOG = Logger.getLogger(BasicBuildingBlocks.class.getName());

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
     * This method lunches the construction process of basic building blocks.
     *
     * @param params
     * @return
     */
    public XmlDom run(final XmlNode mainNode, final ProcessParameters params) {

        prepareParameters(params);
        LOG.fine(this.getClass().getSimpleName() + ": start.");

        params.setContextName(SIGNING_CERTIFICATE);

        final XmlNode basicBuildingBlocksNode = mainNode.addChild(BASIC_BUILDING_BLOCKS);

        final List<XmlDom> signatures = diagnosticData.getElements("/DiagnosticData/Signature");

        for (final XmlDom signature : signatures) {

            params.setSignatureContext(signature);
            /**
             * In this case signatureContext and contextElement are equal, but this is not the case for
             * TimestampsBasicBuildingBlocks
             */
            params.setContextElement(signature);

            /**
             * 5. Basic Building Blocks
             */

            final String signatureId = signature.getValue("./@Id");
            final XmlNode signatureNode = basicBuildingBlocksNode.addChild(SIGNATURE);
            signatureNode.setAttribute(ID, signatureId);
            /**
             * 5.1. Identification of the signer's certificate (ISC)
             */
            final IdentificationOfTheSignersCertificate isc = new IdentificationOfTheSignersCertificate();
            final boolean iscValid = isc.run(params, signatureNode);
            if (!iscValid) {

                continue;
            }

            /**
             * 5.2. Validation Context Initialisation (VCI)
             */
            final ValidationContextInitialisation vci = new ValidationContextInitialisation();
            final boolean vciValid = vci.run(params, signatureNode);
            if (!vciValid) {

                continue;
            }

            /**
             * 5.4 Cryptographic Verification (CV)
             * --> We check the CV before XCV to not repeat the same check with LTV if XCV is not conclusive.
             */
            final CryptographicVerification cv = new CryptographicVerification();
            final boolean cvValid = cv.run(params, signatureNode);
            if (!cvValid) {

                continue;
            }

            /**
             * 5.5 Signature Acceptance Validation (SAV)
             * --> We check the SAV before XCV to not repeat the same check with LTV if XCV is not conclusive.
             */
            final SignatureAcceptanceValidation sav = new SignatureAcceptanceValidation();
            final boolean savValid = sav.run(params, signatureNode);
            if (!savValid) {

                continue;
            }

            /**
             * 5.3 X.509 Certificate Validation (XCV)
             */
            final X509CertificateValidation xcv = new X509CertificateValidation();
            final boolean xcvValid = xcv.run(params, signatureNode);
            if (!xcvValid) {

                continue;
            }

            final XmlNode conclusionNode = signatureNode.addChild(CONCLUSION);
            conclusionNode.addChild(INDICATION, VALID);
        }
        if (ProcessParameters.isLoggingEnabled()) {

            System.out.println("");
            System.out.println(basicBuildingBlocksNode);
        }
        final Document bbbDocument = ValidationResourceManager.xmlNodeIntoDom(basicBuildingBlocksNode);
        final XmlDom bbbDom = new XmlDom(bbbDocument);
        params.setBBBData(bbbDom);
        return bbbDom;
    }
}
