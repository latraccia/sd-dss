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
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlNode;
import eu.europa.ec.markt.dss.validation102853.engine.rules.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.engine.rules.RuleUtils;

/**
 * This class verifies the cryptographic constraints for a given certificate.
 *
 * @author bielecro
 */
public class RevocationCryptographicConstraint extends CryptographicConstraint {

    /**
     * @param params
     */
    protected void prepareParameters(ProcessParameters params) {

        this.constraintData = params.getConstraintData();
        this.currentTime = params.getCurrentTime();
        this.contextElement = params.getContextElement();
        isInitialised();
    }

    /**
     *
     */
    private void isInitialised() {

        if (constraintData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "policyData"));
        }
        if (currentTime == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "currentTime"));
        }
    }

    /**
     * @param infoContainerNode
     * @return
     */
    protected boolean process(XmlNode infoContainerNode) {

        contextName = OCSP_CERTIFICATE;
        String source = contextElement.getValue("./Source/text()");
        if ("CRLToken".equals(source)) {

            contextName = CRL_CERTIFICATE;
        }
        String encryptionAlgo = contextElement.getValue("./EncryptionAlgoUsedToSignThisToken/text()");
        encryptionAlgo = RuleUtils.canonicalizeEncryptionAlgo(encryptionAlgo);

        boolean acceptableEncryptionAlgo = constraintData.isAcceptableEncryptionAlgo(contextName, encryptionAlgo);

        if (!acceptableEncryptionAlgo) {

            String attribute = String.format("/ConstraintsParameters/Cryptographic/%s/AcceptableEncryptionAlgo/Algo", contextName);
            XmlNode infoNode = infoContainerNode.addChild(INFO, encryptionAlgo);
            infoNode.setAttribute(FIELD, attribute);
            return false;
        }

        String digestAlgo = contextElement.getValue("./DigestAlgoUsedToSignThisToken/text()");
        digestAlgo = RuleUtils.canonicalizeDigestAlgo(digestAlgo);

        boolean acceptableDigestAlgo = constraintData.isAcceptableDigestAlgo(contextName, digestAlgo);
        if (!acceptableDigestAlgo) {

            String attribute = String.format("/ConstraintsParameters/Cryptographic/%s/AcceptableDigestAlgo/Algo", contextName);
            XmlNode infoNode = infoContainerNode.addChild(INFO, digestAlgo);
            infoNode.setAttribute(FIELD, attribute);
            return false;
        }

        boolean algorithmExpired = isAlgorithmExpired(digestAlgo, infoContainerNode);
        if (algorithmExpired) {

            return false;
        }
        final String encryptionKeyLength = contextElement.getValue("./KeyLengthUsedToSignThisToken/text()");
        final String encryptionAlgoAndKey = encryptionAlgo + encryptionKeyLength;
        algorithmExpired = isAlgorithmExpired(encryptionAlgoAndKey, infoContainerNode);
        if (algorithmExpired) {

            return false;
        }
        return true;
    }
}
