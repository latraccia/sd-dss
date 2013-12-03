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

import java.util.Date;

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
import eu.europa.ec.markt.dss.validation102853.engine.rules.RuleUtils;
import eu.europa.ec.markt.dss.validation102853.engine.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.VConstraint;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
abstract class CryptographicConstraint implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage, RuleConstant {

    /**
     * The following variables are used only in order to simplify the writing of the rules!
     */

    /**
     * See {@link eu.europa.ec.markt.dss.validation102853.engine.rules.ProcessParameters#getConstraintData()}
     */
    protected VConstraint constraintData;

    /**
     * See {@link eu.europa.ec.markt.dss.validation102853.engine.rules.ProcessParameters#getCurrentTime()}
     */
    protected Date currentTime;

    /**
     * See {@link eu.europa.ec.markt.dss.validation102853.engine.rules.ProcessParameters#getContextName()}
     */
    protected String contextName;

    /**
     * See {@link ProcessParameters#getContextElement()}
     */
    protected XmlDom contextElement;

    protected abstract void prepareParameters(ProcessParameters params);

    protected abstract boolean process(XmlNode infoContainerNode);

    /**
     * The entry point to carry out the cryptographic constraints validation.
     *
     * @param params
     * @param infoContainerNode
     * @return
     */
    public boolean run(ProcessParameters params, XmlNode infoContainerNode) {

        if (infoContainerNode == null) {

            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "Info"));
        }
        prepareParameters(params);

        boolean valid = process(infoContainerNode);

        return valid;
    }

    protected boolean isAlgorithmExpired(final String algorithm, final XmlNode infoContainerNode) {

        try {

            final Date algoExpirationDate = constraintData.getAlgorithmExpirationDate(algorithm);
            if (algoExpirationDate != null && algoExpirationDate.before(currentTime)) {

                final String attribute = String.format("/ConstraintsParameters/Cryptographic/AlgoExpirationDate/Algo[@Name=\"%s\"]", algorithm);
                final String expirationDateString = RuleUtils.formatDate(RuleUtils.SDF_DATE, algoExpirationDate);
                final XmlNode infoNode = infoContainerNode.addChild(INFO, expirationDateString);
                infoNode.setAttribute(CONTEXT, contextName);
                infoNode.setAttribute(FIELD, attribute);
                return true;
            }
        } catch (DSSException e) {

            final String attribute = String.format("/ConstraintsParameters/Cryptographic/AlgoExpirationDate/Algo[@Name=\"%s\"]", algorithm);
            final XmlNode infoNode = infoContainerNode.addChild(INFO, ALGORITHM_NOT_FOUND);
            infoNode.setAttribute(CONTEXT, contextName);
            infoNode.setAttribute(FIELD, attribute);
            return true;
        }
        return false;
    }
}
