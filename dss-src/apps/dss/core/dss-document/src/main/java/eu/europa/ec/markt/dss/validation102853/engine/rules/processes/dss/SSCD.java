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

package eu.europa.ec.markt.dss.validation102853.engine.rules.processes.dss;

import java.util.List;

import eu.europa.ec.markt.dss.validation102853.engine.function.XmlDom;
import eu.europa.ec.markt.dss.validation102853.engine.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.engine.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.engine.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.engine.rules.NodeValue;
import eu.europa.ec.markt.dss.validation102853.engine.rules.RuleConstant;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.VConstraint;

/**
 * This class checks if the signing cert is mandated to be supported by SSCD device.
 *
 * @author bielecro
 */
public class SSCD implements NodeName, NodeValue, AttributeName, AttributeValue, RuleConstant {

    private VConstraint constraintData;

    /**
     * The default constructor with the policy object.
     *
     * @param constraintData
     */
    public SSCD(final VConstraint constraintData) {

        super();
        this.constraintData = constraintData;
    }

    /**
     * The SSCD constraint is to be applied to the signer's cert of the main signature or timestamp before
     * considering it as valid for the intended use.
     *
     * @param isTimestamp indicates if this is a timestamp signing cert or main signature signing cert.
     * @param cert        the cert to be processed
     * @return
     */
    public Boolean run(final boolean isTimestamp, final XmlDom cert) {

        final String context = isTimestamp ? TIMESTAMP_SIGNING_CERTIFICATE : SIGNING_CERTIFICATE;
        final boolean mustBeSSCDCertificate = constraintData.mustBeSSCDCertificate(context);
        if (mustBeSSCDCertificate) {

            return process(cert);
        }
        return null;
    }

    /**
     * Generalised implementation independent of the context (SigningCertificate or TimestampSigningCertificate).
     *
     * @param cert the cert to be processed
     * @return
     */
    private boolean process(final XmlDom cert) {

        /**
         * Mandates the end user cert used in validating the signature to be supported by a secure signature
         * creation device (SSCD) as defined in Directive 1999/93/EC [9].
         *
         * This status is derived from: • QcSSCD extension being set in the signer's cert in accordance with ETSI
         * TS 101 862 [5];
         */

        final boolean qcSSCD = cert.getBoolValue("./QCStatement/QCSSCD/text()");

        /**
         * • QCP+ cert policy OID being indicated in the signer's cert policies extension (i.e.
         * 0.4.0.1456.1.1);
         */

        final boolean qcpPlus = cert.getBoolValue("./QCStatement/QCPPlus/text()");

        /**
         * • The content of a Trusted service Status List;<br>
         * • The content of a Trusted List through information provided in the Sie field of the applicable service entry;
         * or
         */

        final List<String> qualifiers = InvolvedServiceInfo.getQualifiers(cert);

        final boolean sie = qualifiers.contains(QC_WITH_SSCD) || qualifiers.contains(QCSSCD_STATUS_AS_IN_CERT) || qualifiers
              .contains(QC_FOR_LEGAL_PERSON);

        /**
         * • Static configuration that provides such information in a trusted manner.
         */
        // --> Not implemented

        if (!(qcSSCD || qcpPlus || sie)) {

            return false;
        }
        return true;
    }
}
