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

package eu.europa.ec.markt.dss.validation102853.engine.rules;

import java.util.Date;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlDom;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.AdESTValidation;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.BasicBuildingBlocks;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.BasicValidation;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.LongTermValidation;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.TimestampValidation;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.ltv.POEExtraction;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses.IdentificationOfTheSignersCertificate;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses.ValidationContextInitialisation;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.VConstraint;

/**
 * This class stores the references to data exchanged and manipulated by different sub validation processes.
 *
 * @author bielecro
 */
public class ProcessParameters {

    // Logging the result of the validation process on the System.out.
    private static boolean loggingEnabled = false;

    /**
     * This variable contains the diagnostic data which is used to carry out all validation processes. It is extracted
     * from the signature(s) being validated. This data is independent of the form of source signature (PDF, XAdES,
     * PAdES, ASiC).
     */
    protected XmlDom diagnosticData;

    /**
     * This is the policy data to be used by the validation process. This data are not mandatory but in this case the
     * {@link ValidationContextInitialisation} sub process will fail.
     */
    protected VConstraint constraintData;

    /**
     * This is the current time against which the validation process is carried out.
     */
    protected Date currentTime;

    /**
     * This variable contains the Signing Certificate Id. It is initialised by
     * {@link IdentificationOfTheSignersCertificate} sub process.
     */
    private String signCertId;

    /**
     * This variable contains the Signing Certificate Node from diagnostic data. It is initialised by
     * {@link IdentificationOfTheSignersCertificate} sub process.
     */
    private XmlDom signCert;

    /**
     * Represents the current main signature DOM element being validated. This element provides general information used
     * in validation process like the list of used certificates.
     */
    protected XmlDom signatureContext;

    /**
     * Represents the current signature DOM element being validated:<br>
     * in the case of main signature validation <code>contextElement</code> is the signature element being validated;<br>
     * in case of Timestamp signature validation <code>contextElement</code> is the timestamp element being validated.
     */
    protected XmlDom contextElement;

    /**
     * Indicates the current constraint element like: SignatureToValidate, SigningCertificate...
     */
    protected String contextName;

    /**
     * This <code>XmlDom</code> is returned by the Basic Building Blocks process (see {@link BasicBuildingBlocks}).
     */
    private XmlDom bbbData;

    /**
     * This <code>XmlDom</code> is returned by the Basic Validation process (see {@link BasicValidation}).
     */
    private XmlDom bvData;

    /**
     * This <code>XmlDom</code> is returned by the Basic Timestamp Validation process (see {@link TimestampValidation}).
     */
    private XmlDom tsData;

    /**
     * This <code>XmlDom</code> is returned by the AdEST Validation process (see {@link AdESTValidation}).
     */
    private XmlDom adestData;

    /**
     * This <code>XmlDom</code> is returned by the Long Term Validation process (see {@link LongTermValidation}).
     */
    private XmlDom ltvData;

    private XmlDom certPool;

    private POEExtraction poe;

    public static boolean isLoggingEnabled() {
        return loggingEnabled;
    }

    public static void setLoggingEnabled(final boolean loggingEnabled) {
        ProcessParameters.loggingEnabled = loggingEnabled;
    }

    /**
     * See {@link #diagnosticData}
     *
     * @return
     */
    public XmlDom getDiagnosticData() {
        return diagnosticData;
    }

    /**
     * See {@link #diagnosticData}
     *
     * @return
     */
    public void setDiagnosticData(final XmlDom diagnosticData) {
        this.diagnosticData = diagnosticData;
    }

    /**
     * See {@link #constraintData}
     *
     * @return
     */
    public VConstraint getConstraintData() {
        return constraintData;
    }

    /**
     * See {@link #constraintData}
     *
     * @return
     */
    public void setConstraintData(final VConstraint constraintData) {
        this.constraintData = constraintData;
    }

    /**
     * See {@link #signCertId}
     *
     * @return
     */
    public String getSignCertId() {
        return signCertId;
    }

    /**
     * See {@link #signCertId}
     *
     * @return
     */
    public void setSignCertId(final String signCertId) {
        this.signCertId = signCertId;
    }

    /**
     * See {@link #signCert}
     *
     * @return
     */
    public XmlDom getSignCert() {
        return signCert;
    }

    /**
     * See {@link #signCert}
     *
     * @return
     */
    public void setSignCert(final XmlDom signCert) {
        this.signCert = signCert;
    }

    /**
     * See {@link #bbbData}
     *
     * @return
     */
    public XmlDom getBBBData() {
        return bbbData;
    }

    /**
     * See {@link #bbbData}
     *
     * @return
     */
    public void setBBBData(final XmlDom bbbData) {
        this.bbbData = bbbData;
    }

    /**
     * See {@link #bvData}
     *
     * @return
     */
    public XmlDom getBvData() {
        return bvData;
    }

    /**
     * See {@link #bvData}
     *
     * @return
     */
    public void setBvData(XmlDom bvData) {
        this.bvData = bvData;
    }

    /**
     * See {@link #tsData}
     *
     * @return
     */
    public XmlDom getTsData() {
        return tsData;
    }

    /**
     * See {@link #tsData}
     *
     * @return
     */
    public void setTsData(XmlDom tsData) {
        this.tsData = tsData;
    }

    /**
     * See {@link #adestData}
     *
     * @return
     */

    public XmlDom getAdestData() {
        return adestData;
    }

    /**
     * See {@link #adestData}
     *
     * @return
     */
    public void setAdestData(XmlDom adestData) {
        this.adestData = adestData;
    }

    /**
     * See {@link #ltvData}
     *
     * @return
     */

    public XmlDom getLtvData() {
        return ltvData;
    }

    /**
     * See {@link #ltvData}
     *
     * @return
     */
    public void setLtvData(XmlDom ltvData) {
        this.ltvData = ltvData;
    }

    /**
     * See {@link #currentTime}
     *
     * @return
     */
    public Date getCurrentTime() {
        return currentTime;
    }

    /**
     * See {@link #currentTime}
     *
     * @return
     */
    public void setCurrentTime(final Date currentTime) {
        if (this.currentTime != null) {

            throw new DSSException("The current-time variable should be initialised only once!");
        }
        this.currentTime = currentTime;
    }

    /**
     * See {@link #signatureContext}
     *
     * @return
     */
    public XmlDom getSignatureContext() {
        return signatureContext;
    }

    /**
     * See {@link #signatureContext}
     *
     * @param signature
     */
    public void setSignatureContext(final XmlDom signature) {
        this.signatureContext = signature;
    }

    /**
     * See {@link #contextElement}
     *
     * @return
     */
    public XmlDom getContextElement() {
        return contextElement;
    }

    /**
     * See {@link #contextElement}
     *
     * @param contextElement
     */
    public void setContextElement(final XmlDom contextElement) {
        this.contextElement = contextElement;
    }

    /**
     * See {@link #contextElement}
     *
     * @return
     */
    public String getContextName() {
        return contextName;
    }

    /**
     * See {@link #contextElement}
     *
     * @param constraintElement
     */
    public void setContextName(final String constraintElement) {
        this.contextName = constraintElement;
    }

    /**
     * Returns the XmlDom object representing the pool of the certificates used in the validation process.
     *
     * @return
     */
    public XmlDom getCertPool() {
        return certPool;
    }

    public void setCertPool(final XmlDom certPool) {
        this.certPool = certPool;
    }

    /**
     * Returns the XmlDom representing the corresponding certificate or null.
     *
     * @param id
     * @return
     */

    public XmlDom getCertificate(int id) {

        return getCertificate(String.valueOf(id));
    }

    /**
     * Returns the XmlDom representing the corresponding certificate or null.
     *
     * @param id
     * @return
     */

    public XmlDom getCertificate(String id) {

        return certPool == null ? certPool : certPool.getElement("./Certificate[@Id='%s']", id);
    }

    public POEExtraction getPOE() {
        return poe;
    }

    public void setPOE(POEExtraction poe) {
        this.poe = poe;
    }

    @Override
    public String toString() {

        try {

            StringBuilder builder = new StringBuilder();
            builder.append("currentTime: ").append(currentTime).append("\n");
            builder.append("signCertId: ").append(signCertId).append("\n");
            builder.append("contextName: ").append(contextName).append("\n");

            return builder.toString();
        } catch (Exception e) {

            return super.toString();
        }
    }
}
