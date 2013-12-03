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
package eu.europa.ec.markt.dss.validation102853;

import java.util.Date;
import java.util.logging.Logger;

import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlDom;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlNode;
import eu.europa.ec.markt.dss.validation102853.engine.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.engine.rules.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.AdESTValidation;
import eu.europa.ec.markt.dss.validation102853.engine.rules.processes.LongTermValidation;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.VConstraint;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReportBuilder;
import eu.europa.ec.markt.dss.validation102853.report.ValidationReport;

/**
 * @author bielecro
 */
public class ProcessExecutor {

    protected static final Logger LOG = Logger.getLogger(SignedDocumentValidator.class.getName());

    public enum SignatureType {
        QES, AdES, AdESqc, NA
    }

    /**
     * DOM representation of the diagnostic data.
     */
    protected Document diagnosticData;

    protected XmlDom diagnosticDataXmlDom;

    /**
     * Validation policy constraint data DOM representation
     */
    protected Document policyData;

    /**
     * Wrapper for the validation policy constraints
     */
    protected VConstraint constraintData;

    protected ProcessParameters processParams;

    /**
     * The simple validation report, contains only the most important information like validation date, signer from DN,
     * indication, sub-indication...
     */
    protected SimpleReport simpleReport;

    /**
     * The detailed report contains all information collected during the validation process.
     */
    protected ValidationReport fullReport;

    /**
     * See {@link ProcessParameters#getCurrentTime()} TODO The management of the currentTime must be updated between
     * different processes!
     */
    protected Date currentTime = new Date();

    /**
     * This constructor instantiates the validation process with the given diagnostic data file and the policy file. It
     * is used for tests.
     *
     * @param diagnosticData
     * @param policyData
     */
    public ProcessExecutor(final Document diagnosticData, final Document policyData) {

        if (diagnosticData == null) {

            throw new DSSException("The diagnostic data is null!");
        }
        this.diagnosticData = diagnosticData;
        this.policyData = policyData; // Policy data can be null (no policy)
    }

    /**
     * The constructor with only diagnostic data.
     */
    public ProcessExecutor(final Document diagnosticData) {

        this(diagnosticData, null);
    }

    /**
     * This method executes the AdES-T validation process. The underlying processes are automatically executed.
     */
    public XmlDom executeAdEST() {

        final ProcessParameters params = new ProcessParameters();
        params.setDiagnosticData(new XmlDom(diagnosticData));
        params.setConstraintData(new VConstraint(policyData));
        params.setCurrentTime(currentTime);

        /**
         * This executes the AdES-T Validation process. It creates the AdES-T validation data.
         */
        final XmlNode mainNode = new XmlNode(NodeName.VALIDATION_DATA);
        mainNode.setNameSpace(ValidationResourceManager.DIAGNOSTIC_DATA_NAMESPACE);

        final AdESTValidation timeStampValidation = new AdESTValidation();
        XmlDom adestDom = timeStampValidation.run(mainNode, params);
        return adestDom;
    }

    /**
     * This method executes the long term validation processes. The underlying processes are automatically executed.
     */
    public ValidationReport execute() {

        processParams = new ProcessParameters();
        diagnosticDataXmlDom = new XmlDom(diagnosticData);
        processParams.setDiagnosticData(diagnosticDataXmlDom);
        constraintData = new VConstraint(policyData);
        processParams.setConstraintData(constraintData);
        processParams.setCurrentTime(currentTime);
        final XmlDom usedCertificates = diagnosticDataXmlDom.getElement("/DiagnosticData/UsedCertificates");
        processParams.setCertPool(usedCertificates);

        final XmlNode mainNode = new XmlNode(NodeName.VALIDATION_DATA);
        mainNode.setNameSpace(ValidationResourceManager.DIAGNOSTIC_DATA_NAMESPACE);

        final LongTermValidation ltv = new LongTermValidation();
        ltv.run(mainNode, processParams);

        final Document validationReportDocument = ValidationResourceManager.xmlNodeIntoDom(mainNode);
        fullReport = new ValidationReport(validationReportDocument);

        final SimpleReportBuilder simpleReportBuilder = new SimpleReportBuilder(constraintData, diagnosticDataXmlDom);
        simpleReport = simpleReportBuilder.build(processParams);
        return fullReport;
    }

    /**
     * Returns the diagnostic data associated to the process.
     *
     * @return
     */
    public Document getDiagnosticData() {
        return diagnosticData;
    }

    /**
     * Returns the constraints associated to the process.
     *
     * @return
     */
    public Document getPolicyData() {
        return policyData;
    }

    /**
     * Returns the time of the validation.
     *
     * @return
     */
    public Date getCurrentTime() {
        return currentTime;
    }

    /**
     * Returns the simple report. This is the simplest representation of the validation result.
     *
     * @return
     */
    public SimpleReport getSimpleReport() {

        return simpleReport;
    }

    /**
     * Returns the simple report. This is the simplest representation of the validation result.
     *
     * @return
     */
    public XmlDom getFullReport() {

        return fullReport;
    }
}
