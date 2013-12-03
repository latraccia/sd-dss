package eu.europa.ec.markt.dss.applet.model;

import java.io.File;

import org.apache.commons.lang.builder.ReflectionToStringBuilder;

import com.jgoodies.binding.beans.Model;
import eu.europa.ec.markt.dss.validation.report.ValidationReport;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlDom;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
@SuppressWarnings("serial")
public class ValidationModel extends Model {
    /**
     *
     */
    public static final String CHANGE_PROPERTY_SIGNED_FILE = "signedFile";
    private File signedFile;
    /**
     *
     */
    public static final String CHANGE_PROPERTY_ORIGINAL_FILE = "originalFile";
    private File originalFile;

    public static final String CHANGE_PROPERTY_VALIDATION_LEGACY_CHOOSEN = "validationLegacyChoosen";

    private boolean validationLegacyChoosen = false;

    public static final String CHANGE_PROPERTY_DEAFULT_102853_POLICY = "default102853Policy";
    private boolean default102853Policy = true;

    public static final String CHANGE_PROPERTY_SELECTED_POLICY_FILE = "selectedPolicyFile";
    private File selectedPolicyFile;

    private ValidationReport validationReport;

    public static final String CHANGE_PROPERTY_VALIDATION_102853_REPORT = "validation102853Report";
    private eu.europa.ec.markt.dss.validation102853.report.ValidationReport validation102853Report;

    public static final String CHANGE_PROPERTY_DIAGNOSTIC_DATA_102853 = "diagnosticData102853";
    private DiagnosticData diagnosticData102853;

    public static final String CHANGE_PROPERTY_SIMPLE_REPORT_102853 = "simpleReport102853";
    private SimpleReport simpleReport102853;

    /**
     * @return the originalFile
     */
    public File getOriginalFile() {
        return originalFile;
    }

    /**
     * @return the signedFile
     */
    public File getSignedFile() {
        return signedFile;
    }

    /**
     * @return the validationReport
     */
    public ValidationReport getValidationReport() {
        return validationReport;

    }

    /**
     * @param originalFile the originalFile to set
     */
    public void setOriginalFile(final File originalFile) {
        final File oldValue = this.originalFile;
        final File newValue = originalFile;
        this.originalFile = newValue;
        firePropertyChange(CHANGE_PROPERTY_ORIGINAL_FILE, oldValue, newValue);
    }

    /**
     * @param signedFile the signedFile to set
     */
    public void setSignedFile(final File signedFile) {
        final File oldValue = this.signedFile;
        final File newValue = signedFile;
        this.signedFile = newValue;
        firePropertyChange(CHANGE_PROPERTY_SIGNED_FILE, oldValue, newValue);
    }

    /**
     * @param validationReport the validationReport to set
     */
    public void setValidationReport(final ValidationReport validationReport) {
        this.validationReport = validationReport;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return ReflectionToStringBuilder.reflectionToString(this);
    }

    public boolean isValidationLegacyChoosen() {
        return validationLegacyChoosen;
    }


    /**
     * @param validationLegacyChoosen the validationLegacyChoosen to set
     */
    public void setValidationLegacyChoosen(final boolean validationLegacyChoosen) {
        final boolean oldValue = this.validationLegacyChoosen;
        final boolean newValue = validationLegacyChoosen;
        this.validationLegacyChoosen = newValue;
        firePropertyChange(CHANGE_PROPERTY_VALIDATION_LEGACY_CHOOSEN, oldValue, newValue);
    }

    public boolean isDefault102853Policy() {
        return default102853Policy;
    }

    public void setDefault102853Policy(boolean default102853Policy) {
        final boolean oldValue = this.default102853Policy;
        final boolean newValue = default102853Policy;
        this.default102853Policy = newValue;
        firePropertyChange(CHANGE_PROPERTY_DEAFULT_102853_POLICY, oldValue, newValue);
    }

    public File getSelectedPolicyFile() {
        return selectedPolicyFile;
    }

    public void setSelectedPolicyFile(File selectedPolicyFile) {
        final File oldValue = this.selectedPolicyFile;
        final File newValue = selectedPolicyFile;
        this.selectedPolicyFile = newValue;
        firePropertyChange(CHANGE_PROPERTY_SELECTED_POLICY_FILE, oldValue, newValue);
    }

    public eu.europa.ec.markt.dss.validation102853.report.ValidationReport getValidation102853Report() {
        return validation102853Report;
    }

    public void setValidation102853Report(eu.europa.ec.markt.dss.validation102853.report.ValidationReport validation102853Report) {
        final eu.europa.ec.markt.dss.validation102853.report.ValidationReport oldValue = this.validation102853Report;
        final eu.europa.ec.markt.dss.validation102853.report.ValidationReport newValue = validation102853Report;
        this.validation102853Report = validation102853Report;
        firePropertyChange(CHANGE_PROPERTY_VALIDATION_102853_REPORT, oldValue, newValue);
    }

    public void setDiagnosticData102853(DiagnosticData diagnosticData102853) {
        final DiagnosticData oldValue = this.diagnosticData102853;
        final DiagnosticData newValue = diagnosticData102853;
        this.diagnosticData102853 = diagnosticData102853;
        firePropertyChange(CHANGE_PROPERTY_DIAGNOSTIC_DATA_102853, oldValue, newValue);
    }

    public DiagnosticData getDiagnosticData102853() {
        return diagnosticData102853;
    }

    public SimpleReport getSimpleReport102853() {
        return simpleReport102853;
    }

    public void setSimpleReport102853(SimpleReport simpleReport102853) {
        final SimpleReport oldValue = this.simpleReport102853;
        final SimpleReport newValue = simpleReport102853;
        this.simpleReport102853 = simpleReport102853;
        firePropertyChange(CHANGE_PROPERTY_SIMPLE_REPORT_102853, oldValue, newValue);
    }
}


