package eu.europa.ec.markt.dss.applet.wizard.validation;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;

import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.CertificateIdentifier;
import eu.europa.ec.markt.dss.applet.controller.ActivityController;
import eu.europa.ec.markt.dss.applet.controller.DSSWizardController;
import eu.europa.ec.markt.dss.applet.main.DSSAppletCore;
import eu.europa.ec.markt.dss.applet.main.Parameters;
import eu.europa.ec.markt.dss.applet.model.ValidationModel;
import eu.europa.ec.markt.dss.applet.util.SimpleReportConverter;
import eu.europa.ec.markt.dss.applet.util.ValidationReportConverter;
import eu.europa.ec.markt.dss.applet.view.validation.Report102853View;
import eu.europa.ec.markt.dss.applet.view.validation.ValidationView;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.constraint.ValidationPolicyDao;
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

public class ValidationWizardController extends DSSWizardController<ValidationModel> {

    private Report102853View report102853View;

    private ValidationView formView;

    /**
     * The default constructor for ValidationWizardController.
     *
     * @param core
     * @param model
     */
    @Inject
    ValidationWizardController(final DSSAppletCore core, final ValidationModel model) {

        super(core, model);
        final Parameters parameters = core.getParameters();
    }

    /**
     *
     */
    public void displayFormView() {
        formView.show();
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.ecodex.dss.commons.swing.mvc.applet.WizardController#doCancel()
     */
    @Override
    protected void doCancel() {
        getCore().getController(ActivityController.class).display();
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#doStart()
     */
    @Override
    protected Class<? extends WizardStep<ValidationModel, ? extends WizardController<ValidationModel>>> doStart() {
        return FormStep.class;
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#registerViews()
     */
    @Override
    protected void registerViews() {
        formView = new ValidationView(getCore(), this, getModel());
        report102853View = new Report102853View(getCore(), this, getModel());
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#registerWizardStep()
     */
    @Override
    protected Map<Class<? extends WizardStep<ValidationModel, ? extends WizardController<ValidationModel>>>, ? extends WizardStep<ValidationModel, ? extends WizardController<ValidationModel>>> registerWizardStep() {
        final Map steps = new HashMap();
        steps.put(FormStep.class, new FormStep(getModel(), formView, this));
        steps.put(Report102853Step.class, new Report102853Step(getModel(), report102853View, this));
        return steps;
    }

    @Inject
    private CommonCertificateVerifier trustedListCertificateVerifier;

    /**
     * Validate the document with the 102853 validation policy
     *
     * @throws IOException
     */
    public void validate102853Document() throws IOException {

        final ValidationModel model = getModel();
        final File signed = model.getSignedFile();
        final DSSDocument signedDocument = new FileDocument(signed);
        final File externalSignatureFile = model.getOriginalFile();

        CertificateIdentifier.clear();

        eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator validator = eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator
              .fromDocument(signedDocument);
        validator.setCertificateVerifier(trustedListCertificateVerifier);

        // In case of detached signature, the signature file path from JFileChooser
        if (externalSignatureFile != null && externalSignatureFile.exists()) {
            final DSSDocument externalSignatureDocument = new FileDocument(externalSignatureFile);
            validator.setExternalContent(externalSignatureDocument);
        }

        URL validationPolicyURL = getParameter().getDefaultPolicyUrl();
        if (!model.isDefault102853Policy() && model.getSelectedPolicyFile() != null) {
            validationPolicyURL = new File(model.getSelectedPolicyFile().getAbsolutePath()).toURI().toURL();

        }

        assertValidationPolicyFileValid(validationPolicyURL);

        eu.europa.ec.markt.dss.validation102853.report.ValidationReport report = validator.validateDocument(validationPolicyURL);

        model.setDiagnosticData102853(validator.getDiagnosticData());
        model.setValidation102853Report(report);
        model.setSimpleReport102853(validator.getSimpleReport());
    }

    private void assertValidationPolicyFileValid(URL validationPolicyURL) {
        try {
            new ValidationPolicyDao().load(validationPolicyURL);
        } catch (Exception e) {
            throw new DSSException("The selected Validation Policy is not valid.");
        }
    }

    public Document renderSimpleReportAsHtml() {

        final SimpleReport simpleReport102853 = getModel().getSimpleReport102853();
        final SimpleReportConverter simpleReportConverter = new SimpleReportConverter();
        return simpleReportConverter.renderAsHtml(simpleReport102853);
    }

    public Document renderValidationReportAsHtml() {

        final eu.europa.ec.markt.dss.validation102853.report.ValidationReport validation102853Report = getModel().getValidation102853Report();
        final ValidationReportConverter validationReportConverter = new ValidationReportConverter();
        return validationReportConverter.renderAsHtml(validation102853Report);
    }

}
