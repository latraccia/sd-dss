package eu.europa.ec.markt.dss.applet.wizard.validation;

import java.io.File;

import eu.europa.ec.markt.dss.applet.model.ValidationModel;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.ControllerException;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class FormStep extends WizardStep<ValidationModel, ValidationWizardController> {
    /**
     * The default constructor for FormStep.
     *
     * @param model
     * @param view
     * @param controller
     */
    public FormStep(final ValidationModel model, final WizardView<ValidationModel, ValidationWizardController> view,
                    final ValidationWizardController controller) {
        super(model, view, controller);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#finish()
     */
    @Override
    protected void finish() throws ControllerException {

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getBackStep()
     */
    @Override
    protected Class<? extends WizardStep<ValidationModel, ValidationWizardController>> getBackStep() {
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
     */
    @Override
    protected Class<? extends WizardStep<ValidationModel, ValidationWizardController>> getNextStep() {

        return Report102853Step.class;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getStepProgression()
     */
    @Override
    protected int getStepProgression() {
        return 1;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#execute()
     */
    @Override
    protected void init() {
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#isValid()
     */
    @Override
    protected boolean isValid() {
        final File signedFile = getModel().getSignedFile();
        final File originalFile = getModel().getOriginalFile();
        final boolean validationLegacyChoosen = getModel().isValidationLegacyChoosen();
        final boolean default102853Policy = getModel().isDefault102853Policy();
        final File selectedPolicyFile = getModel().getSelectedPolicyFile();

        boolean valid = signedFile != null && signedFile.exists() && signedFile.isFile();

        if (originalFile != null) {
            valid &= originalFile.exists() && originalFile.isFile();
        }

        if (!validationLegacyChoosen) {
            if (!default102853Policy) {
                valid &= selectedPolicyFile != null && selectedPolicyFile.exists() && selectedPolicyFile.isFile();
            }
        }

        return valid;
    }
}
