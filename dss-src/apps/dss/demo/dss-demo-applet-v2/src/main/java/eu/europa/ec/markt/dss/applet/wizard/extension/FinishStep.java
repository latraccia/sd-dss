package eu.europa.ec.markt.dss.applet.wizard.extension;

import java.io.IOException;

import eu.europa.ec.markt.dss.applet.model.ExtendSignatureModel;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.ControllerException;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;

/**
 * 
 * TODO
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class FinishStep extends WizardStep<ExtendSignatureModel, ExtensionWizardController> {
    /**
     * 
     * The default constructor for FinishStep.
     * 
     * @param model
     * @param view
     * @param controller
     */
    public FinishStep(final ExtendSignatureModel model, final WizardView<ExtendSignatureModel, ExtensionWizardController> view, final ExtensionWizardController controller) {
        super(model, view, controller);
    }

    @Override
    protected void finish() throws ControllerException {

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getBackStep()
     */
    @Override
    protected Class<? extends WizardStep<ExtendSignatureModel, ExtensionWizardController>> getBackStep() {
        return SaveStep.class;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
     */
    @Override
    protected Class<? extends WizardStep<ExtendSignatureModel, ExtensionWizardController>> getNextStep() {
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getStepProgression()
     */
    @Override
    protected int getStepProgression() {
        return 3;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#execute()
     */
    @Override
    protected void init() throws ControllerException {
        try {
            getController().extendAndSave();
        } catch (IOException e) {
            throw new ControllerException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#isValid()
     */
    @Override
    protected boolean isValid() {
        return false;
    }

}
