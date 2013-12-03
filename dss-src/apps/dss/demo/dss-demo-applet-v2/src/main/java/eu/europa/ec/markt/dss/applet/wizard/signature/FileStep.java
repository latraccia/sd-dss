package eu.europa.ec.markt.dss.applet.wizard.signature;

import java.io.File;

import eu.europa.ec.markt.dss.applet.model.SignatureModel;
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
public class FileStep extends WizardStep<SignatureModel, SignatureWizardController> {
    /**
     * 
     * The default constructor for FileStep.
     * 
     * @param model
     * @param view
     * @param controller
     */
    public FileStep(final SignatureModel model, final WizardView<SignatureModel, SignatureWizardController> view, final SignatureWizardController controller) {
        super(model, view, controller);
    }

    @Override
    protected void finish() throws ControllerException {
        // TODO Auto-generated method stub

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#execute()
     */
    @Override
    protected void init() throws ControllerException {

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getBackStep()
     */
    @Override
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getBackStep() {
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
     */
    @Override
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {
        return SignatureStep.class;
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
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#isValid()
     */
    @Override
    protected boolean isValid() {
        final SignatureModel model = getModel();
        final File selectedFile = model.getSelectedFile();
        final boolean valid = selectedFile != null && selectedFile.exists() && selectedFile.isFile();
        return valid;
    }
}
