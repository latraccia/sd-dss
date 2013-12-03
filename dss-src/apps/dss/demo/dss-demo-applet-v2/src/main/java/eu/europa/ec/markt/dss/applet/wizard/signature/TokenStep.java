package eu.europa.ec.markt.dss.applet.wizard.signature;

import eu.europa.ec.markt.dss.applet.model.SignatureModel;
import eu.europa.ec.markt.dss.common.SignatureTokenType;
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
public class TokenStep extends WizardStep<SignatureModel, SignatureWizardController> {

    /**
     * 
     * The default constructor for TokenStep.
     * 
     * @param model
     * @param view
     * @param controller
     */
    public TokenStep(final SignatureModel model, final WizardView<SignatureModel, SignatureWizardController> view, final SignatureWizardController controller) {
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
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#execute()
     */
    @Override
    protected void init() {

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getBackStep()
     */
    @Override
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getBackStep() {
        return SignatureStep.class;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
     */
    @Override
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {

        final SignatureTokenType tokenType = getModel().getTokenType();

        if (tokenType == null) {
            return this.getClass();
        }

        switch (tokenType) {
        case MOCCA:
            return MoccaStep.class;
        case MSCAPI:
            return CertificateStep.class;
        case PKCS11:
            return PKCS11Step.class;
        case PKCS12:
            return PKCS12Step.class;
        }
        return this.getClass();

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
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#isValid()
     */
    @Override
    protected boolean isValid() {
        return true;
    }

}
