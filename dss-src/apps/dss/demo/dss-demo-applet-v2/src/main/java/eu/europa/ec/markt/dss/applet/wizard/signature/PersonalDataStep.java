package eu.europa.ec.markt.dss.applet.wizard.signature;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

import eu.europa.ec.markt.dss.applet.main.Parameters;
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
public class PersonalDataStep extends WizardStep<SignatureModel, SignatureWizardController> {
    /**
     * 
     * The default constructor for PersonalDataStep.
     * 
     * @param model
     * @param view
     * @param controller
     */
    public PersonalDataStep(final SignatureModel model, final WizardView<SignatureModel, SignatureWizardController> view, final SignatureWizardController controller) {
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
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getBackStep() {
        return CertificateStep.class;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
     */
    @Override
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {
        return SaveStep.class;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getStepProgression()
     */
    @Override
    protected int getStepProgression() {
        return 5;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#execute()
     */
    @Override
    protected void init() {

        final Parameters parameters = getController().getParameter();
        final SignatureModel model = getModel();

        if (parameters.hasSignaturePolicyAlgo() && StringUtils.isEmpty(model.getSignaturePolicyAlgo())) {
            model.setSignaturePolicyAlgo(parameters.getSignaturePolicyAlgo());
        }

        if (parameters.hasSignaturePolicyValue() && StringUtils.isEmpty(model.getSignaturePolicyValue())) {
            model.setSignaturePolicyValue(Base64.encodeBase64String(parameters.getSignaturePolicyValue()));
        }

        final boolean levelBES = model.getLevel().toUpperCase().endsWith("-BES");
        model.setSignaturePolicyVisible(!levelBES);

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#isValid()
     */
    @Override
    protected boolean isValid() {

        final SignatureModel model = getModel();

        if (model.isSignaturePolicyCheck()) {
            return StringUtils.isNotEmpty(model.getSignaturePolicyAlgo()) && StringUtils.isNotEmpty(model.getSignaturePolicyId()) && StringUtils.isNotEmpty(model.getSignaturePolicyValue());
        }
        return true;
    }
}
