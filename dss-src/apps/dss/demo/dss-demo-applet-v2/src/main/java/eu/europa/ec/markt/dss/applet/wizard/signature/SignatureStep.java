package eu.europa.ec.markt.dss.applet.wizard.signature;

import org.apache.commons.lang.StringUtils;

import eu.europa.ec.markt.dss.applet.main.Parameters;
import eu.europa.ec.markt.dss.applet.model.SignatureModel;
import eu.europa.ec.markt.dss.common.SignatureTokenType;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.ControllerException;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;

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
public class SignatureStep extends WizardStep<SignatureModel, SignatureWizardController> {
    /**
     * 
     * The default constructor for SignatureStep.
     * 
     * @param model
     * @param view
     * @param controller
     */
    public SignatureStep(final SignatureModel model, final WizardView<SignatureModel, SignatureWizardController> view, final SignatureWizardController controller) {
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
        return FileStep.class;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
     */
    @Override
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {

        final Parameters parameters = getController().getParameter();
        if (parameters.hasSignatureTokenType()) {
            final SignatureTokenType tokenType = parameters.getSignatureTokenType();
            getModel().setTokenType(tokenType);
            switch (tokenType) {
            case MOCCA:
                return FinishStep.class;
            case MSCAPI:
                return CertificateStep.class;
            case PKCS11:
                return PKCS11Step.class;
            case PKCS12:
                return PKCS12Step.class;
            default:
                throw new RuntimeException("Cannot evaluate token type");
            }

        } else {
            return TokenStep.class;
        }

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getStepProgression()
     */
    @Override
    protected int getStepProgression() {
        return 2;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#execute()
     */
    @Override
    protected void init() {

        final SignatureModel model = getModel();
        final Parameters parameters = getController().getParameter();
        final SignaturePackaging packaging = parameters.getSignaturePackaging();
        final String level = parameters.getSignatureLevel();
        final String format = parameters.getSignatureFormat();

        if (format != null) {
            model.setFormat(format);
            if (packaging != null) {
                model.setPackaging(packaging);
                if (StringUtils.isNotEmpty(level)) {
                    model.setLevel(level);
                }
            }
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#isValid()
     */
    @Override
    protected boolean isValid() {
        final SignatureModel model = getModel();
        return StringUtils.isNotEmpty(model.getFormat()) && model.getPackaging() != null && StringUtils.isNotEmpty(model.getLevel());
    }

}
