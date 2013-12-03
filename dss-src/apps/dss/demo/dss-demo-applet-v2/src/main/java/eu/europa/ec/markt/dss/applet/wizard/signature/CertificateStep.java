package eu.europa.ec.markt.dss.applet.wizard.signature;

import java.io.File;
import java.security.KeyStoreException;

import eu.europa.ec.markt.dss.applet.main.Parameters;
import eu.europa.ec.markt.dss.applet.model.SignatureModel;
import eu.europa.ec.markt.dss.applet.util.MOCCAAdapter;
import eu.europa.ec.markt.dss.common.PinInputDialog;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.ControllerException;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;
import eu.europa.ec.markt.dss.signature.token.MSCAPISignatureToken;
import eu.europa.ec.markt.dss.signature.token.Pkcs11SignatureToken;
import eu.europa.ec.markt.dss.signature.token.Pkcs12SignatureToken;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class CertificateStep extends WizardStep<SignatureModel, SignatureWizardController> {
    /**
     * The default constructor for CertificateStep.
     *
     * @param model
     * @param view
     * @param controller
     */
    public CertificateStep(final SignatureModel model, final WizardView<SignatureModel, SignatureWizardController> view,
                           final SignatureWizardController controller) {
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

        final Parameters parameters = getController().getParameter();
        if (parameters.hasSignatureTokenType()) {
            return SignatureStep.class;
        } else {
            switch (getModel().getTokenType()) {
                case MOCCA:
                    return MoccaStep.class;
                case MSCAPI:
                    return TokenStep.class;
                case PKCS11:
                    return PKCS11Step.class;
                case PKCS12:
                    return PKCS12Step.class;
                default:
                    throw new RuntimeException("Cannot evaluate token type");
            }
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
     */
    @Override
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {
        return PersonalDataStep.class;
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getStepProgression()
     */
    @Override
    protected int getStepProgression() {
        return 4;
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#execute()
     */
    @Override
    protected void init() throws ControllerException {
        final SignatureModel model = getModel();

        SignatureTokenConnection tokenConnetion = null;

        switch (model.getTokenType()) {

            case MSCAPI: {
                tokenConnetion = new MSCAPISignatureToken();
                break;
            }
            case MOCCA: {
                tokenConnetion = new MOCCAAdapter().createSignatureToken(new PinInputDialog(getController().getCore()));
                break;
            }
            case PKCS11:

                final File file = model.getPkcs11File();

                tokenConnetion = new Pkcs11SignatureToken(file.getAbsolutePath(), model.getPkcs11Password().toCharArray());

                break;
            case PKCS12:
                tokenConnetion = new Pkcs12SignatureToken(model.getPkcs12Password(), model.getPkcs12File());
                break;
            default:
                throw new RuntimeException("No token connection selected");
        }
        try {
            model.setTokenConnection(tokenConnetion);
            model.setPrivateKeys(tokenConnetion.getKeys());
        } catch (final KeyStoreException e) {
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
        return getModel().getSelectedPrivateKey() != null;
    }

}
