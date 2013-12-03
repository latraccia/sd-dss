package eu.europa.ec.markt.dss.applet.wizard.extension;

import org.apache.commons.lang.StringUtils;

import eu.europa.ec.markt.dss.applet.model.ExtendSignatureModel;
import eu.europa.ec.markt.dss.applet.model.FormatType;
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
public class SignatureStep extends WizardStep<ExtendSignatureModel, ExtensionWizardController> {

    /**
     * 
     * The default constructor for SignatureStep.
     * 
     * @param model
     * @param view
     * @param controller
     */
    public SignatureStep(final ExtendSignatureModel model, final WizardView<ExtendSignatureModel, ExtensionWizardController> view, final ExtensionWizardController controller) {
        super(model, view, controller);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#finish()
     */
    @Override
    protected void finish() throws ControllerException {
        // TODO Auto-generated method stub

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getBackStep()
     */
    @Override
    protected Class<? extends WizardStep<ExtendSignatureModel, ExtensionWizardController>> getBackStep() {
        return FileStep.class;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
     */
    @Override
    protected Class<? extends WizardStep<ExtendSignatureModel, ExtensionWizardController>> getNextStep() {
        return SaveStep.class;
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
    protected void init() throws ControllerException {

        final ExtendSignatureModel model = getModel();
        switch (model.getFileType()) {
        case ASiCS:
            model.setFormat(FormatType.ASICS);
            break;
        case BINARY:
            model.setFormat(FormatType.CADES);
            break;
        case CMS:
            model.setFormat(FormatType.CADES);
            break;
        case PDF:
            model.setFormat(FormatType.PADES);
            break;
        case XML:
            model.setFormat(FormatType.XADES);
            break;
        default:
            model.setFormat(FormatType.CADES);
            break;
        }

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#isValid()
     */
    @Override
    protected boolean isValid() {
        final ExtendSignatureModel model = getModel();
        return StringUtils.isNotEmpty(model.getFormat()) && model.getPackaging() != null && StringUtils.isNotEmpty(model.getLevel());
    }

}
