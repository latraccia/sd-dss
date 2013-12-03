package eu.europa.ec.markt.dss.applet.wizard.signature;

import java.io.File;

import org.apache.commons.lang.StringUtils;

import eu.europa.ec.markt.dss.applet.model.SignatureModel;
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
public class SaveStep extends WizardStep<SignatureModel, SignatureWizardController> {
    /**
     * 
     * The default constructor for SaveStep.
     * 
     * @param model
     * @param view
     * @param controller
     */
    public SaveStep(final SignatureModel model, final WizardView<SignatureModel, SignatureWizardController> view, final SignatureWizardController controller) {
        super(model, view, controller);
    }

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
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getBackStep() {
        return PersonalDataStep.class;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getNextStep()
     */
    @Override
    protected Class<? extends WizardStep<SignatureModel, SignatureWizardController>> getNextStep() {
        return FinishStep.class;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#getStepProgression()
     */
    @Override
    protected int getStepProgression() {
        return 6;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#execute()
     */
    @Override
    protected void init() {

        final File selectedFile = getModel().getSelectedFile();
        // Initialize the target file base on the current selected file

        final SignaturePackaging signaturePackaging = getModel().getPackaging();
        final String signatureLevel = getModel().getLevel();
        final File targetFile = prepareTargetFileName(selectedFile, signaturePackaging, signatureLevel);

        getModel().setTargetFile(targetFile);

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep#isValid()
     */
    @Override
    protected boolean isValid() {
        final File targetFile = getModel().getTargetFile();
        return targetFile != null;
    }

    private File prepareTargetFileName(final File file, final SignaturePackaging signaturePackaging, final String signatureLevel) {

        final File parentDir = file.getParentFile();
        final String originalName = StringUtils.substringBeforeLast(file.getName(), ".");
        final String originalExtension = "." + StringUtils.substringAfterLast(file.getName(), ".");
        final String format = signatureLevel.toUpperCase();

        if ((SignaturePackaging.ENVELOPING == signaturePackaging || SignaturePackaging.DETACHED == signaturePackaging) && format.startsWith("XADES")) {
            return new File(parentDir, originalName + "-signed" + ".xml");
        }

        if (format.startsWith("CADES") && !originalExtension.toLowerCase().equals(".p7m")) {
            return new File(parentDir, originalName + originalExtension + ".p7m");
        }

        if (format.startsWith("ASIC")) {
            return new File(parentDir, originalName + originalExtension + ".asics");
        }

        return new File(parentDir, originalName + "-signed" + originalExtension);

    }
}
