package eu.europa.ec.markt.dss.applet.wizard.extension;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;

import org.apache.commons.io.IOUtils;

import eu.europa.ec.markt.dss.applet.controller.ActivityController;
import eu.europa.ec.markt.dss.applet.main.DSSAppletCore;
import eu.europa.ec.markt.dss.applet.model.ExtendSignatureModel;
import eu.europa.ec.markt.dss.applet.util.SigningUtils;
import eu.europa.ec.markt.dss.applet.view.extension.FileView;
import eu.europa.ec.markt.dss.applet.view.extension.FinishView;
import eu.europa.ec.markt.dss.applet.view.extension.SaveView;
import eu.europa.ec.markt.dss.applet.view.extension.SignatureView;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.signature.SignatureParameters;

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
public class ExtensionWizardController extends WizardController<ExtendSignatureModel> {

    private FileView fileView;
    private SignatureView signatureView;
    private SaveView saveView;
    private FinishView finishView;

    /**
     * 
     * The default constructor for ExtendsWizardController.
     * 
     * @param core
     * @param model
     */
    @Inject
    ExtensionWizardController(final DSSAppletCore core, final ExtendSignatureModel model) {
        super(core, model);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#doCancel()
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
    protected Class<? extends WizardStep<ExtendSignatureModel, ? extends WizardController<ExtendSignatureModel>>> doStart() {
        return FileStep.class;
    }

    /**
     * 
     * @throws IOException
     */
    public void extendAndSave() throws IOException {

        final ExtendSignatureModel model = getModel();
        final File signedFile = getModel().getSelectedFile();
        final File originalFile = getModel().getOriginalFile();

        final SignatureParameters parameters = new SignatureParameters();
        parameters.setSignatureFormat(SignatureFormat.valueByName(model.getLevel()));

        final DSSDocument signedDocument = SigningUtils.extendDocument(signedFile, originalFile, parameters, tspSource, certificateVerifier);

        IOUtils.copy(signedDocument.openStream(), new FileOutputStream(model.getTargetFile()));

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#registerViews()
     */
    @Override
    protected void registerViews() {
        this.fileView = new FileView(getCore(), this, getModel());
        this.signatureView = new SignatureView(getCore(), this, getModel());
        this.saveView = new SaveView(getCore(), this, getModel());
        this.finishView = new FinishView(getCore(), this, getModel());
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#registerWizardStep()
     */
    @Override
    protected Map<Class<? extends WizardStep<ExtendSignatureModel, ? extends WizardController<ExtendSignatureModel>>>, ? extends WizardStep<ExtendSignatureModel, ? extends WizardController<ExtendSignatureModel>>> registerWizardStep() {
        final Map steps = new HashMap();
        steps.put(FileStep.class, new FileStep(getModel(), fileView, this));
        steps.put(SignatureStep.class, new SignatureStep(getModel(), signatureView, this));
        steps.put(SaveStep.class, new SaveStep(getModel(), saveView, this));
        steps.put(FinishStep.class, new FinishStep(getModel(), finishView, this));
        return steps;
    }

}
