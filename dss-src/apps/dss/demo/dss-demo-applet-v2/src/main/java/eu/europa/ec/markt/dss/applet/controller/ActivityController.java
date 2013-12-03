package eu.europa.ec.markt.dss.applet.controller;

import eu.europa.ec.markt.dss.applet.main.DSSAppletCore;
import eu.europa.ec.markt.dss.applet.model.ActivityModel;
import eu.europa.ec.markt.dss.applet.view.ActivityView;
import eu.europa.ec.markt.dss.applet.wizard.extension.ExtensionWizardController;
import eu.europa.ec.markt.dss.applet.wizard.signature.SignatureWizardController;
import eu.europa.ec.markt.dss.applet.wizard.validation.ValidationWizardController;
import eu.europa.ec.markt.dss.applet.wizard.validationpolicy.ValidationPolicyWizardController;

import javax.inject.Inject;

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
public class ActivityController extends DSSAppletController<ActivityModel> {

    private ActivityView view;

    /**
     * 
     * The default constructor for ActivityController.
     * 
     * @param core
     * @param model
     */
    @Inject
    ActivityController(final DSSAppletCore core, final ActivityModel model) {
        super(core, model);
        view = new ActivityView(getCore(), this, getModel());
    }

    /**
     * 
     */
    public void display() {
        view.show();
    }

    /**
     * 
     */
    public void startAction() {
        switch (getModel().getAction()) {
        case EXTEND:
            getCore().getController(ExtensionWizardController.class).start();
            break;
        case SIGN:
            getCore().getController(SignatureWizardController.class).start();
            break;
        case VERIFY:
            getCore().getController(ValidationWizardController.class).start();
            break;
        case EDIT_VALIDATION_POLICY:
            getCore().getController(ValidationPolicyWizardController.class).start();
            break;
        }
    }
}
