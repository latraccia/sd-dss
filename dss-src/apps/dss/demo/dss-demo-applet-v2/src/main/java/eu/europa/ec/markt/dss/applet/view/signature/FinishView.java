package eu.europa.ec.markt.dss.applet.view.signature;

import java.awt.Container;

import javax.swing.JLabel;
import javax.swing.JPanel;

import eu.europa.ec.markt.dss.applet.model.SignatureModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.util.ResourceUtils;
import eu.europa.ec.markt.dss.applet.wizard.signature.SignatureWizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
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
public class FinishView extends WizardView<SignatureModel, SignatureWizardController> {

    private final JLabel message;

    /**
     * 
     * The default constructor for SignView.
     * 
     * @param core
     * @param controller
     * @param model
     */
    public FinishView(final AppletCore core, final SignatureWizardController controller, final SignatureModel model) {
        super(core, controller, model);
        message = ComponentFactory.createLabel(ResourceUtils.getI18n("SIGNED_FILE_SAVED"), ComponentFactory.iconSuccess());
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doInit()
     */
    @Override
    public void doInit() {

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {
        final JPanel panel = ComponentFactory.createPanel();
        panel.add(message);
        return panel;
    }

}
