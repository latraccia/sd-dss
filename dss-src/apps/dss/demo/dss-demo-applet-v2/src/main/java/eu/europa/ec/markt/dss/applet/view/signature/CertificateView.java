package eu.europa.ec.markt.dss.applet.view.signature;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JList;

import com.jgoodies.binding.PresentationModel;
import com.jgoodies.binding.list.SelectionInList;
import com.jgoodies.binding.value.ValueModel;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

import eu.europa.ec.markt.dss.applet.component.model.CertificateListCellRenderer;
import eu.europa.ec.markt.dss.applet.model.SignatureModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.util.ResourceUtils;
import eu.europa.ec.markt.dss.applet.wizard.signature.SignatureWizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;

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
public class CertificateView extends WizardView<SignatureModel, SignatureWizardController> {

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
    private class RefreshActionListener implements ActionListener {
        /*
         * (non-Javadoc)
         * 
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        @Override
        public void actionPerformed(final ActionEvent e) {
            getController().doRefreshPrivateKeys();
        }
    }

    private static final String I18N_CHOOSE_SIGNING_CERTIFICATE = ResourceUtils.getI18n("CHOOSE_SIGNING_CERTIFICATE");

    private final JButton refreshButton;
    private final JList certificateList;
    private final SelectionInList<DSSPrivateKeyEntry> selectionList;

    private final PresentationModel<SignatureModel> presentationModel;

    /**
     * 
     * The default constructor for CertificateView.
     * 
     * @param core
     * @param controller
     * @param model
     */
    public CertificateView(final AppletCore core, final SignatureWizardController controller, final SignatureModel model) {
        super(core, controller, model);

        presentationModel = new PresentationModel<SignatureModel>(getModel());

        final ValueModel listValueModel = presentationModel.getModel(SignatureModel.PROPERTY_PRIVATE_KEYS);
        final ValueModel privateKeyValueModel = presentationModel.getModel(SignatureModel.PROPERTY_SELECTED_PRIVATE_KEY);
        selectionList = new SelectionInList<DSSPrivateKeyEntry>(listValueModel, privateKeyValueModel);

        certificateList = ComponentFactory.createList(selectionList, new CertificateListCellRenderer());
        refreshButton = ComponentFactory.createRefreshButton(true, new RefreshActionListener());

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {

        final FormLayout layout = new FormLayout("5dlu, pref, fill:default:grow, 5dlu", "5dlu , pref, 5dlu, fill:default:grow, 5dlu, pref, 5dlu");
        final PanelBuilder builder = ComponentFactory.createBuilder(layout);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator(I18N_CHOOSE_SIGNING_CERTIFICATE, cc.xyw(2, 2, 2));
        builder.add(ComponentFactory.createScrollPane(certificateList), cc.xyw(2, 4, 2));
        builder.add(refreshButton, cc.xy(2, 6));

        return ComponentFactory.createPanel(builder);
    }

}
