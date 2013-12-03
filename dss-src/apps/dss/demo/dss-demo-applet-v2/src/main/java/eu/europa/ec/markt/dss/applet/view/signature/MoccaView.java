package eu.europa.ec.markt.dss.applet.view.signature;

import java.awt.*;

import javax.swing.*;

import com.jgoodies.binding.PresentationModel;
import com.jgoodies.binding.list.SelectionInList;
import com.jgoodies.binding.value.ValueModel;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import eu.europa.ec.markt.dss.applet.model.SignatureModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.util.ResourceUtils;
import eu.europa.ec.markt.dss.applet.wizard.signature.SignatureWizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;

public class MoccaView extends WizardView<SignatureModel, SignatureWizardController> {

    private final PresentationModel<SignatureModel> presentationModel;

    private final ValueModel signatureAlgorithmValue;

    private final JComboBox signatureAlgorithmComboBox;

    /**
     * 
     * The default constructor for MoccaView.
     * 
     * @param core
     * @param controller
     * @param model
     */
    public MoccaView(AppletCore core, SignatureWizardController controller, SignatureModel model) {
        super(core, controller, model);

        this.presentationModel = new PresentationModel<SignatureModel>(getModel());
        signatureAlgorithmValue = presentationModel.getModel(SignatureModel.PROPERTY_MOCCA_SIGNATURE_ALGORITHM);
        final SelectionInList<String> algorithms = new SelectionInList<String>(new String[] { "sha1", "sha256"}, signatureAlgorithmValue);
        signatureAlgorithmComboBox = ComponentFactory.createComboBox(algorithms);

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {

        final String[] colSpecs = new String[] { "5dlu", "pref", "5dlu" };
        final String[] rowSpecs = new String[] { "5dlu", "pref", "5dlu", "pref", "5dlu" };

        final PanelBuilder builder = ComponentFactory.createBuilder(colSpecs, rowSpecs);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator(ResourceUtils.getI18n("SIGNATURE_ALGORITHM"), cc.xyw(2, 2, 1));
        builder.add(signatureAlgorithmComboBox, cc.xyw(2, 4, 1));

        return ComponentFactory.createPanel(builder);
    }

}
