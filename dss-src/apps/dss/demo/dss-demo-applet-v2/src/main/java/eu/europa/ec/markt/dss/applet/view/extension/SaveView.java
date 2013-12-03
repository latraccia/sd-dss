package eu.europa.ec.markt.dss.applet.view.extension;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.io.File;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;

import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

import eu.europa.ec.markt.dss.applet.model.ExtendSignatureModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.util.ResourceUtils;
import eu.europa.ec.markt.dss.applet.wizard.extension.ExtensionWizardController;
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
public class SaveView extends WizardView<ExtendSignatureModel, ExtensionWizardController> {

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
    private class SelectTargetFileEventListener implements ActionListener {
        /*
         * (non-Javadoc)
         * 
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        @Override
        public void actionPerformed(final ActionEvent e) {
            final File targetFile = getModel().getTargetFile();
            final JFileChooser chooser = new JFileChooser();
            chooser.setCurrentDirectory(targetFile.getParentFile());
            chooser.setSelectedFile(targetFile);

            final int result = chooser.showSaveDialog(getCore());

            if (result == JFileChooser.APPROVE_OPTION) {
                getModel().setTargetFile(chooser.getSelectedFile());
            }
        }
    }

    private static final String I18N_NO_FILE_SELECTED = ResourceUtils.getI18n("NO_FILE_SELECTED");

    private static final String I18N_CHOOSE_DESTINATION = ResourceUtils.getI18n("CHOOSE_DESTINATION");
    private final JLabel fileTargetLabel;

    private final JButton selectFileTarget;

    /**
     * 
     * The default constructor for SaveView.
     * 
     * @param core
     * @param controller
     * @param model
     */
    public SaveView(final AppletCore core, final ExtensionWizardController controller, final ExtendSignatureModel model) {
        super(core, controller, model);
        fileTargetLabel = ComponentFactory.createLabel(I18N_NO_FILE_SELECTED);
        selectFileTarget = ComponentFactory.createFileChooser(I18N_CHOOSE_DESTINATION, true, new SelectTargetFileEventListener());
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doInit()
     */
    @Override
    public void doInit() {
        final File targetFile = getModel().getTargetFile();
        fileTargetLabel.setText(targetFile != null ? targetFile.getName() : I18N_NO_FILE_SELECTED);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {
        final FormLayout layout = new FormLayout("5dlu, pref, 5dlu, pref, 5dlu ,pref:grow ,5dlu", "5dlu, pref, 5dlu, pref, 5dlu");
        final PanelBuilder builder = ComponentFactory.createBuilder(layout);
        final CellConstraints cc = new CellConstraints();
        builder.addSeparator(ResourceUtils.getI18n("CHOOSE_DESTINATION"), cc.xyw(2, 2, 5));
        builder.add(selectFileTarget, cc.xy(2, 4));
        builder.add(fileTargetLabel, cc.xyw(4, 4, 3));
        return ComponentFactory.createPanel(builder);
    }

    /*
     * (non-Javadoc)
     * 
     * @see
     * eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView#wizardModelChange(java.beans.PropertyChangeEvent
     * )
     */
    @Override
    public void wizardModelChange(final PropertyChangeEvent evt) {
        if (evt.getPropertyName().equals(ExtendSignatureModel.PROPERTY_TARGET_FILE)) {
            final ExtendSignatureModel model = getModel();
            final File targetFile = model.getTargetFile();
            final String text = targetFile == null ? I18N_NO_FILE_SELECTED : targetFile.getName();
            fileTargetLabel.setText(text);
        }
    }

}
