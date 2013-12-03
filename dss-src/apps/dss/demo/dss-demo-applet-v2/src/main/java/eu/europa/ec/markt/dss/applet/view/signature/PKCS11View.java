package eu.europa.ec.markt.dss.applet.view.signature;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.io.File;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPasswordField;

import com.jgoodies.binding.beans.BeanAdapter;
import com.jgoodies.binding.value.ValueModel;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

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
public class PKCS11View extends WizardView<SignatureModel, SignatureWizardController> {

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
    private class SelectPKCSFileEventListener implements ActionListener {
        /*
         * (non-Javadoc)
         * 
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        @Override
        public void actionPerformed(final ActionEvent e) {
            final JFileChooser chooser = new JFileChooser();

            final int result = chooser.showOpenDialog(getCore());

            if (result == JFileChooser.APPROVE_OPTION) {
                getModel().setPkcs11File(chooser.getSelectedFile());
            }
        }
    }

    private static final String I18N_NO_FILE_SELECTED = ResourceUtils.getI18n("NO_FILE_SELECTED");
    private static final String I18N_BROWSE = ResourceUtils.getI18n("BROWSE");
    private static final String I18N_LIBRARY_PATH = ResourceUtils.getI18n("LIBRARY_PATH");
    private static final String I18N_PASSWORD = ResourceUtils.getI18n("PASSWORD");

    private final JLabel fileSourceLabel;
    private final JButton selectFileSource;
    private final JPasswordField passwordField;

    private final ValueModel valueModel;

    /**
     * 
     * The default constructor for PKCS11View.
     * 
     * @param core
     * @param controller
     * @param model
     */
    public PKCS11View(final AppletCore core, final SignatureWizardController controller, final SignatureModel model) {
        super(core, controller, model);
        final BeanAdapter<SignatureModel> beanAdapter = new BeanAdapter<SignatureModel>(model);
        fileSourceLabel = ComponentFactory.createLabel(I18N_NO_FILE_SELECTED);
        selectFileSource = ComponentFactory.createFileChooser(I18N_BROWSE, true, new SelectPKCSFileEventListener());
        valueModel = beanAdapter.getValueModel(SignatureModel.PROPERTY_PKCS11_PASSWORD);
        passwordField = ComponentFactory.createPasswordField(valueModel, false);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doInit()
     */
    @Override
    public void doInit() {
        final File pkcs11File = getModel().getPkcs11File();
        fileSourceLabel.setText(pkcs11File != null ? pkcs11File.getName() : I18N_NO_FILE_SELECTED);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {
        final FormLayout layout = new FormLayout("5dlu, pref, 5dlu, pref, 5dlu ,pref:grow ,5dlu", "5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu");
        final PanelBuilder builder = ComponentFactory.createBuilder(layout);
        final CellConstraints cc = new CellConstraints();
        builder.addSeparator(I18N_LIBRARY_PATH, cc.xyw(2, 2, 5));
        builder.add(selectFileSource, cc.xy(2, 4));
        builder.add(fileSourceLabel, cc.xyw(4, 4, 3));
        builder.addSeparator(I18N_PASSWORD, cc.xyw(2, 6, 5));
        builder.add(passwordField, cc.xyw(2, 8, 3));
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
        final File pkcs11File = getModel().getPkcs11File();

        if (evt.getPropertyName().equals(SignatureModel.PROPERTY_PKCS11_FILE)) {
            final String text = pkcs11File == null ? I18N_NO_FILE_SELECTED : pkcs11File.getName();
            fileSourceLabel.setText(text);
        }
    }
}
