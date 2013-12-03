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
import javax.swing.filechooser.FileFilter;

import com.jgoodies.binding.beans.BeanAdapter;
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
public class PKCS12View extends WizardView<SignatureModel, SignatureWizardController> {

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
    private final class PKCS12FileFilter extends FileFilter {
        /*
         * (non-Javadoc)
         * 
         * @see javax.swing.filechooser.FileFilter#accept(java.io.File)
         */
        @Override
        public boolean accept(final File f) {
            return f.getName().endsWith(".p12") || f.getName().endsWith(".pfx") || f.isDirectory();
        }

        /*
         * (non-Javadoc)
         * 
         * @see javax.swing.filechooser.FileFilter#getDescription()
         */
        @Override
        public String getDescription() {
            return ResourceUtils.getI18n("PKCS_FILES");
        }
    }

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
            chooser.setFileFilter(new PKCS12FileFilter());

            final int result = chooser.showOpenDialog(getCore());

            if (result == JFileChooser.APPROVE_OPTION) {
                getModel().setPkcs12File(chooser.getSelectedFile());
            }
        }
    }

    private static final String I18N_NO_FILE_SELECTED = ResourceUtils.getI18n("NO_FILE_SELECTED");
    private static final String I18N_BROWSE = ResourceUtils.getI18n("BROWSE");
    private static final String I18N_CHOOSE_PKCS12_FILE = ResourceUtils.getI18n("CHOOSE_PKCS12_FILE");
    private static final String I18N_PASSWORD = ResourceUtils.getI18n("PASSWORD");

    private final JLabel fileSourceLabel;
    private final JButton selectFileSource;
    private final JPasswordField passwordField;

    /**
     * 
     * The default constructor for PKCS12View.
     * 
     * @param core
     * @param controller
     * @param model
     */
    public PKCS12View(final AppletCore core, final SignatureWizardController controller, final SignatureModel model) {
        super(core, controller, model);
        final BeanAdapter<SignatureModel> beanAdapter = new BeanAdapter<SignatureModel>(model);
        fileSourceLabel = ComponentFactory.createLabel(I18N_NO_FILE_SELECTED);
        selectFileSource = ComponentFactory.createFileChooser(I18N_BROWSE, true, new SelectPKCSFileEventListener());
        passwordField = ComponentFactory.createPasswordField(beanAdapter.getValueModel(SignatureModel.PROPERTY_PKCS12_PASSWORD), false);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doInit()
     */
    @Override
    public void doInit() {
        final File pkcs12File = getModel().getPkcs12File();
        fileSourceLabel.setText(pkcs12File != null ? pkcs12File.getName() : I18N_NO_FILE_SELECTED);
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
        builder.addSeparator(I18N_CHOOSE_PKCS12_FILE, cc.xyw(2, 2, 5));
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

        if (evt.getPropertyName().equals(SignatureModel.PROPERTY_PKCS12_FILE)) {
            final File pkcs12File = getModel().getPkcs12File();
            final String text = pkcs12File == null ? I18N_NO_FILE_SELECTED : pkcs12File.getName();
            fileSourceLabel.setText(text);
        }
    }
}
