package eu.europa.ec.markt.dss.applet.view.signature;

import java.awt.Container;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JRadioButton;

import com.jgoodies.binding.beans.BeanAdapter;
import com.jgoodies.binding.list.SelectionInList;
import com.jgoodies.binding.value.ValueHolder;
import com.jgoodies.binding.value.ValueModel;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;

import eu.europa.ec.markt.dss.applet.component.model.AbstractComboBoxModel;
import eu.europa.ec.markt.dss.applet.main.FileType;
import eu.europa.ec.markt.dss.applet.model.FormatType;
import eu.europa.ec.markt.dss.applet.model.SignatureModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.util.ResourceUtils;
import eu.europa.ec.markt.dss.applet.wizard.signature.SignatureWizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
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
public class SignatureView extends WizardView<SignatureModel, SignatureWizardController> {

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
    private final class FormatEventListener implements PropertyChangeListener {
        /*
         * (non-Javadoc)
         * 
         * @see java.beans.PropertyChangeListener#propertyChange(java.beans.PropertyChangeEvent)
         */
        @Override
        public void propertyChange(final PropertyChangeEvent evt) {
            getModel().setFormat((String) evt.getNewValue());
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
    private final class LevelComboBoxModel extends AbstractComboBoxModel {

        /*
         * (non-Javadoc)
         * 
         * @see eu.europa.ec.markt.dss.applet.model.AbstractComboBoxModel#getElements()
         */
        @Override
        protected List<?> getElements() {
            final SignatureModel model = getModel();
            final String signatureFormat = model.getFormat();

            final List<String> elements = new ArrayList<String>();
            if ("PAdES".equals(signatureFormat)) {
                elements.add("PAdES-BES");
                elements.add("PAdES-EPES");
                elements.add("PAdES-LTV");
            } else if ("CAdES".equals(signatureFormat)) {
                elements.add("CAdES-BES");
                elements.add("CAdES-EPES");
                elements.add("CAdES-T");
                elements.add("CAdES-C");
                elements.add("CAdES-X");
                elements.add("CAdES-XL");
                elements.add("CAdES-A");
            } else if ("XAdES".equals(signatureFormat)) {
                elements.add("XAdES-BES");
                elements.add("XAdES-EPES");
                elements.add("XAdES-T");
                elements.add("XAdES-C");
                elements.add("XAdES-X");
                elements.add("XAdES-XL");
                elements.add("XAdES-A");
            } else if ("ASiC-S".equals(signatureFormat)) {
                elements.add("ASiC-S-BES");
                elements.add("ASiC-S-EPES");
                elements.add("ASiC-S-T");
            }
            return elements;

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
    private final class PackagingEventListener implements PropertyChangeListener {
        /*
         * (non-Javadoc)
         * 
         * @see java.beans.PropertyChangeListener#propertyChange(java.beans.PropertyChangeEvent)
         */
        @Override
        public void propertyChange(final PropertyChangeEvent evt) {
            getModel().setPackaging((SignaturePackaging) evt.getNewValue());
        }

    }

    private static final String I18N_ENVELOPING = ResourceUtils.getI18n("ENVELOPING");
    private static final String I18N_ENVELOPED = ResourceUtils.getI18n("ENVELOPED");
    private static final String I18N_DETACHED = ResourceUtils.getI18n("DETACHED");

    private final JRadioButton cadesButton;
    private final JRadioButton xadesButton;
    private final JRadioButton padesButton;
    private final JRadioButton asicsButton;
    private final JRadioButton envelopingButton;
    private final JRadioButton envelopedButton;
    private final JRadioButton detachedButton;
    private final JComboBox levelComboBox;

    private final ValueHolder formatValueHolder;
    private final ValueHolder packagingValueHolder;
    private final ValueModel levelValue;

    /**
     * 
     * The default constructor for SignatureView.
     * 
     * @param core
     * @param controller
     * @param model
     */
    public SignatureView(final AppletCore core, final SignatureWizardController controller, final SignatureModel model) {
        super(core, controller, model);

        final BeanAdapter<SignatureModel> beanAdapter = new BeanAdapter<SignatureModel>(model);

        formatValueHolder = new ValueHolder(model.getFormat());
        formatValueHolder.addPropertyChangeListener(new FormatEventListener());

        cadesButton = ComponentFactory.createRadioButton(FormatType.CADES, formatValueHolder, FormatType.CADES);
        xadesButton = ComponentFactory.createRadioButton(FormatType.XADES, formatValueHolder, FormatType.XADES);
        padesButton = ComponentFactory.createRadioButton(FormatType.PADES, formatValueHolder, FormatType.PADES);
        asicsButton = ComponentFactory.createRadioButton(FormatType.ASICS, formatValueHolder, FormatType.ASICS);

        packagingValueHolder = new ValueHolder(model.getPackaging());
        packagingValueHolder.addPropertyChangeListener(new PackagingEventListener());

        envelopingButton = ComponentFactory.createRadioButton(I18N_ENVELOPING, packagingValueHolder, SignaturePackaging.ENVELOPING);
        envelopedButton = ComponentFactory.createRadioButton(I18N_ENVELOPED, packagingValueHolder, SignaturePackaging.ENVELOPED);
        detachedButton = ComponentFactory.createRadioButton(I18N_DETACHED, packagingValueHolder, SignaturePackaging.DETACHED);

        levelValue = beanAdapter.getValueModel(SignatureModel.PROPERTY_LEVEL);
        final SelectionInList<String> levels = new SelectionInList<String>(new LevelComboBoxModel(), levelValue);
        levelComboBox = ComponentFactory.createComboBox(levels);
    }

    private JPanel doFormatLayout() {
        return ComponentFactory.createPanel(cadesButton, xadesButton, padesButton, asicsButton);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doInit()
     */
    @Override
    public void doInit() {
        final SignatureModel model = getModel();
        final SignaturePackaging packaging = model.getPackaging();
        final String format = model.getFormat();
        final FileType fileType = model.getFileType();

        padesButton.setEnabled(FileType.PDF == fileType);

        formatValueHolder.setValue(format);
        packagingValueHolder.setValue(packaging);
        levelValue.setValue(model.getLevel());

    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doInit()
     */
    @Override
    protected Container doLayout() {

        final JPanel formatPanel = doFormatLayout();
        final JPanel packagingPanel = doPackagingLayout();
        final JPanel levelPanel = doLevelLayout();

        final FormLayout layout = new FormLayout("5dlu,pref:grow ,5dlu", "5dlu, pref, 5dlu, pref, 5dlu, pref, 5dlu,pref, 5dlu,pref, 5dlu, pref, 5dlu");
        final PanelBuilder builder = ComponentFactory.createBuilder(layout);
        final CellConstraints cc = new CellConstraints();
        builder.addSeparator(ResourceUtils.getI18n("SIGNATURE_FORMAT"), cc.xyw(2, 2, 1));
        builder.add(formatPanel, cc.xyw(2, 4, 1));
        builder.addSeparator(ResourceUtils.getI18n("PACKAGING"), cc.xyw(2, 6, 1));
        builder.add(packagingPanel, cc.xyw(2, 8, 1));
        builder.addSeparator(ResourceUtils.getI18n("LEVEL"), cc.xyw(2, 10, 1));
        builder.add(levelPanel, cc.xy(2, 12));
        return ComponentFactory.createPanel(builder);
    }

    private JPanel doLevelLayout() {
        final FormLayout layout = new FormLayout("5dlu, fill:default:grow, 5dlu", "5dlu, pref, 5dlu");
        final PanelBuilder builder = ComponentFactory.createBuilder(layout);
        final CellConstraints cc = new CellConstraints();
        builder.add(levelComboBox, cc.xy(2, 2));
        return ComponentFactory.createPanel(builder);
    }

    private JPanel doPackagingLayout() {
        return ComponentFactory.createPanel(envelopingButton, envelopedButton, detachedButton);
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
        if (SignatureModel.PROPERTY_FORMAT.equals(evt.getPropertyName())) {

            final String format = getModel().getFormat();

            if (FormatType.CADES.equals(format)) {
                envelopingButton.setEnabled(true);
                detachedButton.setEnabled(true);
                envelopedButton.setEnabled(false);
                if (envelopedButton.isSelected()) {
                    envelopedButton.setSelected(false);
                }
                envelopingButton.doClick();
            }

            if (FormatType.PADES.equals(format)) {
                envelopingButton.setEnabled(false);
                detachedButton.setEnabled(false);
                envelopedButton.setEnabled(true);
                if (envelopingButton.isSelected() || detachedButton.isSelected()) {
                    envelopingButton.setSelected(false);
                    detachedButton.setSelected(false);
                }
                envelopedButton.doClick();
            }

            if (FormatType.XADES.equals(format)) {
                envelopingButton.setEnabled(true);
                detachedButton.setEnabled(true);
                envelopedButton.setEnabled(FileType.XML == getModel().getFileType());

                if (envelopedButton.isSelected()) {
                    envelopedButton.setSelected(false);
                }

                envelopingButton.doClick();
            }

            if (FormatType.ASICS.equals(format)) {
                envelopingButton.setEnabled(false);
                detachedButton.setEnabled(true);
                envelopedButton.setEnabled(false);
                if (envelopedButton.isSelected() || envelopingButton.isSelected()) {
                    envelopingButton.setSelected(false);
                    envelopedButton.setSelected(false);
                }
                detachedButton.doClick();
            }

            levelComboBox.setSelectedIndex(-1);
        }

    }
}
