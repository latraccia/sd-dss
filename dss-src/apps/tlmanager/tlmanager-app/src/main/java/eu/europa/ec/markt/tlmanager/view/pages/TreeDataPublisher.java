/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.tlmanager.view.pages;

import eu.europa.ec.markt.tlmanager.core.Configuration;
import eu.europa.ec.markt.tlmanager.model.TSLTreeModel;
import eu.europa.ec.markt.tlmanager.model.treeNodes.TSLDataNode;
import eu.europa.ec.markt.tlmanager.util.Util;
import eu.europa.ec.markt.tlmanager.view.binding.BindingManager;
import eu.europa.ec.markt.tlmanager.view.certificate.CertificateProperty;
import eu.europa.ec.markt.tlmanager.view.certificate.ServiceDigitalIdentityPanel;
import eu.europa.ec.markt.tlmanager.view.common.DateTimePicker;
import eu.europa.ec.markt.tlmanager.view.multivalue.MandatoryLabelHandler;
import eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton;
import org.apache.commons.lang.StringUtils;
import org.jdesktop.swingx.JXDatePicker;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

/**
 * An abstract class for all classes that react to changes in the JTree.
 * 
 *
 * @version $Revision: 2550 $ - $Date: 2013-09-17 14:17:10 +0200 (mar., 17 sept. 2013) $
 */

public abstract class TreeDataPublisher extends JPanel implements MandatoryLabelHandler {
    public static final String POINTER_TO_OTHER_TSL_PAGE = "PointerToOtherTSLPage";
    public static final String QUALIFICATION_EXTENSION_PAGE = "QualificationExtensionPage";
    public static final String SERVICE_CURRENT_STATUS_INFORMATION_PAGE = "ServiceCurrentStatusInformationPage";
    public static final String SERVICE_INFORMATION_EXTENSION_PAGE = "ServiceInformationExtensionPage";
    public static final String SERVICE_STATUS_HISTORY_PAGE = "ServiceStatusHistoryPage";
    public static final String TSL_INFORMATION_PAGE = "TSLInformationPage";
    public static final String TSP_INFORMATION_PAGE = "TSPInformationPage";

    protected static final ResourceBundle uiKeys = ResourceBundle.getBundle("eu/europa/ec/markt/tlmanager/uiKeys",
            Configuration.getInstance().getLocale());
    protected BindingManager bindingManager;
    private List<JLabel> mandatoryLabels;
    protected JTree tree;
    protected TSLDataNode dataNode;

    /**
     * The default constructor for TreeDataPublisher.
     */
    public TreeDataPublisher() {
        super();
        setName();
    }

    /**
     * Another constructor for TreeDataPublisher.
     *
     * @param tree the tree
     */
    public TreeDataPublisher(JTree tree) {
        this();
        this.tree = tree;
    }

    /**
     * Updates the associated visual representation with the provided data.
     *
     * @param data data to show
     */
    public abstract void updateViewFromData(TSLDataNode data);

    /**
     * Called by constructor and helps to ensure that all instances have set a name.
     */
    public abstract void setName();

    /**
     * Convenience method that helps collecting all the mandatory <code>JLabel</code>'s and set a common attribute: red
     * as foreground color.
     *
     * @param label the label to add
     */
    protected void setMandatoryLabel(JLabel label) {
        label.setForeground(Color.red);
        mandatoryLabels.add(label);
    }

    /**
     * Add all used <code>JLabel</code> that are associated to components which have mandatory values.
     */
    protected abstract void setupMandatoryLabels();

    /**
     * Attaches listeners to components, whose content influences the label that is displayed in the tree. This has to
     * be done explicitely to call {@link TSLDataNode#resetLabel()}, otherwise the cached label is not renewed.
     */
    protected void setupListenersForTreeLabelComponents() {
        // default implementation does nothing :)
    }

    /**
     * Does additional setup: - Fishes for all <code>MultivalueButton</code> that are available somewhere in the
     * component hierarchy and attaches this as a <code>MandatoryLabelHandler</code>.<br>
     * - Calls {@link #setupMandatoryLabels()}<br>
     */
    protected void additionalSetup() {
        List<Component> allComponents = Util.getAllComponents(this);
        for (Component comp : allComponents) {
            if (comp instanceof MultivalueButton) {
                MultivalueButton button = (MultivalueButton) comp;
                button.setLabelHandler(this);
            } else if (comp instanceof ServiceDigitalIdentityPanel) {
                ServiceDigitalIdentityPanel serviceDigitalIdentityPanel = (ServiceDigitalIdentityPanel) comp;
                serviceDigitalIdentityPanel.setLabelHandler(this);
            }
        }

        if (mandatoryLabels == null) {
            mandatoryLabels = new ArrayList<JLabel>();
        }

        setupMandatoryLabels();
        setupListenersForTreeLabelComponents();
    }

    /**
     * This method handles the state of the <code>JLabel</code>'s that are associated to mandatory fields, as well as
     * any 'special' component. It is called via two tracks: Once by the implementation of the
     * <code>BindingListener</code> in <code>BindingManager</code> and once by individual action listeners for each
     * component. These action listeners are installed at the same time of the installation of the binding (cf.
     * BindingManager.setupComponent()).
     *
     * @param component the component
     * @param failure if the label should express a failure
     */
    protected void changeMandatoryComponents(Component component, boolean failure) {
        if (mandatoryLabels == null) {
            return;
        }
        for (JLabel label : mandatoryLabels) {
            if (label == null || component == null || label.getLabelFor() == null) {
                continue;
            }
            if (label.getLabelFor().equals(component)) {
                boolean empty = false;
                if (component instanceof JTextField) {
                    JTextField tf = (JTextField) component;
                    if (tf.getText().isEmpty()) {
                        empty = true;
                    }
                } else if (component instanceof JComboBox) {
                    JComboBox box = (JComboBox) component;
                    if (box.isEditable()) {
                        final String text = ((JTextComponent) box.getEditor().getEditorComponent()).getText();
                        if (StringUtils.isEmpty(text) || StringUtils.equals(text, Util.DEFAULT_NO_SELECTION_ENTRY)) {
                            empty = true;
                        }
                    } else {
                        if (box.getSelectedItem().equals(Util.DEFAULT_NO_SELECTION_ENTRY)) {
                            empty = true;
                        }
                    }
                } else if (component instanceof JXDatePicker) {
                    JXDatePicker picker = (JXDatePicker) component;
                    Date date = picker.getDate();
                    if (date == null) {
                        empty = true;
                    }
                } else if (component instanceof DateTimePicker) {
                    DateTimePicker picker = (DateTimePicker) component;
                    Date date = picker.getDateTime();
                    if (date == null) {
                        empty = true;
                    }
                } else if (component instanceof MultivalueButton) {
                    MultivalueButton button = (MultivalueButton) component;
                    if (button.getMultivaluePanel().getMultivalueModel().isEmpty()) {
                        empty = true;
                    }
                } else if (component instanceof CertificateProperty) {
                    CertificateProperty certificateProperty = (CertificateProperty) component;
                    empty = certificateProperty.isEmpty();
                }

                if (failure || empty) {
                    label.setForeground(Configuration.MANDATORY_COLOR);
                } else {
                    label.setForeground(Configuration.NORMAL_COLOR);
                }
                break;
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void handleLabelStateFor(Component component, boolean empty) {
        changeMandatoryComponents(component, empty);

        // Note: if there has something changed in a component, it may be interesting for the tree too
        // e.g. if the pointer-schemeTerritory selection was changed, that shall be reflected directly
        TSLTreeModel model = (TSLTreeModel) tree.getModel();
        model.fireNodeChanged(tree.getSelectionPath());
    }

}