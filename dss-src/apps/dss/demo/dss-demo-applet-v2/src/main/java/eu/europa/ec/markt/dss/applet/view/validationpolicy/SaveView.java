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
package eu.europa.ec.markt.dss.applet.view.validationpolicy;

import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.FormLayout;
import eu.europa.ec.markt.dss.applet.model.ValidationPolicyModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.util.ResourceUtils;
import eu.europa.ec.markt.dss.applet.wizard.validationpolicy.ValidationPolicyWizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.io.File;

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
public class SaveView extends WizardView<ValidationPolicyModel, ValidationPolicyWizardController> {

    private static final String I18N_SAVE_TO_FILE = ResourceUtils.getI18n("SAVE_TO_FILE");
    private static final String I18N_NO_FILE_SELECTED = ResourceUtils.getI18n("NO_FILE_SELECTED");
    private static final String I18N_BROWSE = ResourceUtils.getI18n("BROWSE");


    private final JLabel fileTargetLabel;
    private final JButton selectFileTarget;


    /**
     * The default constructor for SaveView.
     *
     * @param core
     * @param controller
     * @param model
     */
    public SaveView(AppletCore core, ValidationPolicyWizardController controller, ValidationPolicyModel model) {
        super(core, controller, model);
        fileTargetLabel = ComponentFactory.createLabel(I18N_NO_FILE_SELECTED);
        selectFileTarget = ComponentFactory.createFileChooser(I18N_BROWSE, true, new SelectFileAEventListener());
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
    private class SelectFileAEventListener implements ActionListener {
        /*
         * (non-Javadoc)
         *
         * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
         */
        @Override
        public void actionPerformed(final ActionEvent e) {
            final JFileChooser chooser = new JFileChooser() {
                @Override
                public void approveSelection() {
                    final File f = getSelectedFile();
                    if (f.exists() && getDialogType() == SAVE_DIALOG) {
                        int result = JOptionPane.showConfirmDialog(this, "The file exists, overwrite?", "Existing file", JOptionPane.YES_NO_CANCEL_OPTION);
                        switch (result) {
                            case JOptionPane.YES_OPTION:
                                super.approveSelection();
                                return;
                            case JOptionPane.NO_OPTION:
                                return;
                            case JOptionPane.CLOSED_OPTION:
                                return;
                            case JOptionPane.CANCEL_OPTION:
                                cancelSelection();
                                return;
                        }
                    }
                    super.approveSelection();
                }
            };
            if (getModel().getTargetFile() != null){
                chooser.setSelectedFile(getModel().getTargetFile());
            }
            final int result = chooser.showSaveDialog(getCore());

            if (result == JFileChooser.APPROVE_OPTION) {
                getModel().setTargetFile(chooser.getSelectedFile());
            }
        }
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

        builder.addSeparator(I18N_SAVE_TO_FILE, cc.xyw(2, 2, 5));
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

        if (evt.getPropertyName().equals(ValidationPolicyModel.PROPERTY_TARGET_FILE)) {
            final File targetFile = getModel().getTargetFile();
            final String text = targetFile == null ? I18N_NO_FILE_SELECTED : targetFile.getName();
            fileTargetLabel.setText(text);
        }

    }
}
