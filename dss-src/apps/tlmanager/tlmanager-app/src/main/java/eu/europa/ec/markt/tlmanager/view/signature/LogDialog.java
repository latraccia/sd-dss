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

package eu.europa.ec.markt.tlmanager.view.signature;

import eu.europa.ec.markt.tlmanager.core.Configuration;
import eu.europa.ec.markt.tlmanager.core.validation.ValidationLogger;
import eu.europa.ec.markt.tlmanager.core.validation.ValidationLogger.Message;
import eu.europa.ec.markt.tlmanager.util.Util;
import eu.europa.ec.markt.tlmanager.view.MainFrame;

import java.util.List;
import java.util.ResourceBundle;

import javax.swing.DefaultListModel;
import javax.swing.JDialog;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

/**
 * A dialog for holding validation logs.
 * 
 *
 * @version $Revision: 1168 $ - $Date: 2012-03-05 12:28:27 +0100 (lun., 05 mars 2012) $
 */

public class LogDialog extends JDialog {
    private static final ResourceBundle uiKeys = ResourceBundle.getBundle("eu/europa/ec/markt/tlmanager/uiKeys",
            Configuration.getInstance().getLocale());

    private MainFrame mainFrame;
    private DefaultListModel validationItemModel;
    private MessageLabelRenderer itemLabelRenderer;
    private boolean isRefreshing = false;

    /**
     * Instantiates a new log dialog.
     * 
     * @param parent the parent
     * @param modal the modal
     */
    public LogDialog(java.awt.Frame parent, boolean modal) {
        super(parent, modal);
        setTitle(uiKeys.getString("LogDialog.title"));
        validationItemModel = new DefaultListModel();
        itemLabelRenderer = new MessageLabelRenderer();

        initComponents();
        logTitle.setTitle(uiKeys.getString("LogDialog.title"));

        validationLog.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        validationLog.setCellRenderer(itemLabelRenderer);
        validationLog.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting() && !isRefreshing) {
                    Message selectedMessage = (Message) validationLog.getSelectedValue();
                    mainFrame.alignTreeSelectionToValidationMessage(selectedMessage.getParentPanelObject());
                }
            }
        });
    }

    /**
     * The default constructor for LogDialog.
     * 
     * @param parent the parent frame
     * @param modal model or not
     * @param mainFrame the mainFrame
     * @param messages any validation messages
     */
    public LogDialog(java.awt.Frame parent, boolean modal, MainFrame mainFrame,
            List<ValidationLogger.Message> messages) {
        this(parent, modal);

        this.mainFrame = mainFrame;
        setValidationMessages(messages);
    }

    /**
     * Clears the validationItemModel and adds all available validation items.
     * 
     * @param messages the available messages
     */
    public void setValidationMessages(List<ValidationLogger.Message> messages) {
        isRefreshing = true;
        validationItemModel.clear();
        for (Message msg : messages) {
            validationItemModel.addElement(msg);
        }
        isRefreshing = false;
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        logTitle = new eu.europa.ec.markt.tlmanager.view.common.TitledPanel();
        validationLogScrollPane = new javax.swing.JScrollPane();
        validationLog = new javax.swing.JList();
        closeButton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        validationLog.setModel(validationItemModel);
        validationLogScrollPane.setViewportView(validationLog);

        javax.swing.GroupLayout logTitleLayout = new javax.swing.GroupLayout(logTitle);
        logTitle.setLayout(logTitleLayout);
        logTitleLayout.setHorizontalGroup(logTitleLayout.createParallelGroup(
                javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                logTitleLayout
                        .createSequentialGroup()
                        .addContainerGap()
                        .addComponent(validationLogScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 572,
                                Short.MAX_VALUE).addContainerGap()));
        logTitleLayout.setVerticalGroup(logTitleLayout
                .createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                        logTitleLayout
                                .createSequentialGroup()
                                .addComponent(validationLogScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 176,
                                        Short.MAX_VALUE).addContainerGap()));

        closeButton.setText(uiKeys.getString("LogDialog.close")); // NOI18N
        closeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                closeButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                javax.swing.GroupLayout.Alignment.TRAILING,
                layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(
                                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                        .addComponent(logTitle, javax.swing.GroupLayout.Alignment.LEADING,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(closeButton, javax.swing.GroupLayout.Alignment.LEADING,
                                                javax.swing.GroupLayout.DEFAULT_SIZE, 604, Short.MAX_VALUE))
                        .addContainerGap()));
        layout.setVerticalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                javax.swing.GroupLayout.Alignment.TRAILING,
                layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(logTitle, javax.swing.GroupLayout.DEFAULT_SIZE,
                                javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(closeButton).addContainerGap()));

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void closeButtonActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_closeButtonActionPerformed
        Util.closeDialog(evt);
    }// GEN-LAST:event_closeButtonActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                LogDialog dialog = new LogDialog(new javax.swing.JFrame(), true);
                dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        System.exit(0);
                    }
                });
                dialog.setVisible(true);

            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton closeButton;
    private eu.europa.ec.markt.tlmanager.view.common.TitledPanel logTitle;
    private javax.swing.JList validationLog;
    private javax.swing.JScrollPane validationLogScrollPane;
    // End of variables declaration//GEN-END:variables
}