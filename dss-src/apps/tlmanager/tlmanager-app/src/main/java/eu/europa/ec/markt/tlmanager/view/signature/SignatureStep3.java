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

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.tlmanager.core.Configuration;
import eu.europa.ec.markt.tlmanager.view.MainFrame;
import org.jdesktop.swingx.combobox.ListComboBoxModel;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

/**
 * Panel that wraps the controls for the third signature step.
 * 
 *
 * @version $Revision: 2517 $ - $Date: 2013-09-10 09:33:15 +0200 (mar., 10 sept. 2013) $
 */

public class SignatureStep3 extends javax.swing.JPanel {
    private static final ResourceBundle uiKeys = ResourceBundle.getBundle("eu/europa/ec/markt/tlmanager/uiKeys",
            Configuration.getInstance().getLocale());

    private SignatureWizardStep3 wizard;
    private DefaultListModel certificateModel;
    private ComboBoxModel digestAlgorithmsModel;

    /**
     * Instantiates a new signature step3.
     */
    public SignatureStep3() {
        certificateModel = new DefaultListModel();
        digestAlgorithmsModel = new ListComboBoxModel<DigestAlgorithm>(Arrays.asList(DigestAlgorithm.values()));
        initComponents();
        // finally, used shall not be able to choose the digest algorithm
        digestAlgorithmPanel.setVisible(false);
        certificatesTitle.setTitle(uiKeys.getString("SignatureStep3.certificatesTitle.title"));
        outputTitle.setTitle(uiKeys.getString("SignatureStep3.outputTitle.title"));
    }

    /**
     * Instantiates a new signature step3.
     * 
     * @param wizard the related wizard
     */
    public SignatureStep3(final SignatureWizardStep3 wizard) {
        this();
        this.wizard = wizard;

        certificates.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected,
                    boolean cellHasFocus) {
                String label = ((X509Certificate) value).getSubjectX500Principal().toString();

                return super.getListCellRendererComponent(list, label, index, isSelected, cellHasFocus);
            }
        });

        certificates.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    wizard.setSelectedCertificate((Certificate) certificates.getSelectedValue());
                }
            }
        });


        digestAlgorithms.setRenderer((new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected,
                                                          boolean cellHasFocus) {
                String label = ((DigestAlgorithm) value).getName();

                return super.getListCellRendererComponent(list, label, index, isSelected, cellHasFocus);
            }
        }));

        digestAlgorithms.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                wizard.setDigestAlgorithm((DigestAlgorithm) digestAlgorithms.getSelectedItem());
            }
        });
    }

    /**
     * Clears the certificateModel and adds all available certificates.
     * 
     * @param certificates the available certificates
     */
    public void setCertificates(List<Certificate> certificates) {
        certificateModel.clear();
        for (Certificate cert : certificates) {
            certificateModel.addElement(cert);
        }
    }

    /**
     * Preselect the digest algorithm
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm){
        digestAlgorithms.setSelectedItem(digestAlgorithm);
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        descriptionLabel = new javax.swing.JLabel();
        certificatesTitle = new eu.europa.ec.markt.tlmanager.view.common.TitledPanel();
        certificateScrollPane = new javax.swing.JScrollPane();
        certificates = new javax.swing.JList();
        outputTitle = new eu.europa.ec.markt.tlmanager.view.common.TitledPanel();
        targetButton = new javax.swing.JButton();
        targetTextField = new javax.swing.JTextField();
        digestAlgorithmPanel = new eu.europa.ec.markt.tlmanager.view.common.TitledPanel();
        digestAlgorithms = new javax.swing.JComboBox();

        descriptionLabel.setText(uiKeys.getString("SignatureStep3.descriptionLabel.text")); // NOI18N

        certificates.setModel(certificateModel);
        certificateScrollPane.setViewportView(certificates);

        javax.swing.GroupLayout certificatesTitleLayout = new javax.swing.GroupLayout(certificatesTitle);
        certificatesTitle.setLayout(certificatesTitleLayout);
        certificatesTitleLayout.setHorizontalGroup(
            certificatesTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(certificatesTitleLayout.createSequentialGroup().addContainerGap()
                  .addComponent(certificateScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 421, Short.MAX_VALUE)
                  .addContainerGap())
        );
        certificatesTitleLayout.setVerticalGroup(
            certificatesTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(certificatesTitleLayout.createSequentialGroup()
                  .addComponent(certificateScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 68, Short.MAX_VALUE)
                  .addContainerGap())
        );

        targetButton.setText(uiKeys.getString("SignatureStep3.targetButton.text")); // NOI18N
        targetButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                targetButtonActionPerformed(evt);
            }
        });

        targetTextField.setEditable(false);

        javax.swing.GroupLayout outputTitleLayout = new javax.swing.GroupLayout(outputTitle);
        outputTitle.setLayout(outputTitleLayout);
        outputTitleLayout.setHorizontalGroup(
            outputTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(outputTitleLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(targetButton)
                .addGap(18, 18, 18)
                .addComponent(targetTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 354, Short.MAX_VALUE)
                .addContainerGap())
        );
        outputTitleLayout.setVerticalGroup(
            outputTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(outputTitleLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(outputTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(targetButton)
                    .addComponent(targetTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        digestAlgorithmPanel.setName("digestAlgorithPanel"); // NOI18N
        digestAlgorithmPanel.setTitle("Please choose the digest algorithm");

        digestAlgorithms.setModel(digestAlgorithmsModel);

        javax.swing.GroupLayout digestAlgorithmPanelLayout = new javax.swing.GroupLayout(digestAlgorithmPanel);
        digestAlgorithmPanel.setLayout(digestAlgorithmPanelLayout);
        digestAlgorithmPanelLayout.setHorizontalGroup(
            digestAlgorithmPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(digestAlgorithmPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(digestAlgorithms, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        digestAlgorithmPanelLayout.setVerticalGroup(
            digestAlgorithmPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(digestAlgorithmPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(digestAlgorithms, javax.swing.GroupLayout.PREFERRED_SIZE,
                      javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                      .addComponent(certificatesTitle, javax.swing.GroupLayout.DEFAULT_SIZE,
                            javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                      .addComponent(outputTitle, javax.swing.GroupLayout.DEFAULT_SIZE,
                            javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE).addGroup(
                            layout.createSequentialGroup().addComponent(descriptionLabel).addGap(0, 0, Short.MAX_VALUE))
                      .addComponent(digestAlgorithmPanel, javax.swing.GroupLayout.DEFAULT_SIZE,
                            javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(descriptionLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(certificatesTitle, javax.swing.GroupLayout.DEFAULT_SIZE,
                      javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(digestAlgorithmPanel, javax.swing.GroupLayout.PREFERRED_SIZE,
                      javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(outputTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
                      javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void targetButtonActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_targetButtonActionPerformed
        int returnValue = MainFrame.fileChooser.showSaveDialog(getRootPane());
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = MainFrame.fileChooser.getSelectedFile();
            wizard.setTarget(selectedFile);
            targetTextField.setText(selectedFile.getAbsolutePath());
        }
    }// GEN-LAST:event_targetButtonActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JScrollPane certificateScrollPane;
    private javax.swing.JList certificates;
    private eu.europa.ec.markt.tlmanager.view.common.TitledPanel certificatesTitle;
    private javax.swing.JLabel descriptionLabel;
    private eu.europa.ec.markt.tlmanager.view.common.TitledPanel digestAlgorithmPanel;
    private javax.swing.JComboBox digestAlgorithms;
    private eu.europa.ec.markt.tlmanager.view.common.TitledPanel outputTitle;
    private javax.swing.JButton targetButton;
    private javax.swing.JTextField targetTextField;
    // End of variables declaration//GEN-END:variables
}