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

package eu.europa.ec.markt.tlmanager.view.panel;

import java.util.Arrays;
import java.util.List;
import java.util.Vector;

import javax.swing.*;

import eu.europa.ec.markt.tsl.jaxb.xades.IdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.ObjectIdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.QualifierType;

/**
 * A small panel for holding the values for CriteriaList PoliciesList elements
 * 
 *
 * @version $Revision$ - $Date$
 */

public class PolicyIdentifierPanel extends javax.swing.JPanel {

    private ObjectIdentifierType model;

    private final ComboBoxModel qualifierModel;

    /**
     * The default constructor for PoliciesListPanel.
     */
    public PolicyIdentifierPanel() {
        final List<QualifierType> qualifierTypeValues = new Vector<QualifierType>(Arrays.asList(QualifierType.values()));
        qualifierTypeValues.add(0, null);
        qualifierModel = new DefaultComboBoxModel(qualifierTypeValues.toArray());
        model = new ObjectIdentifierType();
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        identifierLabel = new javax.swing.JLabel();
        descriptionLabel = new javax.swing.JLabel();
        identifier = new javax.swing.JTextField();
        description = new javax.swing.JTextField();
        qualifierLabel = new javax.swing.JLabel();
        qualifierCombobox = new javax.swing.JComboBox();

        identifierLabel.setText("Identifier");

        descriptionLabel.setText("Description");

        qualifierLabel.setText("Identifier Qualifier Type");

        qualifierCombobox.setModel(qualifierModel);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(descriptionLabel)
                    .addComponent(qualifierLabel)
                    .addComponent(identifierLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(identifier)
                    .addComponent(description, javax.swing.GroupLayout.DEFAULT_SIZE, 245, Short.MAX_VALUE)
                    .addComponent(qualifierCombobox, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(identifierLabel)
                    .addComponent(identifier, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(qualifierLabel)
                    .addComponent(qualifierCombobox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(descriptionLabel)
                    .addComponent(description, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField description;
    private javax.swing.JLabel descriptionLabel;
    private javax.swing.JTextField identifier;
    private javax.swing.JLabel identifierLabel;
    private javax.swing.JComboBox qualifierCombobox;
    private javax.swing.JLabel qualifierLabel;
    // End of variables declaration//GEN-END:variables

    private void resetValuesFromModel() {
        if (model == null) {
            model = new ObjectIdentifierType();
        }
        if (model.getIdentifier() == null) {
            model.setIdentifier(new IdentifierType());
        }
        identifier.setText(model.getIdentifier().getValue());
        description.setText(model.getDescription());
        qualifierCombobox.setSelectedItem(model.getIdentifier().getQualifier());
    }

    private void resetModelFromValues() {
        if (model.getIdentifier() == null) {
            model.setIdentifier(new IdentifierType());
        }
        model.getIdentifier().setValue(identifier.getText());
        model.getIdentifier().setQualifier((QualifierType) qualifierCombobox.getSelectedItem());
        model.setDescription(description.getText());
    }

    /**
     * Empties all values in the model and resets ui components.
     */
    public void clearModel() {
        model = new ObjectIdentifierType();
        resetValuesFromModel();
    }

    /**
     * Resets the component values to the one in the model.
     * 
     * @param model the updated model
     */
    public void updateCurrentValues(ObjectIdentifierType model) {
        this.model = model;
        resetValuesFromModel();
    }

    /**
     * Resets the current values in the model and returns it.
     * 
     * @return the most current model
     */
    public ObjectIdentifierType retrieveCurrentValues() {
        resetModelFromValues();
        return model;
    }
}