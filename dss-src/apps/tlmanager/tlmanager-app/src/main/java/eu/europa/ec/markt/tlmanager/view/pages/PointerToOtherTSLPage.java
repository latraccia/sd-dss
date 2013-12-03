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

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.Serializable;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.*;
import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;

import eu.europa.ec.markt.tlmanager.core.Configuration;
import eu.europa.ec.markt.tlmanager.core.QNames;
import eu.europa.ec.markt.tlmanager.model.treeNodes.TSLDataNode;
import eu.europa.ec.markt.tlmanager.util.Util;
import eu.europa.ec.markt.tlmanager.view.binding.BindingManager;
import eu.europa.ec.markt.tlmanager.view.binding.InternationalNamesConverter;
import eu.europa.ec.markt.tlmanager.view.binding.NonEmptyMultiLangURIListConverter;
import eu.europa.ec.markt.tlmanager.view.binding.NonEmptyURIListToStringConverter;
import eu.europa.ec.markt.tlmanager.view.multivalue.MultiMode;
import eu.europa.ec.markt.tlmanager.view.multivalue.MultivaluePanel;
import eu.europa.ec.markt.tlmanager.view.multivalue.content.ServiceDigitalIdentitiesMultivalueAdapter;
import eu.europa.ec.markt.tsl.jaxb.tsl.AnyType;
import eu.europa.ec.markt.tsl.jaxb.tsl.InternationalNamesType;
import eu.europa.ec.markt.tsl.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.NonEmptyMultiLangURIType;
import eu.europa.ec.markt.tsl.jaxb.tsl.OtherTSLPointerType;

/**
 * Content page for managing all below a <tsl:OtherTSLPointer/>.
 * 
 * 
 * @version $Revision: 2840 $ - $Date: 2013-11-04 12:30:49 +0100 (lun., 04 nov. 2013) $
 */

public class PointerToOtherTSLPage extends TreeDataPublisher {

    private static final Logger LOG = Logger.getLogger(PointerToOtherTSLPage.class.getName());

    private DefaultComboBoxModel schemeTerritoryModel;
    private DefaultComboBoxModel tslTypeModel;
    private DefaultComboBoxModel mimeTypeModel;

    /**
     * Instantiates a new pointer to other tsl page.
     */
    public PointerToOtherTSLPage(JTree jtree) {
        super(jtree);
        String[] territoryItems = Util.addNoSelectionEntry(Configuration.getInstance().getCountryCodes().getCodes());
        schemeTerritoryModel = new DefaultComboBoxModel(territoryItems);
        String[] tslTypeItems = new String[]{Configuration.getInstance().getTSL().getTslTypeInverse()};
        tslTypeModel = new DefaultComboBoxModel(tslTypeItems);

        String[] mimeTypeItems = Util.addNoSelectionEntry(Configuration.getInstance().getMimeTypes());
        mimeTypeModel = new DefaultComboBoxModel(mimeTypeItems);
        initComponents();
        pointerTitle.setTitle(uiKeys.getString("PointerToOtherTSLPage.pointerTitle.title"));
        toggleMode();
        initBinding();

        additionalSetup();
    }

    /** {@inheritDoc} */
    @Override
    protected void setupListenersForTreeLabelComponents() {
        schemeTerritory.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (!bindingManager.isBindingInProgress() && e.getStateChange() == ItemEvent.SELECTED
                        && dataNode != null) {
                    dataNode.resetLabel();
                }
            }
        });

        tslLocation.addKeyListener(new KeyAdapter() {
            @Override
            public void keyTyped(KeyEvent e) {
                if (dataNode != null) {
                    dataNode.resetLabel();
                }
            }
        });
    }

    /** {@inheritDoc} */
    @Override
    public void setName() {
        setName(TreeDataPublisher.POINTER_TO_OTHER_TSL_PAGE);
    }

    /** {@inheritDoc} */
    @Override
    protected void setupMandatoryLabels() {
        setMandatoryLabel(digitalIdLabel);
        setMandatoryLabel(tslLocationLabel);
        setMandatoryLabel(schemeOperatorNameLabel);
        if (!Configuration.getInstance().isTlMode()) {
            setMandatoryLabel(schemeTypeCommunityRuleLabel);
        }
        setMandatoryLabel(schemeTerritoryLabel);
        setMandatoryLabel(mimeTypeLabel);
    }

    private void toggleMode() {
        if (Configuration.getInstance().isTlMode()) {
            schemeTypeCommunityRuleTL = new JTextField();
            schemeTypeCommunityRuleTL.setEditable(false);
            schemeTypeCommunityRuleLabel.setLabelFor(schemeTypeCommunityRuleTL);

            schemeTypeCommunityRuleComponent = schemeTypeCommunityRuleTL;
        } else {
            schemeTypeCommunityRuleLOTL = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(
                    MultiMode.MULTILANG_COMBOBOX, null, Util.addNoSelectionEntry(Configuration.getInstance().getTL()
                            .getTslSchemeTypeCommunityRules()));
            schemeTypeCommunityRuleLabel.setLabelFor(schemeTypeCommunityRuleLOTL);

            schemeTypeCommunityRuleComponent = schemeTypeCommunityRuleLOTL;
        }

        schemeTypeCommunityRuleContainer.removeAll();
        schemeTypeCommunityRuleContainer.setLayout(new BorderLayout());
        schemeTypeCommunityRuleContainer.add(schemeTypeCommunityRuleComponent, BorderLayout.CENTER);
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        pointerTitle = new eu.europa.ec.markt.tlmanager.view.common.TitledPanel();
        digitalIdLabel = new javax.swing.JLabel();
        tslLocationLabel = new javax.swing.JLabel();
        tslLocation = new javax.swing.JTextField();
        schemeOperatorNameLabel = new javax.swing.JLabel();
        schemeOperatorName = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTILANG_TEXT, Configuration.LanguageCodes.getEnglishLanguage(), null);
        schemeTypeCommunityRuleLabel = new javax.swing.JLabel();
        schemeTypeCommunityRuleContainer = new javax.swing.JPanel();
        schemeTerritoryLabel = new javax.swing.JLabel();
        schemeTerritory = new javax.swing.JComboBox();
        mimeTypeLabel = new javax.swing.JLabel();
        mimeType = new javax.swing.JComboBox();
        digitalIdButton = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTI_SERVICE_ID, null, null);
        jLabel1 = new javax.swing.JLabel();
        tslType = new javax.swing.JComboBox();

        pointerTitle.setName("pointerTitle"); // NOI18N

        digitalIdLabel.setLabelFor(digitalIdButton);
        digitalIdLabel.setText(uiKeys.getString("PointerToOtherTSLPage.digitalIdLabel.text")); // NOI18N

        tslLocationLabel.setLabelFor(tslLocation);
        tslLocationLabel.setText(uiKeys.getString("PointerToOtherTSLPage.tslLocationLabel.text")); // NOI18N

        tslLocation.setName("tslLocation"); // NOI18N

        schemeOperatorNameLabel.setLabelFor(schemeOperatorName);
        schemeOperatorNameLabel.setText(uiKeys.getString("PointerToOtherTSLPage.schemeOperatorNameLabel.text")); // NOI18N

        schemeOperatorName.setName("schemeOperatorName"); // NOI18N

        schemeTypeCommunityRuleLabel.setText(uiKeys.getString("PointerToOtherTSLPage.schemeTypeCommunityRuleLabel.text")); // NOI18N

        schemeTypeCommunityRuleContainer.setMinimumSize(new java.awt.Dimension(0, 0));
        schemeTypeCommunityRuleContainer.setName("schemeTypeCommunityRuleContainer"); // NOI18N

        javax.swing.GroupLayout schemeTypeCommunityRuleContainerLayout = new javax.swing.GroupLayout(schemeTypeCommunityRuleContainer);
        schemeTypeCommunityRuleContainer.setLayout(schemeTypeCommunityRuleContainerLayout);
        schemeTypeCommunityRuleContainerLayout.setHorizontalGroup(
            schemeTypeCommunityRuleContainerLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 396, Short.MAX_VALUE)
        );
        schemeTypeCommunityRuleContainerLayout.setVerticalGroup(
            schemeTypeCommunityRuleContainerLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 23, Short.MAX_VALUE)
        );

        schemeTerritoryLabel.setLabelFor(schemeTerritory);
        schemeTerritoryLabel.setText(uiKeys.getString("PointerToOtherTSLPage.schemeTerritoryLabel.text")); // NOI18N

        schemeTerritory.setEditable(!Configuration.getInstance().isEuMode());
        schemeTerritory.setModel(schemeTerritoryModel);
        schemeTerritory.setName("schemeTerritory"); // NOI18N

        mimeTypeLabel.setLabelFor(mimeType);
        mimeTypeLabel.setText(uiKeys.getString("PointerToOtherTSLPage.mimeTypeLabel.text")); // NOI18N

        mimeType.setModel(mimeTypeModel);
        mimeType.setName("mimeType"); // NOI18N

        digitalIdButton.setName("digitalId"); // NOI18N

        jLabel1.setText("TSL Type");

        tslType.setEditable(!Configuration.getInstance().isEuMode());
        tslType.setModel(tslTypeModel);
        tslType.setName("tslType"); // NOI18N

        javax.swing.GroupLayout pointerTitleLayout = new javax.swing.GroupLayout(pointerTitle);
        pointerTitle.setLayout(pointerTitleLayout);
        pointerTitleLayout.setHorizontalGroup(
            pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pointerTitleLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(pointerTitleLayout.createSequentialGroup()
                        .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(tslLocationLabel)
                            .addComponent(schemeOperatorNameLabel)
                            .addComponent(schemeTypeCommunityRuleLabel)
                            .addComponent(digitalIdLabel))
                        .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(pointerTitleLayout.createSequentialGroup()
                                .addGap(18, 18, 18)
                                .addComponent(schemeTypeCommunityRuleContainer, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 31, Short.MAX_VALUE))
                            .addGroup(pointerTitleLayout.createSequentialGroup()
                                .addGap(21, 21, 21)
                                .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(tslLocation)
                                    .addGroup(pointerTitleLayout.createSequentialGroup()
                                        .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                                .addComponent(digitalIdButton, javax.swing.GroupLayout.DEFAULT_SIZE, 222, Short.MAX_VALUE)
                                                .addComponent(schemeTerritory, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(mimeType, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(schemeOperatorName, javax.swing.GroupLayout.DEFAULT_SIZE, 222, Short.MAX_VALUE))
                                            .addComponent(tslType, javax.swing.GroupLayout.PREFERRED_SIZE, 394, javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addGap(0, 0, Short.MAX_VALUE))))))
                    .addGroup(pointerTitleLayout.createSequentialGroup()
                        .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(schemeTerritoryLabel)
                            .addComponent(mimeTypeLabel)
                            .addComponent(jLabel1))
                        .addGap(0, 0, Short.MAX_VALUE))))
        );
        pointerTitleLayout.setVerticalGroup(
            pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(pointerTitleLayout.createSequentialGroup()
                .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(schemeTypeCommunityRuleContainer, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(pointerTitleLayout.createSequentialGroup()
                        .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(digitalIdLabel)
                            .addComponent(digitalIdButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(18, 18, 18)
                        .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel1)
                            .addComponent(tslType, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(18, 18, 18)
                        .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(tslLocation, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(tslLocationLabel))
                        .addGap(29, 29, 29)
                        .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(schemeOperatorNameLabel)
                            .addComponent(schemeOperatorName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(23, 23, 23)
                        .addComponent(schemeTypeCommunityRuleLabel)))
                .addGap(18, 18, 18)
                .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(schemeTerritoryLabel)
                    .addComponent(schemeTerritory, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(30, 30, 30)
                .addGroup(pointerTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(mimeTypeLabel)
                    .addComponent(mimeType, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(pointerTitle, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(pointerTitle, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton digitalIdButton;
    private javax.swing.JLabel digitalIdLabel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JComboBox mimeType;
    private javax.swing.JLabel mimeTypeLabel;
    private eu.europa.ec.markt.tlmanager.view.common.TitledPanel pointerTitle;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeOperatorName;
    private javax.swing.JLabel schemeOperatorNameLabel;
    private javax.swing.JComboBox schemeTerritory;
    private javax.swing.JLabel schemeTerritoryLabel;
    private javax.swing.JPanel schemeTypeCommunityRuleContainer;
    private javax.swing.JLabel schemeTypeCommunityRuleLabel;
    private javax.swing.JTextField tslLocation;
    private javax.swing.JLabel tslLocationLabel;
    private javax.swing.JComboBox tslType;
    // End of variables declaration//GEN-END:variables

    // custom components
    private JComponent schemeTypeCommunityRuleComponent;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeTypeCommunityRuleLOTL;
    private javax.swing.JTextField schemeTypeCommunityRuleTL;

    private void initBinding() {
        if (bindingManager == null) {
            bindingManager = new BindingManager(this);
        }

        bindingManager.createBindingForComponent(tslLocation, "TSLLocation", QNames._TSLLocation);

        bindingManager.createBindingForComponent(digitalIdButton.getMultivaluePanel(), "value",
                QNames._ServiceDigitalIdentities_QNAME.getLocalPart());
        bindingManager.createBindingForComponent(schemeOperatorName.getMultivaluePanel(), "value",
                QNames._SchemeOperatorName_QNAME.getLocalPart());
        bindingManager.appendConverter(new InternationalNamesConverter(),
                QNames._SchemeOperatorName_QNAME.getLocalPart());

        if (Configuration.getInstance().isTlMode()) {
            bindingManager.createBindingForComponent(schemeTypeCommunityRuleTL, "value",
                    QNames._SchemeTypeCommunityRules_QNAME.getLocalPart());
            bindingManager.appendConverter(new NonEmptyURIListToStringConverter(),
                    QNames._SchemeTypeCommunityRules_QNAME.getLocalPart());
        } else {
            bindingManager.createBindingForComponent(schemeTypeCommunityRuleLOTL.getMultivaluePanel(), "value",
                    QNames._SchemeTypeCommunityRules_QNAME.getLocalPart());
            bindingManager.appendConverter(new NonEmptyMultiLangURIListConverter(),
                    QNames._SchemeTypeCommunityRules_QNAME.getLocalPart());
        }

        bindingManager.createBindingForComponent(schemeTerritory, "value", QNames._SchemeTerritory_QNAME.getLocalPart());
        bindingManager.createBindingForComponent(mimeType, "value", QNames._MimeType_QNAME.getLocalPart());
        bindingManager.createBindingForComponent(tslType, "value", QNames._TSLType_QNAME.getLocalPart());

    }

    private Object getAdditionalDataNode(QName qname) {
        OtherTSLPointerType pointer = (OtherTSLPointerType) dataNode.getUserObject();
        List<Serializable> textualInformationOrOtherInformation = pointer.getAdditionalInformation()
                .getTextualInformationOrOtherInformation();
        for (Object obj : textualInformationOrOtherInformation) {
            if (obj instanceof AnyType) {
                AnyType anyType = (AnyType) obj;
                List<Object> content = anyType.getContent();
                JAXBElement<Object> element = null;
                if (content.isEmpty()) {
                    continue;
                }
                Object object = content.get(0);
                if (object != null && object instanceof JAXBElement<?>) {
                    element = (JAXBElement<Object>) object;
                }
                if (element != null && object != null) {
                    // tsl:SchemeOperatorName
                    if (element.getName().getLocalPart().equals(qname.getLocalPart())) {
                        return object;
                    }
                }
            }
        }
        return null;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    public void updateViewFromData(TSLDataNode dataNode) {
        this.dataNode = dataNode;
        OtherTSLPointerType pointer = (OtherTSLPointerType) dataNode.getUserObject();
        LOG.log(Level.FINE, "Value changed {0}", pointer);
        bindingManager.unbindAll();

        ServiceDigitalIdentitiesMultivalueAdapter serviceDigitalIdentitiesMultivalueAdapter = new ServiceDigitalIdentitiesMultivalueAdapter(pointer.getServiceDigitalIdentities());
        LOG.info("Model for digitalId " + serviceDigitalIdentitiesMultivalueAdapter);
        final MultivaluePanel multivaluePanel = digitalIdButton.getMultivaluePanel();
        multivaluePanel.setMultivalueModel(serviceDigitalIdentitiesMultivalueAdapter);

        bindingManager.amendSourceForBinding(pointer, QNames._ServiceDigitalIdentities_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(pointer, QNames._TSLLocation);

        {
            JAXBElement<InternationalNamesType> concreteElement = (JAXBElement<InternationalNamesType>) getAdditionalDataNode(QNames._SchemeOperatorName_QNAME);
            bindingManager.amendSourceForBinding(concreteElement, QNames._SchemeOperatorName_QNAME.getLocalPart());
        }
        {
            JAXBElement<NonEmptyMultiLangURIListType> concreteElement = (JAXBElement<NonEmptyMultiLangURIListType>) getAdditionalDataNode(QNames._SchemeTypeCommunityRules_QNAME);
            bindingManager.amendSourceForBinding(concreteElement,
                    QNames._SchemeTypeCommunityRules_QNAME.getLocalPart());
            if (Configuration.getInstance().isTlMode() && concreteElement.getValue().getURI().isEmpty()) {
                // if in tl mode: take the community rules string from the lotl
                String[] stcr = Configuration.getInstance().getLOTL().getTslSchemeTypeCommunityRules();
                final NonEmptyMultiLangURIType nonEmptyMultiLangURIType = new NonEmptyMultiLangURIType();
                nonEmptyMultiLangURIType.setValue(stcr[0]);
                //TODO: missing default language
                concreteElement.getValue().getURI().add(nonEmptyMultiLangURIType); // only one value expected
            }
        }
        {
            JAXBElement<String> concreteElement = (JAXBElement<String>) getAdditionalDataNode(QNames._SchemeTerritory_QNAME);
            bindingManager.amendSourceForBinding(concreteElement, QNames._SchemeTerritory_QNAME.getLocalPart());
        }
        {
            JAXBElement<String> concreteElement = (JAXBElement<String>) getAdditionalDataNode(QNames._MimeType_QNAME);
            bindingManager.amendSourceForBinding(concreteElement, QNames._MimeType_QNAME.getLocalPart());
        }
        {
            JAXBElement<String> concreteElement = (JAXBElement<String>) getAdditionalDataNode(QNames._TSLType_QNAME);
            bindingManager.amendSourceForBinding(concreteElement, QNames._TSLType_QNAME.getLocalPart());
        }

        bindingManager.bindAll();

        // refresh all the content information on the multivalue buttons
        schemeOperatorName.refreshContentInformation();
        digitalIdButton.refreshContentInformation();
        if (!Configuration.getInstance().isTlMode()) {
            schemeTypeCommunityRuleLOTL.refreshContentInformation();
        }
    }
}