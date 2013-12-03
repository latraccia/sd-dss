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

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.*;

import eu.europa.ec.markt.dss.common.TooltipHelper;
import eu.europa.ec.markt.tlmanager.core.Configuration;
import eu.europa.ec.markt.tlmanager.core.QNames;
import eu.europa.ec.markt.tlmanager.model.treeNodes.TSLDataNode;
import eu.europa.ec.markt.tlmanager.util.Util;
import eu.europa.ec.markt.tlmanager.view.binding.BigIntegerConverter;
import eu.europa.ec.markt.tlmanager.view.binding.BindingManager;
import eu.europa.ec.markt.tlmanager.view.binding.DistributionPointConverter;
import eu.europa.ec.markt.tlmanager.view.binding.ElectronicAddressConverter;
import eu.europa.ec.markt.tlmanager.view.binding.InternationalNamesConverter;
import eu.europa.ec.markt.tlmanager.view.binding.NonEmptyMultiLangURIListConverter;
import eu.europa.ec.markt.tlmanager.view.binding.PolicyOrLegalnoticeConverter;
import eu.europa.ec.markt.tlmanager.view.binding.PostalAddressListConverter;
import eu.europa.ec.markt.tlmanager.view.binding.TSPInformationExtensionConverter;
import eu.europa.ec.markt.tlmanager.view.binding.XMLGregorianCalendarConverter;
import eu.europa.ec.markt.tlmanager.view.multivalue.MultiMode;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TrustStatusListType;

/**
 * Content page for managing all below a <tsl:SchemeInformation/>.
 * 
 * 
 * @version $Revision: 2845 $ - $Date: 2013-11-04 13:49:07 +0100 (lun., 04 nov. 2013) $
 */

public class TSLInformationPage extends TreeDataPublisher {
    private static final Logger LOG = Logger.getLogger(TSLInformationPage.class.getName());

    private boolean listClosed;
    private DefaultComboBoxModel schemeTerritoryModel;
    private DefaultComboBoxModel tslTypeModel;
    private DefaultComboBoxModel statusDeterminationApproachModel;

    /**
     * Instantiates a new tSL information page.
     */
    public TSLInformationPage(JTree jtree) {
        super(jtree);
        String[] territoryItems = Util.addNoSelectionEntry(Configuration.getInstance().getCountryCodes().getCodes());
        schemeTerritoryModel = new DefaultComboBoxModel(territoryItems);

        String[] tslTypeItems = new String[]{Configuration.getInstance().getTSL().getTslType()};
        tslTypeModel = new DefaultComboBoxModel(tslTypeItems);

        String[] statusDeterminationApproachItems = new String[]{Configuration.getInstance().getTSL()
              .getTslStatusDeterminationApproach()};
        statusDeterminationApproachModel = new DefaultComboBoxModel(statusDeterminationApproachItems);

        initComponents();

        historicalInformationPeriodLabel.setVisible(false);
        historicalInformationPeriod.setVisible(false);

        tslTitle.setTitle(uiKeys.getString("TSLInformationPage.tslTitle.title"));
        initBinding();

        additionalSetup();

        listIssueDateLabel.setToolTipText(Configuration.getInstance().getTimeZoneName());
        TooltipHelper.registerComponentAtTooltipManager(listIssueDateLabel);

        nextUpdateLabel.setToolTipText(Configuration.getInstance().getTimeZoneName());
        TooltipHelper.registerComponentAtTooltipManager(nextUpdateLabel);

        schemeExtensionsLabel.setVisible(!Configuration.getInstance().isEuMode());
        schemeExtensionsButton.setVisible(!Configuration.getInstance().isEuMode());

    }

    /**
     * @return the listClosed
     */
    public boolean isListClosed() {
        return listClosed;
    }

    /** {@inheritDoc} */
    @Override
    public void setName() {
        setName(TreeDataPublisher.TSL_INFORMATION_PAGE);
    }

    /**
     * Re-initialises the page so that all old values will vanish
     */
    public void reInit() {
        bindingManager = null;
        initBinding();
    }

    /** {@inheritDoc} */
    @Override
    protected void setupMandatoryLabels() {
        setMandatoryLabel(tslSequenceNumberLabel);
        setMandatoryLabel(schemeOperatorNameLabel);
        setMandatoryLabel(schemeOperatorPostalAddressLabel);
        setMandatoryLabel(schemeOperatorElectronicAddressLabel);
        setMandatoryLabel(schemeNameLabel);
        setMandatoryLabel(schemeInformationURILabel);
        setMandatoryLabel(schemeTypeCommunityRuleLabel);
        setMandatoryLabel(schemeTerritoryLabel);
        setMandatoryLabel(policyOrLegalNoticeLabel);
        setMandatoryLabel(historicalInformationPeriodLabel);
        setMandatoryLabel(listIssueDateLabel);
        setMandatoryLabel(nextUpdateLabel);
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        tslTitle = new eu.europa.ec.markt.tlmanager.view.common.TitledPanel();
        tslSequenceNumberLabel = new javax.swing.JLabel();
        tslSequenceNumber = new javax.swing.JTextField();
        schemeOperatorNameLabel = new javax.swing.JLabel();
        schemeOperatorName = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTILANG_TEXT, Configuration.LanguageCodes.getEnglishLanguage(), null);
        schemeOperatorPostalAddress = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTILANG_POSTAL, Configuration.LanguageCodes.getEnglishLanguage(), null);
        schemeOperatorPostalAddressLabel = new javax.swing.JLabel();
        schemeOperatorElectronicAddress = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTI_MULTILANGANYURI, null, null);
        schemeOperatorElectronicAddressLabel = new javax.swing.JLabel();
        schemeNameLabel = new javax.swing.JLabel();
        schemeName = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTILANG_TEXT, Configuration.LanguageCodes.getEnglishLanguage(), null);
        schemeInformationURILabel = new javax.swing.JLabel();
        schemeInformationURI = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTILANG_TEXT, Configuration.LanguageCodes.getEnglishLanguage(), null);
        schemeTypeCommunityRuleLabel = new javax.swing.JLabel();
        schemeTypeCommunityRule = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTILANG_COMBOBOX, null, Util.addNoSelectionEntry(Configuration.getInstance().getTSL().getTslSchemeTypeCommunityRules()));
        schemeTerritoryLabel = new javax.swing.JLabel();
        schemeTerritory = new javax.swing.JComboBox();
        policyOrLegalNoticeLabel = new javax.swing.JLabel();
        policyOrLegalNotice = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTILANG_TEXT, Configuration.LanguageCodes.getEnglishLanguage(), null);
        historicalInformationPeriodLabel = new javax.swing.JLabel();
        historicalInformationPeriod = new javax.swing.JTextField();
        listIssueDateLabel = new javax.swing.JLabel();
        nextUpdateLabel = new javax.swing.JLabel();
        closedLabel = new javax.swing.JLabel();
        closed = new javax.swing.JCheckBox();
        distributionPointLabel = new javax.swing.JLabel();
        distributionPoint = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTI_ANYURI, Configuration.LanguageCodes.getEnglishLanguage(), null);
        tslIdentifierLabel = new javax.swing.JLabel();
        tslIdentifier = new javax.swing.JTextField();
        listIssueDate = new eu.europa.ec.markt.tlmanager.view.common.DateTimePicker();
        nextUpdate = new eu.europa.ec.markt.tlmanager.view.common.DateTimePicker();
        jLabel1 = new javax.swing.JLabel();
        tslType = new javax.swing.JComboBox();
        statusDeterminationApproach = new javax.swing.JComboBox();
        jLabel2 = new javax.swing.JLabel();
        schemeExtensionsButton = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTI_TSPINEX, null, null);
        schemeExtensionsLabel = new javax.swing.JLabel();

        tslTitle.setName("tslTitle"); // NOI18N

        tslSequenceNumberLabel.setLabelFor(tslSequenceNumber);
        tslSequenceNumberLabel.setText(uiKeys.getString("TSLInformationPage.tslSequenceNumberLabel.text")); // NOI18N

        tslSequenceNumber.setName("tslSequenceNumber"); // NOI18N

        schemeOperatorNameLabel.setLabelFor(schemeOperatorName);
        schemeOperatorNameLabel.setText(uiKeys.getString("TSLInformationPage.schemeOperatorNameLabel.text")); // NOI18N

        schemeOperatorName.setName("schemeOperatorName"); // NOI18N

        schemeOperatorPostalAddress.setName("schemeOperatorPostalAddress"); // NOI18N

        schemeOperatorPostalAddressLabel.setLabelFor(schemeOperatorPostalAddress);
        schemeOperatorPostalAddressLabel.setText(uiKeys.getString("TSLInformationPage.schemeOperatorPostalAddressLabel.text")); // NOI18N

        schemeOperatorElectronicAddress.setName("schemeOperatorElectronicAddress"); // NOI18N

        schemeOperatorElectronicAddressLabel.setLabelFor(schemeOperatorElectronicAddress);
        schemeOperatorElectronicAddressLabel.setText(uiKeys.getString("TSLInformationPage.schemeOperatorElectronicAddressLabel.text")); // NOI18N

        schemeNameLabel.setLabelFor(schemeName);
        schemeNameLabel.setText(uiKeys.getString("TSLInformationPage.schemeNameLabel.text")); // NOI18N

        schemeName.setName("schemeName"); // NOI18N

        schemeInformationURILabel.setLabelFor(schemeInformationURI);
        schemeInformationURILabel.setText(uiKeys.getString("TSLInformationPage.schemeInformationURILabel.text")); // NOI18N

        schemeInformationURI.setName("schemeInformationURI"); // NOI18N

        schemeTypeCommunityRuleLabel.setLabelFor(schemeTypeCommunityRule);
        schemeTypeCommunityRuleLabel.setText(uiKeys.getString("TSLInformationPage.schemeTypeCommunityRuleLabel.text")); // NOI18N
        schemeTypeCommunityRuleLabel.setName("schemeTypeCommunityRuleLabel"); // NOI18N

        schemeTypeCommunityRule.setName("schemeTypeCommunityRule"); // NOI18N

        schemeTerritoryLabel.setLabelFor(schemeTerritory);
        schemeTerritoryLabel.setText(uiKeys.getString("TSLInformationPage.schemeTerritoryLabel.text")); // NOI18N

        schemeTerritory.setEditable(!Configuration.getInstance().isEuMode());
        schemeTerritory.setModel(schemeTerritoryModel);
        schemeTerritory.setName("schemeTerritory"); // NOI18N

        policyOrLegalNoticeLabel.setLabelFor(policyOrLegalNotice);
        policyOrLegalNoticeLabel.setText(uiKeys.getString("TSLInformationPage.policyOrLegalNoticeLabel.text")); // NOI18N

        policyOrLegalNotice.setName("policyOrLegalNotice"); // NOI18N

        historicalInformationPeriodLabel.setLabelFor(historicalInformationPeriod);
        historicalInformationPeriodLabel.setText(uiKeys.getString("TSLInformationPage.historicalInformationPeriodLabel.text")); // NOI18N

        historicalInformationPeriod.setName("historicalInformationPeriod"); // NOI18N

        listIssueDateLabel.setLabelFor(listIssueDate);
        listIssueDateLabel.setText(uiKeys.getString("TSLInformationPage.listIssueDateLabel.text")); // NOI18N

        nextUpdateLabel.setLabelFor(nextUpdate);
        nextUpdateLabel.setText(uiKeys.getString("TSLInformationPage.nextUpdateLabel.text")); // NOI18N

        closedLabel.setLabelFor(closed);
        closedLabel.setText(uiKeys.getString("TSLInformationPage.closedLabel.text")); // NOI18N

        closed.setName("closed"); // NOI18N
        closed.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                closedActionPerformed(evt);
            }
        });

        distributionPointLabel.setLabelFor(distributionPoint);
        distributionPointLabel.setText(uiKeys.getString("TSLInformationPage.distributionPointLabel.text")); // NOI18N

        distributionPoint.setName("distributionPoint"); // NOI18N

        tslIdentifierLabel.setLabelFor(tslIdentifier);
        tslIdentifierLabel.setText(uiKeys.getString("TSLInformationPage.tslIdentifierLabel.text")); // NOI18N

        tslIdentifier.setName("tslIdentifier"); // NOI18N

        listIssueDate.setName("listIssueDate"); // NOI18N

        nextUpdate.setName("nextUpdate"); // NOI18N

        jLabel1.setText("TSL type");

        tslType.setEditable(!Configuration.getInstance().isEuMode());
        tslType.setModel(tslTypeModel);
        tslType.setName("tslType"); // NOI18N

        statusDeterminationApproach.setEditable(!Configuration.getInstance().isEuMode());
        statusDeterminationApproach.setModel(statusDeterminationApproachModel);
        statusDeterminationApproach.setName("statusDeterminationApproach"); // NOI18N

        jLabel2.setText("Status Determination Approach");

        schemeExtensionsLabel.setText("Scheme Extensions");

        javax.swing.GroupLayout tslTitleLayout = new javax.swing.GroupLayout(tslTitle);
        tslTitle.setLayout(tslTitleLayout);
        tslTitleLayout.setHorizontalGroup(
            tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tslTitleLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(schemeOperatorNameLabel)
                    .addComponent(tslSequenceNumberLabel)
                    .addComponent(schemeOperatorPostalAddressLabel)
                    .addComponent(schemeOperatorElectronicAddressLabel)
                    .addComponent(schemeNameLabel)
                    .addComponent(schemeInformationURILabel)
                    .addComponent(schemeTypeCommunityRuleLabel)
                    .addComponent(schemeTerritoryLabel)
                    .addComponent(policyOrLegalNoticeLabel)
                    .addComponent(historicalInformationPeriodLabel)
                    .addComponent(listIssueDateLabel)
                    .addComponent(closedLabel)
                    .addComponent(nextUpdateLabel)
                    .addComponent(distributionPointLabel)
                    .addComponent(tslIdentifierLabel)
                    .addComponent(jLabel1)
                    .addComponent(jLabel2)
                    .addComponent(schemeExtensionsLabel))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(tslIdentifier)
                    .addComponent(historicalInformationPeriod)
                    .addComponent(tslSequenceNumber)
                    .addComponent(listIssueDate, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(schemeOperatorElectronicAddress, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(schemeOperatorPostalAddress, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(schemeOperatorName, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(schemeName, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(schemeInformationURI, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(schemeTypeCommunityRule, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(policyOrLegalNotice, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(nextUpdate, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(distributionPoint, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(tslType, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(schemeTerritory, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(tslTitleLayout.createSequentialGroup()
                        .addComponent(closed)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addComponent(statusDeterminationApproach, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(schemeExtensionsButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        tslTitleLayout.setVerticalGroup(
            tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tslTitleLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tslSequenceNumber, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(tslSequenceNumberLabel))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(tslType, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(schemeOperatorName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(schemeOperatorNameLabel))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(schemeOperatorPostalAddress, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(schemeOperatorPostalAddressLabel))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(schemeOperatorElectronicAddress, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(schemeOperatorElectronicAddressLabel))
                .addGap(19, 19, 19)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(schemeName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(schemeNameLabel))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(schemeInformationURI, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(schemeInformationURILabel))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(statusDeterminationApproach, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(schemeTypeCommunityRule, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(schemeTypeCommunityRuleLabel))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(schemeTerritory, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(schemeTerritoryLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(policyOrLegalNotice, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(policyOrLegalNoticeLabel))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(historicalInformationPeriod, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(historicalInformationPeriodLabel))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(listIssueDateLabel)
                    .addComponent(listIssueDate, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(closed)
                    .addComponent(closedLabel))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(nextUpdateLabel)
                    .addComponent(nextUpdate, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(distributionPoint, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(distributionPointLabel))
                .addGap(18, 18, 18)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tslIdentifier, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(tslIdentifierLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(schemeExtensionsButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(schemeExtensionsLabel))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(tslTitle, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(tslTitle, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGap(32, 32, 32))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void closedActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_closedActionPerformed
        listClosed = closed.isSelected();
        if (listClosed) {
            nextUpdate.setDateTime(null);
        }
        nextUpdateLabel.setVisible(!listClosed);
        nextUpdate.setVisible(!listClosed);
        nextUpdate.setEnabled(!listClosed);
    }// GEN-LAST:event_closedActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox closed;
    private javax.swing.JLabel closedLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton distributionPoint;
    private javax.swing.JLabel distributionPointLabel;
    private javax.swing.JTextField historicalInformationPeriod;
    private javax.swing.JLabel historicalInformationPeriodLabel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private eu.europa.ec.markt.tlmanager.view.common.DateTimePicker listIssueDate;
    private javax.swing.JLabel listIssueDateLabel;
    private eu.europa.ec.markt.tlmanager.view.common.DateTimePicker nextUpdate;
    private javax.swing.JLabel nextUpdateLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton policyOrLegalNotice;
    private javax.swing.JLabel policyOrLegalNoticeLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeExtensionsButton;
    private javax.swing.JLabel schemeExtensionsLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeInformationURI;
    private javax.swing.JLabel schemeInformationURILabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeName;
    private javax.swing.JLabel schemeNameLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeOperatorElectronicAddress;
    private javax.swing.JLabel schemeOperatorElectronicAddressLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeOperatorName;
    private javax.swing.JLabel schemeOperatorNameLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeOperatorPostalAddress;
    private javax.swing.JLabel schemeOperatorPostalAddressLabel;
    private javax.swing.JComboBox schemeTerritory;
    private javax.swing.JLabel schemeTerritoryLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeTypeCommunityRule;
    private javax.swing.JLabel schemeTypeCommunityRuleLabel;
    private javax.swing.JComboBox statusDeterminationApproach;
    private javax.swing.JTextField tslIdentifier;
    private javax.swing.JLabel tslIdentifierLabel;
    private javax.swing.JTextField tslSequenceNumber;
    private javax.swing.JLabel tslSequenceNumberLabel;
    private eu.europa.ec.markt.tlmanager.view.common.TitledPanel tslTitle;
    private javax.swing.JComboBox tslType;
    // End of variables declaration//GEN-END:variables

    private void initBinding() {
        if (bindingManager == null) {
            bindingManager = new BindingManager(this);
        }

        bindingManager.createBindingForComponent(tslSequenceNumber, "TSLSequenceNumber", QNames._TSLSequenceNumber);
        bindingManager.appendConverter(new BigIntegerConverter(), QNames._TSLSequenceNumber);

        bindingManager.createBindingForComponent(schemeOperatorName.getMultivaluePanel(), "schemeOperatorName",
                QNames._SchemeOperatorName_QNAME.getLocalPart());
        bindingManager.appendConverter(new InternationalNamesConverter(),
                QNames._SchemeOperatorName_QNAME.getLocalPart());

        // NOTE: "PostalAddresses" -> plural is indeed correct
        bindingManager.createBindingForComponent(schemeOperatorPostalAddress.getMultivaluePanel(),
                "postalAddresses", QNames._PostalAddress_QNAME.getLocalPart());
        bindingManager.appendConverter(new PostalAddressListConverter(), QNames._PostalAddress_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(schemeOperatorElectronicAddress.getMultivaluePanel(),
                "electronicAddress", QNames._ElectronicAddress_QNAME.getLocalPart());
        bindingManager.appendConverter(new ElectronicAddressConverter(),
                QNames._ElectronicAddress_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(schemeName.getMultivaluePanel(), "schemeName",
                QNames._SchemeName_QNAME.getLocalPart());
        bindingManager.appendConverter(new InternationalNamesConverter(), QNames._SchemeName_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(schemeInformationURI.getMultivaluePanel(), "schemeInformationURI",
                QNames._SchemeInformationURI_QNAME.getLocalPart());
        bindingManager.appendConverter(new NonEmptyMultiLangURIListConverter(),
                QNames._SchemeInformationURI_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(schemeTypeCommunityRule.getMultivaluePanel(), "schemeTypeCommunityRules",
              QNames._SchemeTypeCommunityRules_QNAME.getLocalPart());
        bindingManager.appendConverter(new NonEmptyMultiLangURIListConverter(), QNames._SchemeTypeCommunityRules_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(schemeTerritory,
              "schemeTerritory", QNames._SchemeTerritory_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(policyOrLegalNotice.getMultivaluePanel(), "policyOrLegalNotice",
                QNames._PolicyOrLegalNotice_QNAME.getLocalPart());
        bindingManager.appendConverter(new PolicyOrLegalnoticeConverter(),
                QNames._PolicyOrLegalNotice_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(historicalInformationPeriod, "historicalInformationPeriod",
              QNames._HistoricalInformationPeriod);
        bindingManager.appendConverter(new BigIntegerConverter(), QNames._HistoricalInformationPeriod);

        bindingManager.createBindingForComponent(listIssueDate, "listIssueDateTime", QNames._ListIssueDateTime);
        bindingManager.appendConverter(new XMLGregorianCalendarConverter(), QNames._ListIssueDateTime);

        bindingManager.createBindingForComponent(nextUpdate, "dateTime", QNames._NextUpdate_QNAME.getLocalPart());
        bindingManager.appendConverter(new XMLGregorianCalendarConverter(), QNames._NextUpdate_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(distributionPoint.getMultivaluePanel(), "distributionPoints",
              QNames._DistributionPoints_QNAME.getLocalPart());
        bindingManager.appendConverter(new DistributionPointConverter(), QNames._DistributionPoints_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(tslIdentifier, "id", QNames._TSLIdentifier);
        bindingManager.createBindingForComponent(tslType, "TSLType", QNames._TSLType_QNAME.getLocalPart());
        bindingManager.createBindingForComponent(statusDeterminationApproach, "statusDeterminationApproach", QNames._StatusDeterminationApproach_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(schemeExtensionsButton.getMultivaluePanel(),
              "schemeExtensions", QNames._Extension_QNAME.getLocalPart());
        bindingManager.appendConverter(new TSPInformationExtensionConverter(),
              QNames._Extension_QNAME.getLocalPart());
    }

    /** {@inheritDoc} */
    @Override
    public void updateViewFromData(TSLDataNode dataNode) {
        this.dataNode = dataNode;
        TrustStatusListType tsl = (TrustStatusListType) dataNode.getUserObject();
        TSLSchemeInformationType schemeInformation = tsl.getSchemeInformation();
        LOG.log(Level.FINE, "Value changed {0}", schemeInformation);

        bindingManager.unbindAll();
        bindingManager.amendSourceForBinding(schemeInformation, QNames._TSLSequenceNumber);
        bindingManager.amendSourceForBinding(schemeInformation, QNames._TSLType_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation,
              QNames._StatusDeterminationApproach_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation, QNames._SchemeOperatorName_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation.getSchemeOperatorAddress(),
                QNames._PostalAddress_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation.getSchemeOperatorAddress(),
                QNames._ElectronicAddress_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation, QNames._SchemeName_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation, QNames._SchemeInformationURI_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation,
                QNames._SchemeTypeCommunityRules_QNAME.getLocalPart());

        bindingManager.amendSourceForBinding(schemeInformation, QNames._SchemeTerritory_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation, QNames._PolicyOrLegalNotice_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation, QNames._HistoricalInformationPeriod);
        bindingManager.amendSourceForBinding(schemeInformation, QNames._ListIssueDateTime);
        bindingManager.amendSourceForBinding(schemeInformation.getNextUpdate(), QNames._NextUpdate_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation, QNames._DistributionPoints_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation, QNames._Extension_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(tsl, QNames._TSLIdentifier);

        bindingManager.bindAll();

        // update all the preview information on the multivalue buttons
        schemeOperatorName.refreshContentInformation();
        schemeOperatorPostalAddress.refreshContentInformation();
        schemeOperatorElectronicAddress.refreshContentInformation();
        schemeName.refreshContentInformation();
        schemeInformationURI.refreshContentInformation();
        schemeTypeCommunityRule.refreshContentInformation();
        policyOrLegalNotice.refreshContentInformation();
        distributionPoint.refreshContentInformation();
        schemeExtensionsButton.refreshContentInformation();
    }
}