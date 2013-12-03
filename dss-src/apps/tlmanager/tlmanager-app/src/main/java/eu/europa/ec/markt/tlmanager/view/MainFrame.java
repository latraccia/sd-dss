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

package eu.europa.ec.markt.tlmanager.view;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.*;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;

import org.openide.DialogDisplayer;
import org.openide.WizardDescriptor;
import org.w3c.dom.Document;

import eu.europa.ec.markt.tlmanager.TSLComposer;
import eu.europa.ec.markt.tlmanager.controller.TreePopupCreator;
import eu.europa.ec.markt.tlmanager.core.Configuration;
import eu.europa.ec.markt.tlmanager.core.Migration;
import eu.europa.ec.markt.tlmanager.core.exception.OpenException;
import eu.europa.ec.markt.tlmanager.core.exception.SaveException;
import eu.europa.ec.markt.tlmanager.core.signature.SignatureManager;
import eu.europa.ec.markt.tlmanager.core.validation.ValidationLogger;
import eu.europa.ec.markt.tlmanager.core.validation.ValidationLogger.Message;
import eu.europa.ec.markt.tlmanager.model.TSLTreeModel;
import eu.europa.ec.markt.tlmanager.model.treeNodes.TSLDataNode;
import eu.europa.ec.markt.tlmanager.view.common.NewServiceStatusPanel;
import eu.europa.ec.markt.tlmanager.view.pages.PointerToOtherTSLPage;
import eu.europa.ec.markt.tlmanager.view.pages.QualificationExtensionPage;
import eu.europa.ec.markt.tlmanager.view.pages.ServiceCurrentStatusInformationPage;
import eu.europa.ec.markt.tlmanager.view.pages.ServiceInformationExtensionPage;
import eu.europa.ec.markt.tlmanager.view.pages.ServiceStatusHistoryPage;
import eu.europa.ec.markt.tlmanager.view.pages.TSLInformationPage;
import eu.europa.ec.markt.tlmanager.view.pages.TSPInformationPage;
import eu.europa.ec.markt.tlmanager.view.pages.TreeDataPublisher;
import eu.europa.ec.markt.tlmanager.view.pages.TreeSelectionHandler;
import eu.europa.ec.markt.tlmanager.view.signature.LogDialog;
import eu.europa.ec.markt.tlmanager.view.signature.SignatureWizardStep1;
import eu.europa.ec.markt.tlmanager.view.signature.SignatureWizardStep2;
import eu.europa.ec.markt.tlmanager.view.signature.SignatureWizardStep3;
import eu.europa.ec.markt.tlmanager.view.signature.SignatureWizardStep4;

/**
 * The MainFrame for TLManager.
 *
 *
 * @version $Revision: 2660 $ - $Date: 2013-09-26 16:03:53 +0200 (jeu., 26 sept. 2013) $
 */

public class MainFrame extends JFrame implements ActionListener {

    private static final ResourceBundle uiKeys = ResourceBundle.getBundle("eu/europa/ec/markt/tlmanager/uiKeys",
            Configuration.getInstance().getLocale());
    private static String APP_TITLE = uiKeys.getString("MainFrame.app.title");
    private static final Logger LOG = Logger.getLogger(MainFrame.class.getName());

    private TSLComposer composer;
    private TSLTreeModel treeModel;

    public static final JFileChooser fileChooser = new JFileChooser();
    // a different fc for the signature sources
    public static final JFileChooser sigSourceFileChooser = new JFileChooser();

    private LogDialog logDialog;
    private TreeSelectionHandler treeSelectionHandler;
    private List<TreeDataPublisher> treeDataPublisher;

    private TSLInformationPage tslInformationPage;
    private TSPInformationPage tspInformationPage;
    private PointerToOtherTSLPage pointerToOtherTSLPage;
    private ServiceInformationExtensionPage serviceInformationExtensionPage;
    private ServiceStatusHistoryPage serviceStatusHistoryPage;
    private ServiceCurrentStatusInformationPage serviceCurrentStatusInformationPage;
    private QualificationExtensionPage qualificationExtensionPage;

    private int WIDTH = 1024, HEIGHT = 800;

    /**
     * Instantiates a new main frame.
     */
    public MainFrame() {
        init();

        // Center the JFrame on the screen
        int widthWindow = this.getWidth();
        int heightWindow = this.getHeight();
        Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
        int X = (screen.width / 2) - (widthWindow / 2); // Center horizontally.
        int Y = (screen.height / 2) - (heightWindow / 2); // Center vertically.
        this.setBounds(X, Y, widthWindow, heightWindow);
    }

    private void init() {
        composer = new TSLComposer(this);
        treeModel = new TSLTreeModel(composer);
        treeDataPublisher = new ArrayList<TreeDataPublisher>();

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        if (Configuration.getInstance().isTlMode()) {
            APP_TITLE += " (tl) ";
        } else {
            APP_TITLE += " (lotl) ";
        }
        setTitle(APP_TITLE);

        setPreferredSize(new Dimension(WIDTH, HEIGHT));

        initComponents();

        tslInformationPage = new TSLInformationPage(tslTree);
        tspInformationPage = new TSPInformationPage(tslTree);
        pointerToOtherTSLPage = new PointerToOtherTSLPage(tslTree);
        serviceCurrentStatusInformationPage = new ServiceCurrentStatusInformationPage(tslTree);
        serviceStatusHistoryPage = new ServiceStatusHistoryPage(tslTree);
        serviceInformationExtensionPage = new ServiceInformationExtensionPage(tslTree);
        qualificationExtensionPage = new QualificationExtensionPage(tslTree);

        treeDataPublisher.add(tslInformationPage);
        treeDataPublisher.add(tspInformationPage);
        treeDataPublisher.add(pointerToOtherTSLPage);
        treeDataPublisher.add(serviceCurrentStatusInformationPage);
        treeDataPublisher.add(serviceStatusHistoryPage);
        treeDataPublisher.add(serviceInformationExtensionPage);
        treeDataPublisher.add(qualificationExtensionPage);

        treeSelectionHandler = new TreeSelectionHandler(treeDataPublisher, detailsPanel);
        ToolTipManager.sharedInstance().registerComponent(tslTree);
        tslTree.addTreeSelectionListener(treeSelectionHandler);
        tslTree.addMouseListener(new TreePopupCreator(composer));

        tslTree.setName("tslTree");

        newTSLButton.addActionListener(this);
        openTSLButton.addActionListener(this);
        saveTSLButton.addActionListener(this);
        saveAsTSLButton.addActionListener(this);
        signTSLButton.addActionListener(this);
        showLogButton.addActionListener(this);

        treeModel.addTreeModelListener(new TreeModelListener() {
            @Override
            public void treeStructureChanged(TreeModelEvent e) {
                if (composer.isDoCreateNodesForData()) {
                    TSLDataNode lastPathComponent = (TSLDataNode) e.getTreePath().getLastPathComponent();
                    composer.createNodes((DefaultMutableTreeNode) lastPathComponent,
                            lastPathComponent.getUserObject());
                }
                TreePath path = e.getTreePath();
                tslTree.setSelectionPath(path);
                tslTree.updateUI();
                tslTree.scrollPathToVisible(path);
            }

            @Override
            public void treeNodesRemoved(TreeModelEvent e) {
                tslTree.setSelectionPath(e.getTreePath());
            }

            @Override
            public void treeNodesInserted(TreeModelEvent e) {
            }

            @Override
            public void treeNodesChanged(TreeModelEvent e) {
            }
        });
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jSplitPane1 = new javax.swing.JSplitPane();
        treePanel = new javax.swing.JScrollPane();
        tslTree = new javax.swing.JTree();
        detailsPanel = new javax.swing.JScrollPane();
        jToolBar1 = new javax.swing.JToolBar();
        newTSLButton = new javax.swing.JButton();
        openTSLButton = new javax.swing.JButton();
        saveTSLButton = new javax.swing.JButton();
        saveAsTSLButton = new javax.swing.JButton();
        signTSLButton = new javax.swing.JButton();
        showLogButton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setMinimumSize(new java.awt.Dimension(119, 400));

        treePanel.setPreferredSize(new java.awt.Dimension(250, 64));

        tslTree.setModel(treeModel);
        tslTree.setCellRenderer(new TSLTreeCellRenderer());
        tslTree.setPreferredSize(null);
        treePanel.setViewportView(tslTree);

        jSplitPane1.setLeftComponent(treePanel);
        jSplitPane1.setRightComponent(detailsPanel);

        getContentPane().add(jSplitPane1, java.awt.BorderLayout.CENTER);

        jToolBar1.setRollover(true);

        newTSLButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/icons/tsl_new.png")));
        newTSLButton.setMnemonic(uiKeys.getString("MainFrame.menu.new.mnemonic").charAt(0));
        newTSLButton.setText(uiKeys.getString("MainFrame.menu.new")); // NOI18N
        newTSLButton.setFocusable(false);
        newTSLButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        newTSLButton.setName("mainFrame_newButton"); // NOI18N
        newTSLButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(newTSLButton);

        openTSLButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/icons/tsl_open.png")));
        openTSLButton.setMnemonic(uiKeys.getString("MainFrame.menu.open.mnemonic").charAt(0));
        openTSLButton.setText(uiKeys.getString("MainFrame.menu.open")); // NOI18N
        openTSLButton.setFocusable(false);
        openTSLButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        openTSLButton.setName("mainFrame_openButton"); // NOI18N
        openTSLButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(openTSLButton);

        saveTSLButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/icons/tsl_save.png")));
        saveTSLButton.setMnemonic(uiKeys.getString("MainFrame.menu.save.mnemonic").charAt(0));
        saveTSLButton.setText(uiKeys.getString("MainFrame.menu.save")); // NOI18N
        saveTSLButton.setEnabled(false);
        saveTSLButton.setFocusable(false);
        saveTSLButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        saveTSLButton.setName("mainFrame_saveButton"); // NOI18N
        saveTSLButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(saveTSLButton);

        saveAsTSLButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/icons/tsl_save.png")));
        saveAsTSLButton.setMnemonic('A');
        saveAsTSLButton.setText(uiKeys.getString("MainFrame.menu.saveAs")); // NOI18N
        saveAsTSLButton.setEnabled(false);
        saveAsTSLButton.setFocusable(false);
        saveAsTSLButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        saveAsTSLButton.setName("mainFrame_saveAsButton"); // NOI18N
        saveAsTSLButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(saveAsTSLButton);

        signTSLButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/icons/tsl_sign.png")));
        signTSLButton.setMnemonic(uiKeys.getString("MainFrame.menu.sign.mnemonic").charAt(0));
        signTSLButton.setText(uiKeys.getString("MainFrame.menu.sign")); // NOI18N
        signTSLButton.setEnabled(false);
        signTSLButton.setFocusable(false);
        signTSLButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        signTSLButton.setName("mainFrame_signButton"); // NOI18N
        signTSLButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(signTSLButton);

        showLogButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/icons/tsl_sign.png")));
        showLogButton.setMnemonic(uiKeys.getString("MainFrame.menu.log.mnemonic").charAt(0));
        showLogButton.setText(uiKeys.getString("MainFrame.menu.log")); // NOI18N
        showLogButton.setEnabled(false);
        showLogButton.setFocusable(false);
        showLogButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        showLogButton.setName("mainFrame_logButton"); // NOI18N
        showLogButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(showLogButton);

        getContentPane().add(jToolBar1, java.awt.BorderLayout.PAGE_START);

        pack();
    }// </editor-fold>//GEN-END:initComponents
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JScrollPane detailsPanel;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JToolBar jToolBar1;
    private javax.swing.JButton newTSLButton;
    private javax.swing.JButton openTSLButton;
    private javax.swing.JButton saveAsTSLButton;
    private javax.swing.JButton saveTSLButton;
    private javax.swing.JButton showLogButton;
    private javax.swing.JButton signTSLButton;
    private javax.swing.JScrollPane treePanel;
    private javax.swing.JTree tslTree;
    // End of variables declaration//GEN-END:variables

    /**
     * Aligns the selection path of the tree to the matching associated <code>TreeNode</code> object found in the map of
     * 'validation associations'.
     *
     * @param panelObject the reference object
     */
    public void alignTreeSelectionToValidationMessage(Object panelObject) {
        if (panelObject != null) {
            Map<Object, TreeNode[]> validationAssociations = composer.getValidationAssociations();
            if (validationAssociations != null) {
                TreeNode[] treeNodes = validationAssociations.get(panelObject);
                if (treeNodes != null) {
                    TreePath path = new TreePath(treeNodes);
                    tslTree.setSelectionPath(path);
                    tslTree.scrollPathToVisible(path);
                } else {
                    LOG.log(Level.WARNING, "Unable to get associated Selection Path to object!");
                }
            }
        }
    }

    /**
     * Returns true if the Closed checkbox on the <code>TSLInformationPage</code> was selected.
     */
    public boolean isListClosed() {
        return tslInformationPage.isListClosed();
    }

    private void resetEnv() {
        tslInformationPage.reInit();
        String title = APP_TITLE;
        if (composer.getCurrentFile() != null) {
            title += "- " + composer.getCurrentFile().getAbsolutePath();
        }
        setTitle(title);
        composer.setValidationLogger(null);
        showLogButton.setEnabled(false);
        updateLogDialog(new ArrayList<ValidationLogger.Message>());
    }

    /**
     * Updates the logging dialog
     *
     * @param messages a list of messages
     */
    public void updateLogDialog(List<Message> messages) {
        if (logDialog != null) {
            logDialog.setValidationMessages(messages);
        }
    }

    /**
     * Asks the user for his opinion by displaying a confirmation dialog.
     *
     * @param message the message to display
     * @param title the title of the confirmation dialog
     *
     * @return true if confirmed
     */
    public boolean queryUser(String message, String title) {
        int confirmValue = JOptionPane.showConfirmDialog(this, message, title, JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);
        if (confirmValue == JOptionPane.OK_OPTION) {
            return true;
        }
        return false;
    }

    /**
     * Notifies the user about something that is further detailed in the given message.
     *
     * @param message the message describing the event
     * @param title the title of the message dialog
     */
    public void notifyUser(String message, String title) {
        JOptionPane.showMessageDialog(this, message, title, JOptionPane.OK_OPTION);
    }

    /**
     * Asks the user for new status values and returns a <code>NewServiceStatusPanel.Values</code>.
     *
     * @return the new status values
     */
    public NewServiceStatusPanel.Values queryForNewServiceStatusValues() {
        NewServiceStatusPanel newServiceStatusPanel = new NewServiceStatusPanel();

        int selection = JOptionPane.showOptionDialog(this, newServiceStatusPanel,
                uiKeys.getString("MainFrame.newService.title"), JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE, null, null, null);

        if (selection == JOptionPane.OK_OPTION) {
            return newServiceStatusPanel.getValues();
        }
        return null;
    }

    private void newAction() {
        boolean createNew = userMustConfirmLosingUnsavedWork(uiKeys.getString("MainFrame.newList.message"),
              uiKeys.getString("MainFrame.newList.title"));
        if (createNew) {
            LOG.info("Create new TSL");
            composer.newTSL();
            resetEnv();
            saveTSLButton.setEnabled(true);
            saveAsTSLButton.setEnabled(true);
            signTSLButton.setEnabled(true);
        }
    }

    private boolean userMustConfirmLosingUnsavedWork(String confirmMesage, String confirmTitle) {
        boolean createNew = false;
        if (composer.doesAnyTSLExist()) {
            int msg = JOptionPane.showConfirmDialog(this, confirmMesage, confirmTitle, JOptionPane.OK_CANCEL_OPTION,
                  JOptionPane.QUESTION_MESSAGE);
            if (msg == JOptionPane.OK_OPTION) {
                createNew = true;
            }
        } else {
            createNew = true;
        }
        return createNew;
    }

    private void openAction() {
        boolean createNew = userMustConfirmLosingUnsavedWork(uiKeys.getString("MainFrame.openList.message"),
              uiKeys.getString("MainFrame.openList.title"));
        if (!createNew) {
            return;
        }
        LOG.info("Trying to open a file ...");
        int returnValue = fileChooser.showOpenDialog(getRootPane());
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            try {
                composer.openFile(fileChooser.getSelectedFile());
                resetEnv();
                saveTSLButton.setEnabled(true);
                signTSLButton.setEnabled(true);
                saveAsTSLButton.setEnabled(true);
                LOG.info("... success!");
                if (composer.isFileWasMigrated()) {
                    final Migration.MigrationMessages migrationMessages = composer.getMigrationMessages();
                    String migrationBody = uiKeys.getString("MainFrame.openDialog.migrated.message");
                    if (!migrationMessages.getMessges().isEmpty()) {
                        for (final String message : migrationMessages.getMessges()) {
                            migrationBody += "\n\n" + message;
                        }
                    }
                    JOptionPane.showMessageDialog(this, migrationBody,
                          uiKeys.getString("MainFrame.openDialog.migrated.title"), JOptionPane.WARNING_MESSAGE);
                }
            } catch (OpenException ex) {
                LOG.info("... error!");
                JOptionPane.showMessageDialog(this, ex.getMessage(), "Open", JOptionPane.OK_OPTION);
                LOG.log(Level.SEVERE, "Exception: " + ex.getMessage());
            }
        }
    }

    private void saveAction() {
        LOG.info("Trying to save TSL ...");
        try {
            if (composer.getCurrentFile() == null) {
                saveAsAction();
            } else {
                boolean aborted = false;
                if (composer.isSignatureWasRemovedFromLastList()) {
                    // if user saves, the signature (removed during loading) will be removed
                    // which makes sense, coz 'save' saves changes and if there are changes, the digest in the sig is
                    // wrong
                    int msg = JOptionPane.showConfirmDialog(this,
                            uiKeys.getString("MainFrame.saveDialog.confirm.message"),
                            uiKeys.getString("MainFrame.saveDialog.confirm.title"), JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.WARNING_MESSAGE);
                    if (msg == JOptionPane.CANCEL_OPTION) {
                        aborted = true;
                    }
                }
                if (!aborted) {
                    composer.saveToFile(composer.getCurrentFile());
                    LOG.info("... success!");
                    JOptionPane.showMessageDialog(this, uiKeys.getString("MainFrame.saveDialog.message"),
                            uiKeys.getString("MainFrame.saveDialog.title"), JOptionPane.INFORMATION_MESSAGE);
                }
            }
        } catch (SaveException ex) {
            LOG.info("... error!");
            JOptionPane.showMessageDialog(this, ex.getMessage(), uiKeys.getString("MainFrame.saveDialog.title"),
                    JOptionPane.OK_OPTION);
            ex.printStackTrace();
        }
    }

    private void saveAsAction() {
        LOG.info("Trying to save TSL as ...");
        try {
            int returnValue = fileChooser.showSaveDialog(getRootPane());
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                composer.saveToFile(fileChooser.getSelectedFile());
                resetEnv();
                LOG.info("... success!");
                JOptionPane.showMessageDialog(this, uiKeys.getString("MainFrame.saveAsDialog.message"),
                        uiKeys.getString("MainFrame.saveAsDialog.title"), JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (SaveException ex) {
            LOG.info("... error!");
            JOptionPane.showMessageDialog(this, ex.getMessage(), uiKeys.getString("MainFrame.saveAsDialog.title"),
                    JOptionPane.OK_OPTION);
            ex.printStackTrace();
        }
    }

    private void signAction() {
        LOG.info("Sign TSL");
        Document document = null;
        try {
            document = composer.marshall();
        } catch (Exception ex) {
            String message = uiKeys.getString("MainFrame.marshalling.error") + ex.getMessage();
            notifyUser(message, uiKeys.getString("MainFrame.marshalling.title"));
            LOG.log(Level.SEVERE, message, ex);
        }

        ValidationLogger logger = composer.startValidation();

        updateLogDialog(logger.getMessages());
        if (!logger.getValidationMessages().isEmpty()) {
            showLogButton.setEnabled(true);
        } else {
            showLogButton.setEnabled(false);
        }

        // start wizard
        SignatureManager manager = new SignatureManager(logger);
        manager.initInMemoryDocument(document);

        WizardDescriptor wizard = new WizardDescriptor(new WizardDescriptor.Panel[] {
                new SignatureWizardStep1(manager), new SignatureWizardStep2(manager),
                new SignatureWizardStep3(manager), new SignatureWizardStep4(manager) });

        wizard.setTitle(uiKeys.getString("MainFrame.validateSignWizard.title"));
        wizard.putProperty("WizardPanel_autoWizardStyle", Boolean.TRUE);
        Dialog wizardDialog = DialogDisplayer.getDefault().createDialog(wizard);
        wizardDialog.setName("SignatureDialog");
        wizardDialog.setVisible(true);
    }

    private void showLogAction() {
        ValidationLogger validationLogger = composer.getValidationLogger();
        if (validationLogger != null) {
            if (logDialog == null) {
                logDialog = new LogDialog(null, false, this, validationLogger.getValidationMessages());
            } else {
                updateLogDialog(validationLogger.getValidationMessages());
            }
            logDialog.setVisible(true);
        }
    }

    /**
     * Action Handling Method
     */
    public void actionPerformed(ActionEvent e) {
        Object source = e.getSource();

        if (source == newTSLButton) {
            newAction();
        } else if (source == openTSLButton) {
            openAction();
        } else if (source == saveTSLButton) {
            saveAction();
        } else if (source == saveAsTSLButton) {
            saveAsAction();
        } else if (source == signTSLButton) {
            signAction();
        } else if (source == showLogButton) {
            showLogAction();
        } else {
            LOG.warning("Unhandled source: " + source + " (command=" + e.getActionCommand() + ")");
        }
    }

    /**
     * used in JUnit tests
     *
     * @return the TSLComposer
     */
    TSLComposer getComposer() {
        return composer;
    }
}