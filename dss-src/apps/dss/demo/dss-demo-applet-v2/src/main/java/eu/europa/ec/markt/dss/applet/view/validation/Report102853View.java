/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.applet.view.validation;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.swing.*;
import javax.swing.tree.DefaultTreeModel;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xhtmlrenderer.pdf.ITextRenderer;
import org.xhtmlrenderer.simple.FSScrollPane;
import org.xhtmlrenderer.simple.XHTMLPanel;

import com.jgoodies.binding.value.ValueHolder;
import com.jgoodies.forms.builder.PanelBuilder;
import com.jgoodies.forms.layout.CellConstraints;
import com.lowagie.text.DocumentException;
import eu.europa.ec.markt.dss.applet.component.model.XMLTreeModel;
import eu.europa.ec.markt.dss.applet.model.ValidationModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.wizard.validation.ValidationWizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;
import eu.europa.ec.markt.dss.validation102853.ValidationResourceManager;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlDom;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class Report102853View extends WizardView<ValidationModel, ValidationWizardController> {

    private final JTextArea detailedReportText;

    private JTree diagnostic;
    private final JTextArea diagnosticText;

    private final ValueHolder detailledReportValueHolder;
    private final ValueHolder diagnositcValueHolder;

    private final XHTMLPanel simpleReportHtmlPanel;
    private final FSScrollPane simpleReportScrollPane;

    private final XHTMLPanel detailedReportHtmlPanel;
    private final FSScrollPane detailedReportScrollPane;

    /**
     * The default constructor for Report102853View.
     *
     * @param core
     * @param controller
     * @param model
     */
    public Report102853View(final AppletCore core, final ValidationWizardController controller, final ValidationModel model) {
        super(core, controller, model);
        detailledReportValueHolder = new ValueHolder("");
        diagnositcValueHolder = new ValueHolder("");

        detailedReportText = ComponentFactory.createTextArea(detailledReportValueHolder);
        detailedReportText.setTabSize(2);

        diagnostic = ComponentFactory.tree("Diagnostic", new DefaultTreeModel(null));
        diagnosticText = ComponentFactory.createTextArea(diagnositcValueHolder);
        diagnosticText.setTabSize(2);

        simpleReportHtmlPanel = new XHTMLPanel();
        simpleReportScrollPane = new FSScrollPane(simpleReportHtmlPanel);

        detailedReportHtmlPanel = new XHTMLPanel();
        detailedReportScrollPane = new FSScrollPane(detailedReportHtmlPanel);
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doInit()
     */

    @SuppressWarnings("unchecked")
    @Override
    public void doInit() {
        final ValidationModel model = getModel();

        final XmlDom validation102853Report = model.getValidation102853Report();
        final String reportText = validation102853Report.toString();
        detailledReportValueHolder.setValue(reportText);

        final XMLTreeModel xmlTreeModelReport = new XMLTreeModel();
        Element doc = validation102853Report.getRootElement();
        xmlTreeModelReport.setDocument(doc);

        final DiagnosticData diagnosticData102853 = model.getDiagnosticData102853();
        final Document document = ValidationResourceManager.convert(diagnosticData102853);
        final XMLTreeModel xmlTreeModelDiagnostic = new XMLTreeModel();
        xmlTreeModelDiagnostic.setDocument(document.getDocumentElement());
        diagnostic = ComponentFactory.tree("Diagnostic", xmlTreeModelDiagnostic);
        expandTree(diagnostic);

        diagnositcValueHolder.setValue(new XmlDom(document).toString());

        final Document simpleReportHtml = getController().renderSimpleReportAsHtml();
        simpleReportHtmlPanel.setDocument(simpleReportHtml);

        final Document detailedReportHtml = getController().renderValidationReportAsHtml();
        detailedReportHtmlPanel.setDocument(detailedReportHtml);
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.applet.view.DSSAppletView#doLayout()
     */
    @Override
    protected Container doLayout() {

        JTabbedPane tabbedPane = new JTabbedPane(SwingConstants.TOP);
        tabbedPane.addTab("Simple Report", getHtmlPanel("Simple Report", simpleReportScrollPane, simpleReportHtmlPanel));
        tabbedPane.addTab("Detailed Report", getHtmlPanel("Detailed Report", detailedReportScrollPane, detailedReportHtmlPanel));
//        tabbedPane.addTab("Detailled Report Tree", getDetailledReportPanel());
        // tabbedPane.addTab("Detailled Report XML", getDetailledReportText());
        tabbedPane.addTab("Diagnostic Tree", getDiagnosticPanel());
        // tabbedPane.addTab("Diagnostic XML", getDiagnosticPanelText());

        return tabbedPane;

    }

    private JPanel getHtmlPanel(final String textWithMnemonic, final FSScrollPane simpleReportScrollPane, final XHTMLPanel htmlPanel) {
        final String[] columnSpecs = new String[]{"5dlu", "pref", "5dlu", "fill:default:grow", "5dlu"};
        final String[] rowSpecs = new String[]{"5dlu", "pref", "5dlu", "fill:default:grow", "5dlu", "pref", "5dlu"};
        final PanelBuilder builder = ComponentFactory.createBuilder(columnSpecs, rowSpecs);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator(textWithMnemonic, cc.xyw(2, 2, 3));
        builder.add(ComponentFactory.createScrollPane(simpleReportScrollPane), cc.xyw(2, 4, 3));
        builder.add(ComponentFactory.createSaveButton("Save as PDF", true, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                final JFileChooser fileChooser = new JFileChooser();
                int returnValue = fileChooser.showSaveDialog(simpleReportScrollPane);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    try {
                        OutputStream os = new FileOutputStream(fileChooser.getSelectedFile());
                        ITextRenderer renderer = new ITextRenderer();
                        renderer.setDocument(htmlPanel.getDocument(), "file:///");
                        renderer.layout();
                        renderer.createPDF(os);

                        os.close();
                    } catch (FileNotFoundException e) {
                        throw new RuntimeException(e);
                    } catch (DocumentException e) {
                        throw new RuntimeException(e);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                }
            }
        }), cc.xyw(2, 6, 1));

        return ComponentFactory.createPanel(builder);
    }

    private JPanel getDetailledReportText() {
        final String[] columnSpecs = new String[]{"5dlu", "fill:default:grow", "5dlu"};
        final String[] rowSpecs = new String[]{"5dlu", "pref", "5dlu", "fill:default:grow", "5dlu"};
        final PanelBuilder builder = ComponentFactory.createBuilder(columnSpecs, rowSpecs);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator("Detailled Report XML", cc.xyw(2, 2, 1));
        builder.add(ComponentFactory.createScrollPane(detailedReportText), cc.xyw(2, 4, 1));

        return ComponentFactory.createPanel(builder);
    }

    private JPanel getDiagnosticPanel() {
        final String[] columnSpecs = new String[]{"5dlu", "fill:default:grow", "5dlu"};
        final String[] rowSpecs = new String[]{"5dlu", "pref", "5dlu", "fill:default:grow", "5dlu"};
        final PanelBuilder builder = ComponentFactory.createBuilder(columnSpecs, rowSpecs);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator("Diagnostic Tree", cc.xyw(2, 2, 1));
        builder.add(ComponentFactory.createScrollPane(diagnostic), cc.xyw(2, 4, 1));

        return ComponentFactory.createPanel(builder);
    }

    private JPanel getDiagnosticPanelText() {
        final String[] columnSpecs = new String[]{"5dlu", "fill:default:grow", "5dlu"};
        final String[] rowSpecs = new String[]{"5dlu", "pref", "5dlu", "fill:default:grow", "5dlu"};
        final PanelBuilder builder = ComponentFactory.createBuilder(columnSpecs, rowSpecs);
        final CellConstraints cc = new CellConstraints();

        builder.addSeparator("Diagnostic XML", cc.xyw(2, 2, 1));
        builder.add(ComponentFactory.createScrollPane(diagnosticText), cc.xyw(2, 4, 1));

        return ComponentFactory.createPanel(builder);
    }

    /**
     * fully expand the tree
     *
     * @param tree
     */
    private void expandTree(JTree tree) {
        // expand all
//        for (int i = 0; i < tree.getRowCount(); i++) {
        int i = 0;
        tree.expandRow(i);
//        }
    }

}
