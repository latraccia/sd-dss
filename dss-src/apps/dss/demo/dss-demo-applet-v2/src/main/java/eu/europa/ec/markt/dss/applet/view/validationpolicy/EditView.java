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
import eu.europa.ec.markt.dss.applet.component.model.validation.AbstractListNode;
import eu.europa.ec.markt.dss.applet.component.model.validation.BeanNode;
import eu.europa.ec.markt.dss.applet.component.model.validation.ListValueLeaf;
import eu.europa.ec.markt.dss.applet.component.model.validation.TreeNode;
import eu.europa.ec.markt.dss.applet.component.model.validation.ValidationPolicyTreeCellRenderer2;
import eu.europa.ec.markt.dss.applet.component.model.validation.ValidationPolicyTreeModel;
import eu.europa.ec.markt.dss.applet.component.model.validation.ValidationPolicyTreeRoot;
import eu.europa.ec.markt.dss.applet.component.model.validation.ValueLeaf;
import eu.europa.ec.markt.dss.applet.model.ValidationPolicyModel;
import eu.europa.ec.markt.dss.applet.util.ComponentFactory;
import eu.europa.ec.markt.dss.applet.util.ResourceUtils;
import eu.europa.ec.markt.dss.applet.wizard.validationpolicy.ValidationPolicyWizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardView;

import javax.swing.*;
import javax.swing.tree.TreeCellRenderer;
import javax.swing.tree.TreePath;
import javax.xml.bind.annotation.XmlElement;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.lang.reflect.Field;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

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
public class EditView extends WizardView<ValidationPolicyModel, ValidationPolicyWizardController> {

    private JTree validationPolicyTree;
    private JScrollPane scrollPane;
    private ValidationPolicyTreeModel validationPolicyTreeModel;
    final TreeCellRenderer treeCellRenderer = new ValidationPolicyTreeCellRenderer2();

    /**
     * The default constructor for EditView.
     *
     * @param core
     * @param controller
     * @param model
     */
    public EditView(AppletCore core, ValidationPolicyWizardController controller, ValidationPolicyModel model) {
        super(core, controller, model);

        validationPolicyTree = ComponentFactory.tree("tree", new ValidationPolicyTreeModel(null), treeCellRenderer);
        scrollPane = ComponentFactory.createScrollPane(validationPolicyTree);

    }

    @Override
    public void doInit() {
        validationPolicyTreeModel = new ValidationPolicyTreeModel(new ValidationPolicyTreeRoot(getModel().getValidationPolicy()));
        validationPolicyTree = ComponentFactory.tree("tree", validationPolicyTreeModel, treeCellRenderer);

        scrollPane = ComponentFactory.createScrollPane(validationPolicyTree);
        registerMouseListener(validationPolicyTree);
    }

    /**
     * fully expand the tree
     *
     * @param tree
     */
    private void expandTree(JTree tree) {
        // expand all
        for (int i = 0; i < tree.getRowCount(); i++) {
            tree.expandRow(i);
        }
    }

    private void registerMouseListener(final JTree tree) {

        MouseListener mouseAdapter = new MouseAdapter() {
            public void mousePressed(MouseEvent mouseEvent) {
                if (mouseEvent.getButton() == MouseEvent.BUTTON3) {
                    final int selectedRow = tree.getRowForLocation(mouseEvent.getX(), mouseEvent.getY());
                    final TreePath selectedPath = tree.getPathForLocation(mouseEvent.getX(), mouseEvent.getY());
                    if (selectedRow != -1) {
                        final TreeNode clickedItem2 = (TreeNode) selectedPath.getLastPathComponent();
                        // Do nothing on root element
                        if (selectedPath.getPathCount() > 1) {
                            // find the allowed actions, to know if a popup menu should be displayed and the content of the popup menu + action handlers
                            if (clickedItem2 instanceof ValueLeaf) {
                                final ValueLeaf clickedItem = (ValueLeaf) clickedItem2;
                                valueLeafActionEdit(mouseEvent, selectedPath, clickedItem, tree);
                            } else if (clickedItem2 instanceof ListValueLeaf) {
                                final ListValueLeaf clickedItem = (ListValueLeaf) clickedItem2;
                                listValueLeafActionEdit(mouseEvent, selectedPath, clickedItem, tree);
                            } else if (clickedItem2 instanceof AbstractListNode) {
                                final AbstractListNode clickedItem = (AbstractListNode) clickedItem2;
                                abstractListNodeActionDelete(mouseEvent, selectedPath, clickedItem, tree);
                            } else if (clickedItem2 instanceof BeanNode) {
                                final BeanNode clickedItem = (BeanNode) clickedItem2;
                                beanNodeActionAdd(mouseEvent, selectedRow, selectedPath, clickedItem, tree);
                            }

                        }


                    }
                }
            }
        };
        tree.addMouseListener(mouseAdapter);
    }

    private void beanNodeActionAdd(MouseEvent mouseEvent, final int selectedRow, final TreePath selectedPath, final BeanNode clickedItem, final JTree tree) {
        // popup menu for list -> add
        final JPopupMenu popup = new JPopupMenu();
        final Map<Field, Class> listFields = clickedItem.getListFieldsInBean();
        for (final Map.Entry<Field, Class> entry : listFields.entrySet()) {
            final Field listField = entry.getKey();
            final Class<?> itemClass = entry.getValue();
            final String xmlName = listField.getAnnotation(XmlElement.class).name();
            final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("ADD") + " (" + xmlName + ")");
            popup.add(menuItem);
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    int indexOfAddedItem = clickedItem.addListItem(listField, itemClass);
                    final Object addedItem = clickedItem.getListItem(listField, indexOfAddedItem);

                    // find the order# of the child added
                    final List<TreeNode> childrenNode = clickedItem.getChildren();
                    for (int i = 0; i < childrenNode.size(); i++) {
                        TreeNode child = childrenNode.get(i);
                        if (child instanceof AbstractListNode) {
                            final AbstractListNode abstractListNode = (AbstractListNode) child;
                            if (abstractListNode.getItemInList() == addedItem) {
                                indexOfAddedItem = i;
                                break;
                            }
                        }
                    }
                    validationPolicyTreeModel.fireTreeInsert(selectedPath, indexOfAddedItem, addedItem);

                    tree.expandPath(selectedPath);

                    // find again the row corresponding to child added and now displayed
                    int row = selectedRow;
                    while(true){
                        final TreeNode treeNode = (TreeNode) tree.getPathForRow(row).getLastPathComponent();
                        if (treeNode instanceof AbstractListNode) {
                            final AbstractListNode abstractListNode = (AbstractListNode) treeNode;
                            if (abstractListNode.getItemInList() == addedItem) {
                                break;
                            }
                        }
                        row++;
                    }

                    tree.expandRow(row);
                    tree.setSelectionRow(row);

                }
            });

        }
        popup.show(tree, mouseEvent.getX(), mouseEvent.getY());
    }

    private void abstractListNodeActionDelete(MouseEvent mouseEvent, final TreePath selectedPath, final AbstractListNode clickedItem, JTree tree) {
        // List item -> delete
        JPopupMenu popup = new JPopupMenu();
        final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("DELETE"));
        menuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                final Object valueToDelete = clickedItem.getItemInList();
                // find the order# of the child to delete
                int treeIndexOfItemToDelete = -1;
                final List<TreeNode> childrenNode = clickedItem.getParent().getChildren();
                for (int i = 0; i < childrenNode.size(); i++) {
                    TreeNode child = childrenNode.get(i);
                    if (child instanceof AbstractListNode) {
                        final AbstractListNode abstractListNode = (AbstractListNode) child;
                        if (abstractListNode.getItemInList() == valueToDelete) {
                            treeIndexOfItemToDelete = i;
                            break;
                        }
                    }
                }

                final int indexOfDeleted = clickedItem.delete();
                if (indexOfDeleted > -1) {
                    validationPolicyTreeModel.fireTreeNodesRemoved(selectedPath.getParentPath(), treeIndexOfItemToDelete, clickedItem);
                }
            }
        });
        popup.add(menuItem);
        popup.show(tree, mouseEvent.getX(), mouseEvent.getY());
    }

    private void listValueLeafActionEdit(final MouseEvent mouseEvent, final TreePath selectedPath, final ListValueLeaf clickedItem, final JTree tree) {
        // List item : edit
        final JPopupMenu popup = new JPopupMenu();
        if (clickedItem.isBoolean()) {
            final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("TOGGLE"));
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    final Boolean oldValue = (Boolean) clickedItem.getItemInList();
                    try {
                        clickedItem.setNewValue(Boolean.toString(!oldValue));
                    } catch (ParseException e) {
                        throw new RuntimeException(e);
                    }
                    validationPolicyTreeModel.fireTreeChanged(selectedPath);
                }
            });
            popup.add(menuItem);
//        } else if (clickedItem.isDate()) {
        } else {
            final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("EDIT"));
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    final String newValue = JOptionPane.showInputDialog(ResourceUtils.getI18n("EDIT"), clickedItem.getTitle());
                    if (newValue != null) {
                        try {
                            clickedItem.setNewValue(newValue);
                        } catch (ParseException e) {
                            showErrorMessage(newValue, tree);
                        } catch (NumberFormatException e) {
                            showErrorMessage(newValue, tree);
                        }
                        validationPolicyTreeModel.fireTreeChanged(selectedPath);
                    }
                }
            });
            popup.add(menuItem);
        }

        popup.show(tree, mouseEvent.getX(), mouseEvent.getY());

    }

    private void valueLeafActionEdit(final MouseEvent mouseEvent, final TreePath selectedPath, final ValueLeaf clickedItem, final JTree tree) {
        if (clickedItem.isReadOnly()) {
            final JPopupMenu popup = new JPopupMenu();
            final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("CANNOT_BE_CHANGED"));
            menuItem.setEnabled(false);
            popup.add(menuItem);
            popup.show(tree, mouseEvent.getX(), mouseEvent.getY());
        } else {
            final JPopupMenu popup = new JPopupMenu();

            if (clickedItem.isBoolean()) {
                final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("TOGGLE"));
                menuItem.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        final Boolean oldValue = (Boolean) clickedItem.getValue();
                        try {
                            clickedItem.setNewValue(Boolean.toString(!oldValue));
                        } catch (ParseException e) {
                            throw new RuntimeException(e);
                        }

                        validationPolicyTreeModel.fireTreeChanged(selectedPath);
                    }
                });
                popup.add(menuItem);
//            } else if (clickedItem.isDate()) {
            } else {
                // Basic type : edit
                final JMenuItem menuItem = new JMenuItem(ResourceUtils.getI18n("EDIT"));
                menuItem.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        final String newValue = JOptionPane.showInputDialog(ResourceUtils.getI18n("EDIT"), clickedItem.getTitle());
                        if (newValue != null) {
                            try {
                                clickedItem.setNewValue(newValue);
                            } catch (ParseException e) {
                                showErrorMessage(newValue, tree);
                            } catch (NumberFormatException e) {
                                showErrorMessage(newValue, tree);
                            }
                            validationPolicyTreeModel.fireTreeChanged(selectedPath);
                        }
                    }
                });
                popup.add(menuItem);
            }
            popup.show(tree, mouseEvent.getX(), mouseEvent.getY());

        }
    }

    private void showErrorMessage(String newValue, JTree tree) {
        JOptionPane.showMessageDialog(tree, ResourceUtils.getI18n("INVALID_VALUE") + " (" + newValue + ")");
    }

    @Override
    protected Container doLayout() {
        final FormLayout layout = new FormLayout("5dlu, fill:default:grow, 5dlu", "5dlu, fill:default:grow, 5dlu");
        final PanelBuilder builder = ComponentFactory.createBuilder(layout);
        final CellConstraints cc = new CellConstraints();

        builder.add(scrollPane, cc.xy(2, 2));

        return ComponentFactory.createPanel(builder);
    }
}
