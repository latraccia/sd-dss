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

package eu.europa.ec.markt.tlmanager.model.treeNodes;

import eu.europa.ec.markt.tlmanager.core.QNames;
import eu.europa.ec.markt.tlmanager.view.pages.TreeDataPublisher;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionsListType;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.xml.bind.JAXBElement;

/**
 * A custom <code>DefaultMutableTreeNode</code> for representing a <code>ExtensionsListType</code>.
 * 
 *
 * @version $Revision: 1017 $ - $Date: 2011-06-17 15:48:30 +0200 (ven., 17 juin 2011) $
 */

public class ExtensionNode extends DefaultMutableTreeNode implements TSLDataNode {

    private ImageIcon icon;
    private String label;
    private static final String LABEL = "Extensions";

    /**
     * Instantiates a new extension node.
     */
    public ExtensionNode() {
        super(null);
    }

    /**
     * Instantiates a new extension node.
     * 
     * @param userObject the user object
     */
    public ExtensionNode(ExtensionsListType userObject) {
        super(userObject);
        icon = new ImageIcon(getClass().getResource("/icons/extension.png"));
    }

    /**
     * Sets the user object for this node to <code>userObject</code>.
     *
     * @param   userObject  the Object that constitutes this node's 
     *                          user-specified data
     */
    public void setUserObject(ExtensionsListType userObject) {
        super.setUserObject(userObject);
    }

    /** {@inheritDoc} */
    public ExtensionsListType getUserObject() {
        return (ExtensionsListType) userObject;
    }

    /** {@inheritDoc} */
    @Override
    public List<Object> getChildren() {
        List<Object> children = new ArrayList<Object>();

        if (this.children != null) {
            children.addAll(this.children);
        }
        return children;
    }

    /** {@inheritDoc} */
    @Override
    public void sort() {
        if (children != null && !children.isEmpty()) {
            // Note: it does not make sense to have a comparator because all qualifications have the same label
            // Collections.sort(this.children, TSLTreeModel.lexicalNodeComparator);
            
            // trigger sort on children
            for (Object child: children) {
                if (child instanceof TSLDataNode) {
                    ((TSLDataNode) child).sort();
                }
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public String getAssociatedDataPublisherName() {
        return TreeDataPublisher.SERVICE_INFORMATION_EXTENSION_PAGE;
    }

    /**
     * Scans through the userObject to find an extension that contains a <code>JAXBElement</code> with a QName that
     * matches the content of <code>QNames._Qualifications_QNAME</code>.
     * 
     * @return the matching <code>ExtensionType</code>
     */
    public ExtensionType getQualificationExtension() {
        ExtensionsListType extensionsList = this.getUserObject();

        for (ExtensionType extension : extensionsList.getExtension()) {
            List<Object> list = extension.getContent();
            if (list.isEmpty()) {
                continue;
            }
            Object content = list.get(0);
            if (content != null && content instanceof JAXBElement<?>) {
                JAXBElement<?> element = (JAXBElement<?>) content;
                if (QNames._Qualifications_QNAME.equals(element.getName())) {
                    return extension;
                }
            }
        }
        return null;
    }

    /** {@inheritDoc} */
    public Icon getIcon() {
        return icon;
    }

    /** {@inheritDoc} */
    @Override
    public String getLabel() {
        if (label == null) {
            label = LABEL;
        }

        return label;
    }

    /** {@inheritDoc} */
    @Override
    public void resetLabel() {
        label = null;
    }
}