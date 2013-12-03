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

package eu.europa.ec.markt.tlmanager.model;

import eu.europa.ec.markt.tlmanager.TSLComposer;
import eu.europa.ec.markt.tlmanager.TSLComposerEvent;
import eu.europa.ec.markt.tlmanager.model.treeNodes.ExtensionNode;
import eu.europa.ec.markt.tlmanager.model.treeNodes.HistoryNode;
import eu.europa.ec.markt.tlmanager.model.treeNodes.PointerNode;
import eu.europa.ec.markt.tlmanager.model.treeNodes.QualificationNode;
import eu.europa.ec.markt.tlmanager.model.treeNodes.ServiceNode;
import eu.europa.ec.markt.tlmanager.model.treeNodes.TSLDataNode;
import eu.europa.ec.markt.tlmanager.model.treeNodes.TSLRootNode;
import eu.europa.ec.markt.tlmanager.model.treeNodes.TSPNode;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationElementType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionsListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.OtherTSLPointerType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPServiceType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TrustStatusListType;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;

/**
 * A custom <code>DefaultTreeModel</code> that observes the <code>TSLComposer</code> for <code>TSLComposerEvent</code>'s
 * and adds new <code>TSLDataNode</code>'s to the model.
 * 
 *
 * @version $Revision: 2992 $ - $Date: 2013-11-15 17:10:33 +0100 (ven., 15 nov. 2013) $
 */

public class TSLTreeModel extends DefaultTreeModel implements TreeModel, Observer {

    private static final Logger LOG = Logger.getLogger(TSLTreeModel.class.getName());
    private TSLComposer composer;

    /**
     * A <code>Comparator</code> for comparing <code>TSLDataNode</code>'s in a lexicographical way.
     */
    public static Comparator lexicalNodeComparator = new Comparator() {
        public int compare(Object o1, Object o2) {
            if (o1 instanceof TSLDataNode && o2 instanceof TSLDataNode) {
                return ((TSLDataNode) o1).getLabel().compareTo(((TSLDataNode) o2).getLabel());
            }
            return 0;
        }
    };

    /**
     * The default constructor for TSLTreeModel.
     * 
     * @param composer the <code>TSLComposer</code>
     */
    public TSLTreeModel(TSLComposer composer) {
        super(null);
        this.composer = composer;
        this.composer.addObserver(this);
    }

    private List<? extends Object> getChildren(Object parent) {
        LOG.log(Level.FINE, "Getting children of node {0}", parent);

        if (parent instanceof TSLDataNode) {
            TSLDataNode tslDataNode = (TSLDataNode) parent;
            List<Object> children = tslDataNode.getChildren();
            
            return children;
        } else {
            LOG.log(Level.WARNING, "No information for node {0}", parent.getClass().getSimpleName());
            return Collections.EMPTY_LIST;
        }
    }

    @Override
    public Object getChild(Object parent, int index) {
        LOG.log(Level.FINE, "Get child {0} for {1}", new Object[] { index, parent });
        return getChildren(parent).get(index);
    }

    @Override
    public int getChildCount(Object parent) {
        LOG.log(Level.FINE, "Get child count for {0}", parent);
        return getChildren(parent).size();
    }

    @Override
    public boolean isLeaf(Object node) {
        boolean isLeaf = getChildren(node).isEmpty();
        LOG.log(Level.FINE, "The node {0} {1} a leaf node", new Object[] { node, isLeaf ? "is" : "isn't" });
        return isLeaf;
    }

    @Override
    public int getIndexOfChild(Object parent, Object child) {
        LOG.log(Level.FINE, "Index of child {0} in parent {1}", new Object[] { child, parent });
        return getChildren(parent).indexOf(child);
    }

    /**
     * The TSLTreeModel is an adapter between JTree and the TSLComposer. At the construction time, this TSLTreeModel
     * registers himself to the TSLComposer. Every change made to the TSLComposer will trigger this update method.
     * 
     * @param o The TSLComposer from who this event comes.
     * @param obj A representation of the event.
     */
    @Override
    public void update(Observable o, Object obj) {
        LOG.log(Level.FINE, "Received event {0} from observable {1}", new Object[] { obj, o });

        if (obj instanceof TSLComposerEvent) {
            TSLComposerEvent event = (TSLComposerEvent) obj;
            Object data = event.getData();
            DefaultMutableTreeNode parentNode = (DefaultMutableTreeNode) event.getParentNode();
            if (event.getEventCode().equals(TSLComposerEvent.REMOVE_NODE)) {
                // in this case, 'parentNode' is the actual node to remove
                removeNodeFromParent(parentNode);
                composer.removeAllUserObjectsFromAssociatedMap(parentNode);
            } else if (event.getEventCode().equals(TSLComposerEvent.SORT_NODE)) {
                // in this case, 'parentNode' is the actual node on which sort was called
                fireModelChanged(data, parentNode.getPath());
            } else if (data != null) {
                if (data instanceof TrustStatusListType) {
                    TSLRootNode tslRootNode = new TSLRootNode((TrustStatusListType) data);
                    super.setRoot(tslRootNode);
                    fireModelChanged(data, tslRootNode.getPath());

                } else if (data instanceof OtherTSLPointerType) {
                    PointerNode pointerNode = new PointerNode((OtherTSLPointerType) data);
                    parentNode.add(pointerNode);
                    fireModelChanged(data, pointerNode.getPath());

                } else if (data instanceof TSPType) { // may create 2 nodes at once !!
                    TSPType tspType = (TSPType) data;
                    TSPNode tspNode = new TSPNode(tspType);
                    parentNode.add(tspNode);
                    TreeNode[] tspPath = tspNode.getPath();
                    if (tspType.getTSPServices() != null && !tspType.getTSPServices().getTSPService().isEmpty()) {
                        TSPServiceType serviceType = tspType.getTSPServices().getTSPService().get(0);
                        ServiceNode serviceNode = new ServiceNode(serviceType);
                        tspNode.add(serviceNode);
                        TreeNode[] servicePath = serviceNode.getPath();
                        composer.addValidationAssociation(tspType, tspPath); // don't forget these!
                        fireModelChanged(serviceType, servicePath);
                    } else {
                        fireModelChanged(tspType, tspPath);
                    }

                } else if (data instanceof TSPServiceType) {
                    ServiceNode serviceNode = new ServiceNode((TSPServiceType) data);
                    parentNode.add(serviceNode);
                    fireModelChanged(data, serviceNode.getPath());

                } else if (data instanceof ExtensionsListType) {
                    ExtensionNode extensionNode = new ExtensionNode((ExtensionsListType) data);
                    parentNode.add(extensionNode);
                    fireModelChanged(data, extensionNode.getPath());

                } else if (data instanceof ServiceHistoryInstanceType) {
                    HistoryNode historyNode = new HistoryNode((ServiceHistoryInstanceType) data);
                    parentNode.insert(historyNode, 0);
                    fireModelChanged(data, historyNode.getPath());

                } else if (data instanceof QualificationElementType) {
                    QualificationNode qualificationNode = new QualificationNode((QualificationElementType) data);
                    parentNode.add(qualificationNode);
                    fireModelChanged(data, qualificationNode.getPath());

                }
            }
        }
    }

    protected void fireModelChanged(Object obj, TreeNode[] path) {
        if (obj != null) {
            composer.addValidationAssociation(obj, path);
        }
        synchronized (listenerList) {
            for (TreeModelListener l : listenerList.getListeners(TreeModelListener.class)) {
                TreeModelEvent e = new TreeModelEvent(this, path);
                l.treeStructureChanged(e);
            }
        }
    }

    /**
     * Triggers a <code>TreeModelEvent</code> whenever a node has changed.
     * 
     * @param path the path to the node that has changed
     */
    public void fireNodeChanged(TreePath path) {
        synchronized (listenerList) {
            for (TreeModelListener l : listenerList.getListeners(TreeModelListener.class)) {
                TreeModelEvent e = new TreeModelEvent(this, path);
                l.treeNodesChanged(e);
            }
        }
    }
}