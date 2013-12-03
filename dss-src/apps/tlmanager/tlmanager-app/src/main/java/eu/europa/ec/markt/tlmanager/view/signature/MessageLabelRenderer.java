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

import eu.europa.ec.markt.tlmanager.core.validation.ValidationLogger;
import eu.europa.ec.markt.tlmanager.core.validation.ValidationLogger.Message;

import java.awt.Component;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.ListCellRenderer;

/**
 * A renderer for <code>JLabel</code>'s in a list.
 * 
 *
 * @version $Revision: 1121 $ - $Date: 2011-11-22 09:36:10 +0100 (mar., 22 nov. 2011) $
 */

public class MessageLabelRenderer extends DefaultListCellRenderer {
    /** {@inheritDoc} */
    @Override
    public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected,
            boolean cellHasFocus) {
        super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);

        ValidationLogger.Message msg = (Message) value;
        JLabel label = msg.getLabel();
        if (label != null) {
            setIcon(label.getIcon());
            setText(label.getText());
        }

        return this;
    }
}