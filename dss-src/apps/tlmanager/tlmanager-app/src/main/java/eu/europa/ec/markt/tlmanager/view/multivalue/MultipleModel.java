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

package eu.europa.ec.markt.tlmanager.view.multivalue;

/**
 * Interface for wrapping all multiple value related value models.
 * 
 *
 * @version $Revision: 2519 $ - $Date: 2013-09-10 17:26:58 +0200 (mar., 10 sept. 2013) $
 */

public interface MultipleModel<T> extends MultivalueModel<T> {
    /**
     * Removes the item that is associated to the specified key
     * 
     * @param key the key
     */
    public void removeItem(String key);

    /**
     * In case there is an additional bean as value holder (besides the key/value based structure that holds the
     * (temporary) values coming from the ui), the method can be used to refresh its values.
     */
    public void updateBeanValues();

    /**
     * Creates a new Item in the model and returns the associated key for it.
     */
    public String createNewItem();
}