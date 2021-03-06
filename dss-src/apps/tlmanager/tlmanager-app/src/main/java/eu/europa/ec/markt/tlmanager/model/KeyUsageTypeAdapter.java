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

import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import eu.europa.ec.markt.tlmanager.util.Util;
import eu.europa.ec.markt.tlmanager.view.multivalue.MultipleModel;
import eu.europa.ec.markt.tlmanager.view.panel.KeyUsageModel;
import eu.europa.ec.markt.tsl.jaxb.ecc.KeyUsageType;

/**
 * Adapter for a list of <code>KeyUsageTypeAdapter</code>. It implements the <code>MultipleModel</code> and uses a
 * hashmap as working copy of the managed entries. On request, the bean is updated and given back.
 *
 * @version $Revision$ - $Date$
 */

public class KeyUsageTypeAdapter implements MultipleModel<KeyUsageModel> {

    private List<KeyUsageType> keyUsageTypeList;
    private Map<String, KeyUsageModel> values = new HashMap<String, KeyUsageModel>();
    private String initialValueKey = null;
    private int createdEntryCounter = 0;

    /**
     * @param keyUsageTypeList
     */
    public KeyUsageTypeAdapter(List<KeyUsageType> keyUsageTypeList) {
        this.keyUsageTypeList = keyUsageTypeList;

        initialValueKey = Util.getInitialCounterItem();

        if (keyUsageTypeList != null && !keyUsageTypeList.isEmpty()) {
            for (KeyUsageType keyUsageType : keyUsageTypeList) {
                KeyUsageModel keyUsageModel = new KeyUsageModel(keyUsageType);
                if (!keyUsageModel.isEmpty()) {
                    setValue(Util.getCounterItem(createdEntryCounter++), keyUsageModel);
                }
            }
        } else {
            createNewItem();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KeyUsageModel getValue(String key) {
        return values.get(key);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setValue(String key, KeyUsageModel value) {
        if (value != null) {
            values.put(key, value);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void removeItem(String key) {
        values.remove(key);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void updateBeanValues() {
        // just trigger updating
        getKeyUsageTypeList();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createNewItem() {
        String key = Util.getCounterItem(createdEntryCounter++);
        setValue(key, new KeyUsageModel());

        return key;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getInitialValueKey() {
        return initialValueKey;
    }

    /**
     * @return the KeyUsageType list
     */
    public List<KeyUsageType> getKeyUsageTypeList() {
        keyUsageTypeList.clear();

        for (KeyUsageModel value : values.values()) {
            keyUsageTypeList.add(value.getKeyUsageType());
        }
        return keyUsageTypeList;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getKeys() {
        return new ArrayList<String>(values.keySet());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int size() {
        int size = 0;
        for (KeyUsageModel value : values.values()) {
            if (!value.isEmpty()) {
                size++;
            }
        }
        return size;
    }

    @Override
    public Dimension getRecommendedDialogSize() {
        return new Dimension(850, 280);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isEmpty() {
        return size() == 0;
    }
}
