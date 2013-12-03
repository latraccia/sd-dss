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

import org.apache.commons.lang.StringUtils;

import eu.europa.ec.markt.tlmanager.util.Util;
import eu.europa.ec.markt.tlmanager.view.multivalue.MultipleModel;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualifierType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualifiersType;

/**
 * Adapter for a list of <code>NonEmptyURIListType</code>. It implements the <code>MultipleModel</code> and uses a
 * hashmap as working copy of the managed entries. On request, the bean is updated and given back.
 * 
 *
 * @version $Revision$ - $Date$
 */

public class QualifiersTypeAdapter implements MultipleModel<String> {

    private QualifiersType qualifiersType;
    private Map<String, String> values = new HashMap<String, String>();
    private String initialValueKey = null;
    private int createdEntryCounter = 0;

    /**
     * The default constructor for QualifiersTypeAdapter.
     *
     * @param qualifiersType the <code>QualifiersType</code>
     */
    public QualifiersTypeAdapter(QualifiersType qualifiersType) {
        this.qualifiersType = qualifiersType;
        initialValueKey = Util.getInitialCounterItem();
        if (qualifiersType != null && qualifiersType.getQualifier() != null && !qualifiersType.getQualifier().isEmpty()) {
            for (QualifierType qualifierType : qualifiersType.getQualifier()) {
                if (qualifierType != null) {
                    setValue(Util.getCounterItem(createdEntryCounter++), qualifierType.getUri());
                }
            }
        } else {
            createNewItem();
        }
    }

    /** {@inheritDoc} */
    @Override
    public String getValue(String key) {
        return values.get(key);
    }

    /** {@inheritDoc} */
    @Override
    public void setValue(String key, String value) {
        values.put(key, value);
    }

    /** {@inheritDoc} */
    @Override
    public void removeItem(String key) {
        values.remove(key);
    }

    /** {@inheritDoc} */
    @Override
    public void updateBeanValues() {
        qualifiersType.getQualifier().clear();
        for (String value : values.values()) {
            if (StringUtils.isNotBlank(value) && !StringUtils.equals(value, Util.DEFAULT_NO_SELECTION_ENTRY)) {
                final QualifierType qualifierType = new QualifierType();
                qualifierType.setUri(value);
                qualifiersType.getQualifier().add(qualifierType);
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public String createNewItem() {
        String key = Util.getCounterItem(createdEntryCounter++);
        setValue(key, Util.DEFAULT_NO_SELECTION_ENTRY);

        return key;
    }

    /** {@inheritDoc} */
    @Override
    public String getInitialValueKey() {
        return initialValueKey;
    }

    /**
     * @return the qualifiersType
     */
    public QualifiersType getQualifiersType() {
        return qualifiersType;
    }

    /** {@inheritDoc} */
    @Override
    public List<String> getKeys() {
        return new ArrayList<String>(values.keySet());
    }

    /** {@inheritDoc} */
    @Override
    public int size() {
        int size = 0;
        for (String value : values.values()) {
            if (!Util.DEFAULT_NO_SELECTION_ENTRY.equals(value)) {
                size++;
            }
        }
        return size;
    }

    @Override
    public Dimension getRecommendedDialogSize() {
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public boolean isEmpty() {
        return size() == 0;
    }


}