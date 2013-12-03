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

import eu.europa.ec.markt.tlmanager.core.Configuration;
import eu.europa.ec.markt.tlmanager.util.ItemDuplicator;
import eu.europa.ec.markt.tlmanager.view.multivalue.LingualModel;
import eu.europa.ec.markt.tsl.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.NonEmptyMultiLangURIType;

import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Adapter for a list of <code>NonEmptyMultiLangURIListType</code>. It implements the <code>LingualModel</code> and
 * works directly on the given bean.
 * 
 *
 * @version $Revision: 2848 $ - $Date: 2013-11-04 14:15:28 +0100 (lun., 04 nov. 2013) $
 */

public class NonEmptyMultiLangURIListAdapter implements LingualModel<String> {

    private NonEmptyMultiLangURIListType multiLangUris;
    private String initialValueKey = null;

    /**
     * The default constructor for NonEmptyMultiLangURIListAdapter.
     * 
     * @param multiLangUris
     */
    public NonEmptyMultiLangURIListAdapter(NonEmptyMultiLangURIListType multiLangUris) {
        this.multiLangUris = multiLangUris;
        initialValueKey = Configuration.getInstance().getLanguageCodes().getFirstLanguage();

        handleDuplicates();
    }

    private void handleDuplicates() {
        Map<String, Integer> entries = new HashMap<String, Integer>();
        for (NonEmptyMultiLangURIType uri : multiLangUris.getURI()) {
            String lang = uri.getLang();
            if (lang == null) {
                lang = Configuration.LanguageCodes.getEnglishLanguage();
                uri.setLang(lang);
            }
            if (entries.containsKey(lang)) {
                Integer counter = entries.get(lang);
                uri.setLang(ItemDuplicator.duplicate(lang, ++counter));
                entries.put(lang, counter);
            } else {
                entries.put(lang, 0);
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public String getValue(String key) {
        for (NonEmptyMultiLangURIType s : multiLangUris.getURI()) {
            String lang = s.getLang();
            if (lang != null && lang.equals(key)) {
                return s.getValue();
            }
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public void setValue(String key, String strValue) {
        for (NonEmptyMultiLangURIType s : multiLangUris.getURI()) {
            String lang = s.getLang();
            if (lang != null && lang.equals(key)) {
                if (strValue.isEmpty()) {
                    multiLangUris.getURI().remove(s);
                } else {
                    s.setValue(strValue);
                }
                return;
            }
        }
        if (!strValue.isEmpty()) {
            NonEmptyMultiLangURIType s = new NonEmptyMultiLangURIType();
            s.setLang(key);
            s.setValue(strValue);
            multiLangUris.getURI().add(s);
        }
    }

    /** {@inheritDoc} */
    @Override
    public String getInitialValueKey() {
        return initialValueKey;
    }

    /**
     * @return the multiLangUris
     */
    public NonEmptyMultiLangURIListType getMultiLangUris() {
        return multiLangUris;
    }

    /** {@inheritDoc} */
    @Override
    public List<String> getKeys() {
        List<String> list = new ArrayList<String>();
        for (NonEmptyMultiLangURIType key : multiLangUris.getURI()) {
            list.add(key.getLang());
        }
        return list;
    }

    /** {@inheritDoc} */
    @Override
    public int size() {
        return multiLangUris.getURI().size();
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