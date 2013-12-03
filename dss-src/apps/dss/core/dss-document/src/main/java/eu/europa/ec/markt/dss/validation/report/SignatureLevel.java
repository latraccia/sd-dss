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

package eu.europa.ec.markt.dss.validation.report;

import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation.pades.PAdESSignature;
import eu.europa.ec.markt.dss.validation.xades.XAdESSignature;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * Base class for SignatureLevel related classes.
 * 
 * 
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */
@XmlType
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class SignatureLevel {

    public static final String FORMAT_PADES = "PAdES";
    public static final String FORMAT_CADES = "CAdES";
    public static final String FORMAT_XADES = "XAdES";

    // possible "inheritance" of signature levels
    // EPES                                     if BES
    // LTV                                      if BES
    // A   if   XL   if   X   if   C   if   T   if BES
    public static final String LEVEL_BES = "BES";
    public static final String LEVEL_EPES = "EPES";
    public static final String LEVEL_T = "T";
    public static final String LEVEL_C = "C";
    public static final String LEVEL_X = "X";
    public static final String LEVEL_XL = "XL";
    public static final String LEVEL_A = "A";
    public static final String LEVEL_LTV = "LTV";

    @XmlElement
    private Result levelReached;

    public SignatureLevel() {
    }

    /**
     * The default constructor for SignatureLevel.
     * 
     * @param signature
     * @param levelReached
     */
    public SignatureLevel(Result levelReached) {
        this.levelReached = levelReached;
    }

    /**
     * @return the levelReached
     */
    public Result getLevelReached() {
        return levelReached;
    }

    /**
     * returns the acronym associated to a specific format/signature:
     * {@link #FORMAT_PADES}, {@link #FORMAT_CADES} or {@link #FORMAT_XADES}
     *
     * @param signature the instance (or null)
     * @return the acronym or null
     */
    public static String toAcronym(final AdvancedSignature signature) {
        if (signature instanceof PAdESSignature ) {
            return FORMAT_PADES;
        } else if (signature instanceof CAdESSignature ) {
            return FORMAT_CADES;
        } else if (signature instanceof XAdESSignature ) {
            return FORMAT_XADES;
        } else {
            return null;
        }
    }

    /**
     * returns the acronym associated to a specific level:
     * {@link #LEVEL_BES}, {@link #LEVEL_EPES}, {@link #LEVEL_T}, {@link #LEVEL_C}, {@link #LEVEL_X}, {@link #LEVEL_XL}, {@link #LEVEL_A} or {@link #LEVEL_LTV}
     *
     * @param level the instance (or null)
     * @return the acronym or null
     */
    public static String toAcronym(final SignatureLevel level) {
        if ( level instanceof SignatureLevelBES) {
            return LEVEL_BES;
        } else if ( level instanceof SignatureLevelEPES) {
            return LEVEL_EPES;
        } else if ( level instanceof SignatureLevelT) {
            return LEVEL_T;
        } else if ( level instanceof SignatureLevelC) {
            return LEVEL_C;
        } else if ( level instanceof SignatureLevelX) {
            return LEVEL_X;
        } else if ( level instanceof SignatureLevelXL) {
            return LEVEL_XL;
        } else if ( level instanceof SignatureLevelA) {
            return LEVEL_A;
        } else if ( level instanceof SignatureLevelLTV) {
            return LEVEL_LTV;
        }
        return null;
    }

}
