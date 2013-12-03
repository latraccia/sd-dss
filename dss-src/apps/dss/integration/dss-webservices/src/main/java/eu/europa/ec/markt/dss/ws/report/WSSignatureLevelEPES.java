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

package eu.europa.ec.markt.dss.ws.report;

import eu.europa.ec.markt.dss.validation.report.SignatureLevelEPES;

/**
 * Wrap data of a SignatureLevelEPES. Used to expose the information in the Webservice.
 * 
 *
 * @version $Revision: 990 $ - $Date: 2011-06-16 16:56:41 +0200 (jeu., 16 juin 2011) $
 */

public class WSSignatureLevelEPES {

    private String levelReached;

    private String policyValue;

    /**
     * The default constructor for WSSignatureLevelEPES.
     */
    public WSSignatureLevelEPES() {
    }

    /**
     * 
     * The default constructor for WSSignatureLevelEPES.
     * 
     * @param level
     */
    public WSSignatureLevelEPES(SignatureLevelEPES level) {
        levelReached = level.getLevelReached().getStatus().toString();
        if (level.getPolicyId() != null) {
            policyValue = level.getPolicyId().toString();
        }
    }

    /**
     * @return the levelReached
     */
    public String getLevelReached() {
        return levelReached;
    }

    /**
     * @param levelReached the levelReached to set
     */
    public void setLevelReached(String levelReached) {
        this.levelReached = levelReached;
    }

    /**
     * @return the policyValue
     */
    public String getPolicyValue() {
        return policyValue;
    }

    /**
     * @param policyValue the policyValue to set
     */
    public void setPolicyValue(String policyValue) {
        this.policyValue = policyValue;
    }

}
