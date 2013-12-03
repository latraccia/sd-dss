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

package eu.europa.ec.markt.dss.validation.tsl;

/**
 * 
 * 
 * 
 * @version $Revision: 1739 $ - $Date: 2013-03-08 15:48:22 +0100 (ven., 08 mars 2013) $
 */

public class QualificationElement {

    private String qualification;

    private Condition condition;

    /**
     * The default constructor for QualificationElement.
     */
    public QualificationElement(String qualification, Condition condition) {
        this.qualification = qualification;
        this.condition = condition;
    }

    /**
     * @return the condition
     */
    public Condition getCondition() {
        return condition;
    }

    /**
     * @return the qualification
     */
    public String getQualification() {
        return qualification;
    }

    /**
     * @param condition the condition to set
     */
    public void setCondition(Condition condition) {
        this.condition = condition;
    }

    /**
     * @param qualification the qualification to set
     */
    public void setQualification(String qualification) {
        this.qualification = qualification;
    }

    @Override
    public String toString() {

        return toString("");
    }

    public String toString(String indentStr) {

        String res = "";
        res += indentStr + "[QualificationElement\r\n";
        indentStr += "\t";
        res += indentStr + "Qualification: " + getQualification() + "\r\n";
        res += indentStr + "Condition: " + getCondition() + "\r\n";
        indentStr = indentStr.substring(1);
        res += indentStr + "]\r\n";
        return res;
    }

}
