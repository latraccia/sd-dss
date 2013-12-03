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

import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;

import java.io.Serializable;
import java.util.List;

/**
 * Condition resulting of the composition of other Condition
 * 
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (lun., 06 juin 2011) $
 */

public class CompositeCriteriaList implements Condition, Serializable {

    private static final long serialVersionUID = 904590921979120791L;

    /**
     * How the conditions are aggregated.
     * 
     * <p>
     * DISCLAIMER: Project owner DG-MARKT.
     * 
     * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (lun., 06 juin 2011) $
     * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
     */
    public static enum Composition {
        atLeastOne, all, none
    }

    private Condition[] conditions;

    private Composition composition;

    /**
     * The default constructor for CompositeCriteriaList.
     */
    public CompositeCriteriaList() {
    }

    /**
     * 
     * The default constructor for CompositeCriteriaList.
     * 
     * @param conditions
     */
    public CompositeCriteriaList(Composition composition, Condition... conditions) {
        this.composition = composition;
        this.conditions = conditions;
    }
    
    /**
     * @return the composition
     */
    public Composition getComposition() {
        return composition;
    }
    
    /**
     * @return the conditions
     */
    public Condition[] getConditions() {
        return conditions;
    }

    /**
     * 
     * The default constructor for CompositeCriteriaList.
     * 
     * @param composition
     * @param conditions
     */
    public CompositeCriteriaList(Composition composition, List<Condition> conditions) {
        this(composition, conditions.toArray(new Condition[conditions.size()]));
    }

    @Override
    public boolean check(CertificateAndContext cert) {
        switch (composition) {
        case all:
            for (Condition c : conditions) {
                if (!c.check(cert)) {
                    return false;
                }
            }
            return true;
        case atLeastOne:
            for (Condition c : conditions) {
                if (c.check(cert)) {
                    return true;
                }
            }
            return false;
        case none:
            for (Condition c : conditions) {
                if (c.check(cert)) {
                    return false;
                }
            }
            return true;
        }
        throw new IllegalStateException("Unsupported Composition " + composition);
    }

}
