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

package eu.europa.ec.markt.tlmanager.view.binding;

import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jdesktop.beansbinding.Converter;

/**
 * Does the conversion between a <code>BigInteger</code> and a <code>String</code>
 * 
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (lun., 06 juin 2011) $
 */

public class BigIntegerConverter extends Converter<BigInteger, String> {
    private static final Logger LOG = Logger.getLogger(BigIntegerConverter.class.getName());

    /** {@inheritDoc} */
    @Override
    public String convertForward(BigInteger source) {
        return source.toString();
    }

    /** {@inheritDoc} */
    @Override
    public BigInteger convertReverse(String target) {
        BigInteger bigInteger = null;
        if (target != null && !target.isEmpty()) {
            try {
                bigInteger = new BigInteger(target);
            } catch (NumberFormatException nfe) {
                LOG.log(Level.WARNING, "Unable to create a BigInteger from: " + target);
            }
        }

        return bigInteger;
    }
}