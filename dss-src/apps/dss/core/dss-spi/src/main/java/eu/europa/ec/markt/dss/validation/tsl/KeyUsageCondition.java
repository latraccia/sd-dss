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

import java.io.Serializable;

import eu.europa.ec.markt.dss.validation.certificate.CertificateAndContext;

/**
 * Test if the certificate has a Key usage
 * 
 * 
 * @version $Revision: 2172 $ - $Date: 2013-05-31 22:38:44 +0200 (ven., 31 mai 2013) $
 */

public class KeyUsageCondition implements Condition, Serializable {

   private static final long serialVersionUID = -7931767601112389304L;

   /**
    * 
    * KeyUsage bit values
    * 
    * <p>
    * DISCLAIMER: Project owner DG-MARKT.
    * 
    * @version $Revision: 2172 $ - $Date: 2013-05-31 22:38:44 +0200 (ven., 31 mai 2013) $
    * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
    */
   public static enum KeyUsageBit {

      digitalSignature(0), nonRepudiation(1), keyEncipherment(2), dataEncipherment(3), keyAgreement(4), keyCertSign(5), crlSign(6), encipherOnly(7), decipherOnly(8);

      int index;

      /**
       * The default constructor for KeyUsageCondition.KeyUsageBit.
       */
      private KeyUsageBit(int index) {
         this.index = index;
      }

   }

   private KeyUsageBit bit;

   /**
    * The default constructor for KeyUsageCondition.
    */
   public KeyUsageCondition() {
   }

   /**
    * 
    * The default constructor for KeyUsageCondition.
    * 
    * @param bit
    */
   public KeyUsageCondition(KeyUsageBit bit) {
      this.bit = bit;
   }

   /**
    * 
    * The default constructor for KeyUsageCondition.
    * 
    * @param value
    */
   public KeyUsageCondition(String value) {
      this(KeyUsageBit.valueOf(value));
   }

   /**
    * @return the bit
    */
   public KeyUsageBit getBit() {
      return bit;
   }

   @Override
   public boolean check(CertificateAndContext cert) {
      return cert.getCertificate().getKeyUsage()[bit.index];
   }

}
