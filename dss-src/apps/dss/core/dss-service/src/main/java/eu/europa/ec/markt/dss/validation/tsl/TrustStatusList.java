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

import eu.europa.ec.markt.tsl.jaxb.tsl.OtherTSLPointerType;
import eu.europa.ec.markt.tsl.jaxb.tsl.OtherTSLPointersType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TrustServiceProviderListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TrustStatusListType;

import java.util.ArrayList;
import java.util.List;

/**
 * 
 * Represents a Trusted List
 * 
 * 
 * @version $Revision: 2468 $ - $Date: 2013-08-29 08:08:43 +0200 (jeu., 29 août 2013) $
 */
class TrustStatusList {

   private TrustStatusListType trustStatusListType;

   private boolean wellSigned = false;

   /**
    * 
    * The default constructor for TrustStatusList.
    * 
    * @param trustStatusListType
    */
   public TrustStatusList(TrustStatusListType trustStatusListType) {
      this.trustStatusListType = trustStatusListType;
   }

   /**
    * @param wellSigned the wellSigned to set
    */
   public void setWellSigned(boolean wellSigned) {
      this.wellSigned = wellSigned;
   }

   /**
    * @return the wellSigned
    */
   public boolean isWellSigned() {
      return wellSigned;
   }

   /**
    * Returns the list of providers in this trusted list
    * 
    * @return
    */
   public List<TrustServiceProvider> getTrustServicesProvider() {
     
      final List<TrustServiceProvider> list = new ArrayList<TrustServiceProvider>();

      final TrustServiceProviderListType tspListType = trustStatusListType.getTrustServiceProviderList();
      if (tspListType == null) {
         return list;
      }

      final List<TSPType> tspTypes = tspListType.getTrustServiceProvider();
      if (tspTypes == null) {
         return list;
      }

      for (final TSPType tsp : tspTypes) {
         list.add(new TrustServiceProvider(tsp));
      }
      return list;
   }

   /**
    * Return pointer to other TSL (with mime/type = application/vnd.etsi.tsl+xml)
    * 
    * @return
    */
   public List<PointerToOtherTSL> getOtherTSLPointers() {
      final List<PointerToOtherTSL> list = new ArrayList<PointerToOtherTSL>();

      final TSLSchemeInformationType tsiType = trustStatusListType.getSchemeInformation();
      if (tsiType == null) {
         return list;
      }

      final OtherTSLPointersType pointerListType = tsiType.getPointersToOtherTSL();
      if (pointerListType == null) {
         return list;
      }

      final List<OtherTSLPointerType> pointerTypes = pointerListType.getOtherTSLPointer();
      if (pointerTypes == null) {
         return list;
      }

      for (OtherTSLPointerType p : pointerTypes) {
         PointerToOtherTSL pointer = new PointerToOtherTSL(p);
         if ("application/vnd.etsi.tsl+xml".equals(pointer.getMimeType())) {
            list.add(pointer);
         }
      }
      return list;
   }

}
