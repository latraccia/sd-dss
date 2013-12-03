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

import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionType;
import eu.europa.ec.markt.tsl.jaxb.tsl.InternationalNamesType;
import eu.europa.ec.markt.tsl.jaxb.tsl.MultiLangNormStringType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceHistoryInstanceType;

import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Historical entry in the TL for the service
 * 
 * 
 * @version $Revision: 2357 $ - $Date: 2013-07-05 16:08:02 +0200 (ven., 05 juil. 2013) $
 */

class HistoricalTrustService extends AbstractTrustService {

   private ServiceHistoryInstanceType service;

   private CurrentTrustService currentTrustService;

   protected AbstractTrustService previousEntry;

   /**
    * Set the previous entry in the Trusted List
    * 
    * @param previousEntry the previousEntry to set
    */
   public void setPreviousEntry(AbstractTrustService previousEntry) {
      this.previousEntry = previousEntry;
   }

   /**
    * The default constructor for TrustServiceHistoryEntry.
    */
   public HistoricalTrustService(ServiceHistoryInstanceType instance, CurrentTrustService currentTrustService) {
      this.service = instance;
      this.currentTrustService = currentTrustService;
   }

   @Override
   protected List<ExtensionType> getExtensions() {
      if (service != null && service.getServiceInformationExtensions() != null) {
         return service.getServiceInformationExtensions().getExtension();
      } else {
         return Collections.emptyList();
      }
   }

   @Override
   protected DigitalIdentityListType getServiceDigitalIdentity() {
      /* The X509Certificate is saved on the current instance only */
      return currentTrustService.getServiceDigitalIdentity();
   }

   @Override
   public CurrentTrustService getCurrentServiceInfo() {
      return currentTrustService;
   }

   @Override
   public String getStatus() {
      return service.getServiceStatus();
   }

   @Override
   public Date getStatusStartDate() {
      return service.getStatusStartingTime().toGregorianCalendar().getTime();
   }

   @Override
   public Date getStatusEndDate() {
      return previousEntry.getStatusStartDate();
   }

   @Override
   public String getType() {
      return service.getServiceTypeIdentifier();
   }

   @Override
   public String getServiceName() {
      /* Return the English name or the first name */
      InternationalNamesType names = service.getServiceName();
      for (MultiLangNormStringType s : names.getName()) {
         if ("en".equalsIgnoreCase(s.getLang())) {
            return s.getValue();
         }
      }
      return names.getName().get(0).getValue();
   }

}
