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

import eu.europa.ec.markt.tsl.jaxb.tsl.InternationalNamesType;
import eu.europa.ec.markt.tsl.jaxb.tsl.MultiLangNormStringType;
import eu.europa.ec.markt.tsl.jaxb.tsl.PostalAddressType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPServiceType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Wrapper for the tag TrustServiceProvider
 *
 * @version $Revision: 2841 $ - $Date: 2013-11-04 12:30:53 +0100 (lun., 04 nov. 2013) $
 */

class TrustServiceProvider {

    private TSPType tsp;

    /**
     * 
     * The default constructor for TrustServiceProvider.
     * 
     * @param tsp
     */
    public TrustServiceProvider(TSPType tsp) {
        this.tsp = tsp;
    }

    /**
     * Retrieve the list of service of this provider
     * 
     * @return The list of service and history, in desceding order.
     */
    public List<AbstractTrustService> getTrustServiceList() {

        List<AbstractTrustService> providerList = new ArrayList<AbstractTrustService>();
        
        for (TSPServiceType s : tsp.getTSPServices().getTSPService()) {

            List<AbstractTrustService> list = new ArrayList<AbstractTrustService>();
            
            CurrentTrustService currentService = new CurrentTrustService(s);
            list.add(currentService);

            AbstractTrustService previous = currentService;
            if (s.getServiceHistory() != null) {
                for (ServiceHistoryInstanceType h : s.getServiceHistory().getServiceHistoryInstance()) {
                    HistoricalTrustService service = new HistoricalTrustService(h, currentService);
                    list.add(service);
                    previous = service;
                }
            }
            

            /* The Services must be sorted in descending order CROBIES 2.2.15 */
            Collections.sort(list, new Comparator<AbstractTrustService>() {
                @Override
                public int compare(AbstractTrustService o1, AbstractTrustService o2) {
                    return -o1.getStatusStartDate().compareTo(o2.getStatusStartDate());
                }
            });

            previous = currentService;
            for(AbstractTrustService a : list) {
                if(a instanceof HistoricalTrustService) {
                    ((HistoricalTrustService) a).setPreviousEntry(previous);
                }
                previous = a;
            }
            
            providerList.addAll(list);

        }
        
        return providerList;
    }

    private String getEnglishOrFirst(InternationalNamesType names) {
        if (names == null) {
            return null;
        }
        for (MultiLangNormStringType s : names.getName()) {
            if ("en".equalsIgnoreCase(s.getLang())) {
                return s.getValue();
            }
        }
        return names.getName().get(0).getValue();
    }

    public String getName() {
        return getEnglishOrFirst(tsp.getTSPInformation().getTSPName());
    }

    public String getTradeName() {
        return getEnglishOrFirst(tsp.getTSPInformation().getTSPTradeName());
    }

    public String getPostalAddress() {
        PostalAddressType a = null;
        if (tsp.getTSPInformation().getTSPAddress() == null) {
            return null;
        }
        for (PostalAddressType c : tsp.getTSPInformation().getTSPAddress().getPostalAddresses().getPostalAddress()) {
            if ("en".equalsIgnoreCase(c.getLang())) {
                a = c;
                break;
            }
        }
        if (a == null) {
            a = tsp.getTSPInformation().getTSPAddress().getPostalAddresses().getPostalAddress().get(0);
        }
        return a.getStreetAddress() + ", " + a.getPostalCode() + " " + a.getLocality() + ", "
                + a.getStateOrProvince() + a.getCountryName();
    }

    public String getElectronicAddress() {
        if (tsp.getTSPInformation().getTSPAddress().getElectronicAddress() == null) {
            return null;
        }
        return tsp.getTSPInformation().getTSPAddress().getElectronicAddress().getURI().get(0).getValue();
    }

}
