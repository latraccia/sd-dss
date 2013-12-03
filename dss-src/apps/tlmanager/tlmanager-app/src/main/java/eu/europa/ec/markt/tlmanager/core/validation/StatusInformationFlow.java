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

package eu.europa.ec.markt.tlmanager.core.validation;

import eu.europa.ec.markt.tlmanager.core.Configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This is a representation of the 'Expected supervision/accreditation status flow for a single CSP service' which is
 * described in Study on Cross-Border Interoperability of eSignatures (CROBIES). Please note, that the exact keys are
 * not hardcoded here but expected to be configured accordingly in 'tlmanager.properties'. However, only the last
 * keyword is essential to distinguish the state, so that it would still work with slightly changed configuration
 * values.
 * 
 *
 * @version $Revision: 1168 $ - $Date: 2012-03-05 12:28:27 +0100 (lun., 05 mars 2012) $
 */

public class StatusInformationFlow {
    private static final Logger LOG = Logger.getLogger(StatusInformationFlow.class.getName());

    private boolean initOk;
    private Status underSupervision;
    private Status supervisionInCessation;
    private Status supervisionCeased;
    private Status supervisionRevoked;
    private Status accredited;
    private Status accreditationCeased;
    private Status accreditationRevoked;

    private String[] serviceStatus;
    private List<Status> allStatus;

    /**
     * The default constructor for StatusInformationFlow.
     */
    public StatusInformationFlow() {
        initOk = initConfigurationValues();
        if (initOk) {
            init();
        }
    }

    /**
     * @return the initError
     */
    public boolean isInitError() {
        return !initOk;
    }

    private boolean initConfigurationValues() {
        serviceStatus = Configuration.getInstance().getTL().getTslServiceStatus();

        if (serviceStatus.length != 7) {
            LOG.log(Level.SEVERE, "Unable to initialise StatusInformationFlow "
                    + "due to unexpected number of configuration values!");
            return false;
        }

        // check that all expected strings are present
        for (String str : serviceStatus) {
            if (!str.endsWith("undersupervision") && !str.endsWith("supervisionincessation")
                    && !str.endsWith("supervisionceased") && !str.endsWith("supervisionrevoked")
                    && !str.endsWith("accredited") && !str.endsWith("accreditationceased")
                    && !str.endsWith("accreditationrevoked")) {
                LOG.log(Level.SEVERE,
                        "Unable to initialise all keys for the StatusInformationFlow: problematic string: " + str
                                + "!");
                return false;
            }
        }

        return true;
    }

    private String getFullKey(String status) {
        for (String str : serviceStatus) {
            if (str.endsWith(status)) {
                return str;
            }
        }
        return "";
    }

    /**
     * Collects all names of Status that may be a start point.
     * 
     * @return the list of names of start status
     */
    public List<String> getStartStatusNames() {
        List<String> startStatus = new ArrayList<String>();
        for (Status status : allStatus) {
            if (status.isStartPoint()) {
                startStatus.add(status.getName());
            }
        }

        return startStatus;
    }

    /**
     * Finds the status with a name that matches the given name.
     * 
     * @param name the string to match
     * 
     * @return the matching status
     */
    public Status getMatchingStatus(String name) {
        for (Status status : allStatus) {
            if (status.getName().equals(name)) {
                return status;
            }
        }
        return null;
    }

    private List<Status> createList(Status... statuses) {
        List<Status> list = new ArrayList<StatusInformationFlow.Status>();
        for (Status status : statuses) {
            list.add(status);
        }
        return list;
    }

    private void init() {
        underSupervision = new Status("undersupervision", true, false);
        supervisionInCessation = new Status("supervisionincessation", false, false);
        supervisionCeased = new Status("supervisionceased", false, false);
        supervisionRevoked = new Status("supervisionrevoked", false, false);
        accredited = new Status("accredited", true, false);
        accreditationCeased = new Status("accreditationceased", false, true);
        accreditationRevoked = new Status("accreditationrevoked", false, true);
        allStatus = new ArrayList<StatusInformationFlow.Status>();

        underSupervision.setOutGoing(createList(accredited, supervisionRevoked, supervisionCeased,
                supervisionInCessation));
        allStatus.add(underSupervision);

        supervisionInCessation.setOutGoing(createList(supervisionRevoked, supervisionCeased));
        allStatus.add(supervisionInCessation);

        supervisionCeased.setOutGoing(createList(underSupervision));
        allStatus.add(supervisionCeased);

        supervisionRevoked.setOutGoing(createList(underSupervision));
        allStatus.add(supervisionRevoked);

        accredited.setOutGoing(createList(accreditationCeased, accreditationRevoked));
        allStatus.add(accredited);

        accreditationCeased.setOutGoing(createList(accreditationRevoked, accredited, underSupervision));
        allStatus.add(accreditationCeased);

        accreditationRevoked.setOutGoing(createList(accredited, underSupervision));
        allStatus.add(accreditationRevoked);
    }

    /**
     * A helping class to represent a single Status.
     * 
     * <p>
     * DISCLAIMER: Project owner DG-MARKT.
     * 
     * @version $Revision: 1168 $ - $Date: 2012-03-05 12:28:27 +0100 (lun., 05 mars 2012) $
     * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
     */
    public class Status {
        private boolean startPoint;
        private boolean isTransit;
        private String shortName;
        private String name;
        private List<Status> outGoing;

        /**
         * The default constructor for Status.
         * 
         * @param shortName just the last part of the name
         * @param startPoint true, if this status can be a starting point
         * @param isTransit true, if this status is a transit status
         */
        public Status(String shortName, boolean startPoint, boolean isTransit) {
            this.shortName = shortName;
            this.name = getFullKey(shortName);
            this.startPoint = startPoint;
            this.isTransit = isTransit;
        }

        /**
         * @return the outGoing
         */
        public List<Status> getOutGoing() {
            return outGoing;
        }

        /**
         * @param outGoing the outGoing to set
         */
        public void setOutGoing(List<Status> outGoing) {
            this.outGoing = outGoing;
        }

        /**
         * @return the isTransit
         */
        public boolean isTransit() {
            return isTransit;
        }

        /**
         * @return the startPoint
         */
        public boolean isStartPoint() {
            return startPoint;
        }

        /**
         * @return the name
         */
        public String getName() {
            return name;
        }

        /**
         * @return the shortName
         */
        public String getShortName() {
            return shortName;
        }
    }
}