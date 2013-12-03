/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.validation102853.engine.rules.processes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

import eu.europa.ec.markt.dss.validation102853.engine.function.XmlNode;
import eu.europa.ec.markt.dss.validation102853.engine.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.engine.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.engine.rules.SubIndication;

/**
 * This class represents the conclusion (result) of the process, with at least the Indication, SubIndication (if any)...
 * This class can be derived to handle specific needs of the process.
 *
 * @author bielecro
 */
public class Conclusion implements Indication, SubIndication, NodeName {

    private String indication;
    private String subIndication;

    private XmlNode validationData;

    static public class Info {

        String value;
        private HashMap<String, String> attributes = null;

        public Info(String value) {

            super();
            this.value = value;
        }

        public void setAttribute(String name, String value) {

            if (attributes == null) {

                attributes = new HashMap<String, String>();
            }
            attributes.put(name, value);
        }

        public boolean hasAttribute(String name) {

            return attributes.containsKey(name);
        }

        public boolean hasAttribute(String name, String value) {

            String attributeValue = attributes.get(name);
            return attributeValue != null && attributeValue.equals(value);
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        /**
         * This method adds the Info <code>XmlNode</code> to the given <code>XmlNode</code>
         *
         * @param xmlNode The node to which the Info node is added
         */
        public void addTo(XmlNode xmlNode) {

            XmlNode info = xmlNode.addChild(INFO, value);
            if (attributes != null && attributes.entrySet() != null) {
                for (final Entry<String, String> entry : attributes.entrySet()) {

                    info.setAttribute(entry.getKey(), entry.getValue());
                }
            }
        }
    }

    private List<Info> infoList;

    public String getIndication() {
        return indication;
    }

    public void setIndication(String indication) {
        this.indication = indication;
    }

    public void setIndication(String indication, String subIndication) {
        this.indication = indication;
        this.subIndication = subIndication;
    }

    public String getSubIndication() {
        return subIndication;
    }

    public void setSubIndication(String subIndication) {
        this.subIndication = subIndication;
    }

    public Info addInfo(String value) {

        Info info = new Info(value);
        if (infoList == null) {

            infoList = new ArrayList<Conclusion.Info>();
        }
        infoList.add(info);
        return info;
    }

    public void addInfo(Conclusion conclusion) {

        if (conclusion.infoList != null && !conclusion.infoList.isEmpty()) {

            if (infoList == null) {

                infoList = new ArrayList<Conclusion.Info>();
            }
            infoList.addAll(conclusion.infoList);
        }
    }

    public Info getInfo(String attributName) {

        if (infoList == null) {
            return null;
        }
        for (Info info : infoList) {
            if (info.hasAttribute(attributName)) {
                return info;
            }
        }
        return null;
    }

    public Info getInfo(String attributName, String attributValue) {

        if (infoList == null) {
            return null;
        }
        for (Info info : infoList) {
            if (info.hasAttribute(attributName, attributValue)) {
                return info;
            }
        }
        return null;
    }

    public XmlNode getValidationData() {

        return validationData;
    }

    /**
     * This method sets the validation data. The conclusion node is added based on the content of this object. This
     * method must be called at the end of the process. If the content of this object changes, then this method need to
     * be called again.
     *
     * @param validationData
     */
    public void setValidationData(XmlNode validationData) {

        validationData.addChild(this.toXmlNode());
        this.validationData = validationData;
    }

    public XmlNode toXmlNode() {

        XmlNode conclusion = new XmlNode(CONCLUSION);
        conclusion.addChild(INDICATION, indication);
        if (subIndication != null) {

            conclusion.addChild(SUB_INDICATION, subIndication);
        }
        if (infoList != null) {

            for (Info info : infoList) {

                XmlNode infoNode = conclusion.addChild(INFO, info.getValue());
                if (info.attributes != null) {

                    Iterator<Entry<String, String>> iterator = info.attributes.entrySet().iterator();
                    while (iterator.hasNext()) {

                        Entry<String, String> entry = iterator.next();
                        infoNode.setAttribute(entry.getKey(), entry.getValue());
                    }
                }
            }
        }
        return conclusion;
    }

    public String toString() {

        return toXmlNode().toString();
    }
}
