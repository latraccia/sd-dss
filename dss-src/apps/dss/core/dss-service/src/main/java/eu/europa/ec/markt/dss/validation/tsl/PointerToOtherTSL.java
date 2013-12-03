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

import eu.europa.ec.markt.tsl.jaxb.tsl.AnyType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityType;
import eu.europa.ec.markt.tsl.jaxb.tsl.OtherTSLPointerType;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.JAXBElement;

import org.w3c.dom.Element;

/**
 * Wrapper for the tag OtherTSLPointer
 *
 * @version $Revision: 1154 $ - $Date: 2012-02-23 16:04:49 +0100 (jeu., 23 févr. 2012) $
 */

class PointerToOtherTSL {

    private static final Logger LOG = Logger.getLogger(PointerToOtherTSL.class.getName());

    private OtherTSLPointerType pointer;

    /**
     * 
     * The default constructor for PointerToOtherTSL.
     * 
     * @param pointer
     */
    public PointerToOtherTSL(OtherTSLPointerType pointer) {
        this.pointer = pointer;
    }

    private List<DigitalIdentityListType> getServiceDigitalIdentities() {
        if (pointer.getServiceDigitalIdentities() != null) {
            return pointer.getServiceDigitalIdentities().getServiceDigitalIdentity();
        } else {
            return null;
        }
    }

    /**
     * 
     * @return
     */
    public String getTslLocation() {
        return pointer.getTSLLocation();
    }

    private Map<String, String> getProperties() {
        Map<String, String> properties = new HashMap<String, String>();

        for (Object info : pointer.getAdditionalInformation().getTextualInformationOrOtherInformation()) {
            if (info instanceof AnyType) {
                AnyType any = (AnyType) info;
                for (Object content : any.getContent()) {
                    if (content instanceof String) {
                        if (((String) content).trim().length() > 0) {
                            throw new RuntimeException("Unexpected String : " + content);
                        }
                    } else if (content instanceof JAXBElement) {
                        @SuppressWarnings("rawtypes")
                        JAXBElement el = (JAXBElement) content;
                        properties.put(el.getName().toString(), el.getValue().toString());
                    } else if (content instanceof Element) {
                        Element el = (Element) content;
                        properties.put("{" + el.getNamespaceURI() + "}" + el.getLocalName(), el.getTextContent());
                    } else {
                        throw new RuntimeException("Unknown element : " + content.getClass());
                    }
                }
            } else {
                throw new RuntimeException("Unknown type : " + info.getClass());
            }
        }
        return properties;
    }

    /**
     * 
     * @return
     */
    public String getMimeType() {
        return getProperties().get("{http://uri.etsi.org/02231/v2/additionaltypes#}MimeType");
    }

    /**
     * 
     * @return
     */
    public String getTerritory() {
        return getProperties().get("{http://uri.etsi.org/02231/v2#}SchemeTerritory");
    }

    /**
     * 
     * @return
     */
    public X509Certificate getDigitalId() throws CertificateException {

        if (getServiceDigitalIdentities() == null) {
            return null;
        }

        if (getServiceDigitalIdentities().size() > 1) {
            LOG.warning("More than one digital-id, this is not supported yet");
        }

        DigitalIdentityType x509id = getServiceDigitalIdentities().get(0).getDigitalId().get(0);
        for(DigitalIdentityType t : getServiceDigitalIdentities().get(0).getDigitalId()) {
            if(t.getX509Certificate() != null) {
                x509id = t;
                break;
            }
        }
        
        if(x509id == null) {
            return null;
        }

        if (x509id.getX509Certificate() == null) {
            LOG.log(Level.WARNING, "X509 Certificate entry empty");
        } else {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(x509id
                    .getX509Certificate()));
            LOG.log(Level.INFO, "Territory {0} signed by {1}", new Object[] { getTerritory(), cert.getSubjectDN() });
            return cert;
        }

        return null;
    }
}
