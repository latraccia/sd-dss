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
package eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.constraint;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.text.SimpleDateFormat;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlDom;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class ValidationPolicyDao {

    public ValidationPolicy load(URL url) {
        try {
            return load(url.openStream());
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    public ValidationPolicy load(InputStream inputStream) {
        try {

            final Document document = DSSXMLUtils.buildDOM(inputStream);
            final XmlDom xmlDom = new XmlDom(document);
            String dateFormat = xmlDom.getValue("/ConstraintsParameters/Cryptographic/AlgoExpirationDate/@Format");
            if (dateFormat.isEmpty()) {
                dateFormat = "yyyy-MM-dd";
            }

            final Unmarshaller unmarshaller = JAXBContext.newInstance(ValidationPolicy.class).createUnmarshaller();
            unmarshaller.setAdapter(new DateAdapter(new SimpleDateFormat(dateFormat)));
            final ValidationPolicy validationPolicy = ValidationPolicy.class.cast(unmarshaller.unmarshal(document));
            return validationPolicy;
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        } catch (SAXException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    public void save(ValidationPolicy validationPolicy, OutputStream outputStream) {
        try {
            String dateFormat = "yyyy-MM-dd";
            final Cryptographic cryptographic = validationPolicy.getCryptographic();
            if (cryptographic != null && cryptographic.getAlgoExpirationDateList() != null) {
                dateFormat = cryptographic.getAlgoExpirationDateList().getFormat();
            }
            final SimpleDateFormat simpleDateFormat = new SimpleDateFormat(dateFormat);
            final DateAdapter dateAdapter = new DateAdapter(simpleDateFormat);

            final JAXBContext jaxbContext;
            jaxbContext = JAXBContext.newInstance(ValidationPolicy.class);
            final Marshaller marshaller = jaxbContext.createMarshaller();

            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.setAdapter(dateAdapter);
            marshaller.marshal(validationPolicy, outputStream);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }

    }
}
