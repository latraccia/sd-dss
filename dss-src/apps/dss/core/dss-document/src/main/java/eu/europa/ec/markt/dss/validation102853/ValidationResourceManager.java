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
package eu.europa.ec.markt.dss.validation102853;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Logger;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.IOUtils;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.ObjectFactory;
import eu.europa.ec.markt.dss.validation102853.engine.function.XmlNode;

public class ValidationResourceManager {

    private static final Logger LOG = Logger.getLogger(ValidationResourceManager.class.getName());

    public static final String DIAGNOSTIC_DATA_NAMESPACE = "http://dss.markt.ec.europa.eu/validation/diagnostic";

    private static Marshaller marshaller;

    private static DocumentBuilder documentBuilder;

    /**
     * flag to configure on VM level if the diagnostic data from 102853 validation process should be stored.<br/>
     * to define this, use <code>-Ddss.v102853.savediagnosticdata=true</code><br/>
     * you can set this property also programmatically via <code>System.setProperty(...)</code> and then calling
     * {@link #resolveProcessConfiguration()}.
     */
    public static final String DSS_V102853_SAVE_DIAGNOSTIC_DATA = "dss.v102853.savediagnosticdata";
    private static boolean SAVE_DIAGNOSTIC_DATA = false;

    /**
     * flag to configure on VM level the folder where the diagnostic data from 102853 validation process is stored.<br/>
     * to define this, use <code>-Ddss.v102853.diagnosticdatafolder=/temp</code><br/>
     * you can set this property also programmatically via <code>System.etProperty(...)</code> and then calling
     * {@link #resolveProcessConfiguration()}.
     */
    public static final String DSS_V102853_DIAGNOSTIC_DATA_FOLDER = "dss.v102853.diagnosticdatafolder";
    private static String DIAGNOSTIC_DATA_FOLDER = "";

    private static long diagnosticDataUniqueId = 1;

    public static String defaultPolicyConstraintsLocation = "/102853/policy/constraint.xml";

    static {

        try {

            JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
            marshaller = jaxbContext.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            // unmarshaller = jaxbContext.createUnmarshaller();

            DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
            dfactory.setNamespaceAware(true);
            documentBuilder = dfactory.newDocumentBuilder();
        } catch (JAXBException e) {
            throw new DSSException(e);
        } catch (ParserConfigurationException e) {
            throw new DSSException(e);
        }
    }

    /**
     * This method saves the diagnostic data. A unique name is given to the saved file.
     *
     * @param diagnosticData
     */
    public static void saveDiagnosticData(final DiagnosticData diagnosticData) {

        if (SAVE_DIAGNOSTIC_DATA) {

            try {

                final long diagnosticDataUniqueId = getSequenceNumber();
                String unique = diagnosticDataUniqueId + ".";

                // FIXME Just for tests to be deleted.
                unique = "";

                final String diagnosticDataFileName = DIAGNOSTIC_DATA_FOLDER + "/diagnostic_data" + ((unique == null || unique
                      .isEmpty()) ? "" : ("-" + unique)) + ".xml";

                ByteArrayOutputStream baos = jaxbMarshalToOutputStream(diagnosticData);
                ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
                FileWriter fw = new FileWriter(diagnosticDataFileName);
                IOUtils.copy(bais, fw, "UTF-8");
                fw.close();
            } catch (Exception e) {

                LOG.warning(e.getMessage());
            }
        }
    }

    /**
     * This method loads the policy constraint file. If the policyData is not specified then the default policy file is
     * loaded.
     *
     * @param policyDataStream
     * @return
     */
    public static Document loadPolicyData(InputStream policyDataStream) {

        if (policyDataStream != null) {

            return load(policyDataStream);
        }
        if (defaultPolicyConstraintsLocation != null && !defaultPolicyConstraintsLocation.isEmpty()) {

            return load(defaultPolicyConstraintsLocation);
        }
        return null;
    }

    /**
     * This method returns the unique number used in a file name of diagnostic data.
     *
     * @return
     */
    private static synchronized long getSequenceNumber() {

        diagnosticDataUniqueId++;
        return diagnosticDataUniqueId;
    }

    /**
     * this checks for:<br>
     * - {@link #DSS_V102853_SAVE_DIAGNOSTIC_DATA}<br>
     * - {@link #DSS_V102853_DIAGNOSTIC_DATA_FOLDER}<br>
     * that configures {@link ProcessExecutor(DiagnosticData)} .
     */
    public static void resolveProcessConfiguration() {

        SAVE_DIAGNOSTIC_DATA = "true".equalsIgnoreCase(System.getProperty(DSS_V102853_SAVE_DIAGNOSTIC_DATA, "false"));
        DIAGNOSTIC_DATA_FOLDER = System.getProperty(DSS_V102853_DIAGNOSTIC_DATA_FOLDER);
    }

    /**
     * sets the value for {@link #DSS_V102853_SAVE_DIAGNOSTIC_DATA} so that {@link ProcessExecutor(DiagnosticData)} is
     * executed in that respect.
     */
    public static void enableSaveDiagnosticData() {

        System.setProperty(DSS_V102853_SAVE_DIAGNOSTIC_DATA, "true");
        resolveProcessConfiguration();
    }

    /**
     * sets the value for {@link #DSS_V102853_SAVE_DIAGNOSTIC_DATA} so that {@link ProcessExecutor(DiagnosticData)} is
     * executed in that respect.
     */
    public static void setDiagnosticDataFolder(String folder) {

        System.setProperty(DSS_V102853_DIAGNOSTIC_DATA_FOLDER, folder);
        resolveProcessConfiguration();
    }

    /**
     * This method saves the data in the output stream to a file.
     *
     * @param diagnosticDataFileName
     * @param outputStream
     * @throws IOException
     */
    protected static void saveToFile(final String diagnosticDataFileName, final OutputStream outputStream) throws IOException {

        FileWriter file = null;
        try {

            file = new FileWriter(diagnosticDataFileName);
            file.write(outputStream.toString());
        } finally {

            if (file != null) {

                file.close();
            }
        }
    }

    /**
     * This method loads the data from the file into an {@link InputStream}.
     *
     * @param dataFileName
     * @return
     */
    private static InputStream getResourceInputStream(final String dataFileName) {

        try {

            InputStream inputStream = ValidationResourceManager.class.getResourceAsStream(dataFileName);
            // IOUtils.copy(inputStream, System.out);
            return inputStream;
        } catch (Exception e) {
            throw new DSSException(e);
        }
    }

    /**
     * This method loads the data from the {@link XmlNode} into a {@link Document}</code>.
     *
     * @param data
     * @return
     */
    public static Document xmlNodeIntoDom(final XmlNode data) {

        final InputStream inputStream = data.getInputStream();
        Document document;
        try {
            document = documentBuilder.parse(inputStream);
        } catch (SAXException e) {

            throw new DSSException(e);
        } catch (IOException e) {
            throw new DSSException(e);
        }
        return document;
    }

    /**
     * This is the utility method that loads the data from the file determined by the path parameter into a
     * {@link Document}.
     *
     * @param path
     * @return
     */
    public static Document load(final String path) {

        if (path == null || path.isEmpty()) {

            return null;
        }
        final InputStream fileInputStream = getResourceInputStream(path);
        final Document document = load(fileInputStream);
        // DSSXMLUtils.printDocument(document, System.out);
        return document;
    }

    /**
     * This is the utility method that loads the data from the inputstream determined by the inputstream parameter into a
     * {@link Document}.
     *
     * @param inputStream
     * @return
     */
    public static Document load(final InputStream inputStream) throws DSSException {

        Document document = null;
        try {

            document = documentBuilder.parse(inputStream);
            // DSSXMLUtils.printDocument(document, System.out);
        } catch (Exception e) {
            throw new DSSException(e);
        } finally {
            DSSUtils.closeQuietly(inputStream);
        }
        return document;
    }

    /**
     * This is the utility method that marshals the JAXB object into a {@link Document}.
     *
     * @param diagnosticDataJB The JAXB object representing the diagnostic data.
     * @return
     */
    public static Document convert(final DiagnosticData diagnosticDataJB) {

        try {

            Document diagnosticData = documentBuilder.newDocument();
            marshaller.marshal(diagnosticDataJB, diagnosticData);
            return diagnosticData;
        } catch (JAXBException e) {
            throw new DSSException(e);
        }
    }

    /**
     * This is the utility method that marshal the JAXB object into an output stream.
     *
     * @param diagnosticData The JAXB object representing the diagnostic data.
     * @return
     */
    public static ByteArrayOutputStream jaxbMarshalToOutputStream(final DiagnosticData diagnosticData) {

        try {

            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            marshaller.marshal(diagnosticData, baos);
            return baos;
        } catch (JAXBException e) {
            throw new DSSException(e);
        }
    }

    // /**
    // * This method sets the path of the file containing the diagnostic data to be used for the validation.<br>
    // *
    // * @param policySubFolderFile
    // */
    // public void setDiagnosticDataPath(String diagnostiDataPath) {
    // this.diagnosticDataLocation = diagnostiDataPath;
    // }
    //
    // /**
    // * This method sets the path of the file containing the policy constraints.<br>
    // *
    // * @param policySubFolderFile
    // */
    // public void setPolicyPath(String policyPath) {
    // this.policyDataPath = policyPath;
    // }
}
