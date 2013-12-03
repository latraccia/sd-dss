/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/tags/ecodex-container-DSS-library-2.5.0.3/apps/dss/dss-report/src/main/java/eu/europa/ec/markt/dss/report/PdfValidationReportService.java $
 * $Revision: 2149 $
 * $Date: 2013-05-29 20:59:24 +0200 (Wed, 29 May 2013) $
 * $Author: meyerfr $
 */
package eu.europa.ec.markt.dss.report;

import eu.europa.ec.markt.dss.validation.report.CertificateVerification;
import eu.europa.ec.markt.dss.validation.report.Result;
import eu.europa.ec.markt.dss.validation.report.SignatureInformation;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelA;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelBES;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelC;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelEPES;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelT;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelX;
import eu.europa.ec.markt.dss.validation.report.SignatureLevelXL;
import eu.europa.ec.markt.dss.validation.report.TimestampVerificationResult;
import eu.europa.ec.markt.dss.validation.report.ValidationReport;

import com.lowagie.text.Chunk;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.PdfWriter;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.openssl.PEMWriter;

import javax.imageio.ImageIO;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;

/**
 * This service create a PDF report from the validation report of the document.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @version $Revision: 2149 $ - $Date: 2013-05-29 20:59:24 +0200 (Wed, 29 May 2013) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class PdfValidationReportService {

    private static final class Resources {
        private static final Font defaultFont;
        private static final Font header1Font;
        private static final Font header2Font;
        private static final Font header3Font;
        private static final Font header4Font;
        private static final Font header5Font;
        private static final Font monoFont;
        private static final Image okImage;
        private static final Image koImage;

        static {
            try {
                defaultFont = createFont("LiberationSans-Regular.ttf", 9);
                header1Font = createFont("LiberationSans-Bold.ttf", 14);
                header1Font.setColor(54, 95, 145);
                header2Font = createFont("LiberationSans-Bold.ttf", 13);
                header2Font.setColor(79, 129, 189);
                header3Font = createFont("LiberationSans-Bold.ttf", 12);
                header3Font.setColor(79, 129, 189);
                header4Font = createFont("LiberationSans-BoldItalic.ttf", 11);
                header4Font.setColor(79, 129, 189);
                header5Font = createFont("LiberationSans-Regular.ttf", 10);
                header5Font.setColor(79, 129, 189);
                monoFont = createFont("LiberationMono-Regular.ttf", 8);

                okImage = Image.getInstance(ImageIO.read(PdfValidationReportService.class.getResourceAsStream("/ok.jpg")), null);
                okImage.scaleToFit(9, 9);
                okImage.setSpacingAfter(25);
                okImage.setSmask(false);

                koImage = Image.getInstance(ImageIO.read(PdfValidationReportService.class.getResourceAsStream("/error.jpg")), null);
                koImage.scaleToFit(9, 9);
                koImage.setSmask(false);

            } catch (Exception e) {
                throw new ExceptionInInitializerError(e);
            }
        }

        private static Font createFont(final String name, final int size) throws IOException, DocumentException {
            final byte[] data;
            final BaseFont bfo;
            data = IOUtils.toByteArray(PdfValidationReportService.class.getResourceAsStream("/" + name));
            bfo = BaseFont.createFont(name, BaseFont.WINANSI, BaseFont.EMBEDDED, BaseFont.CACHED, data, null);
            return new Font(bfo, size);
        }
    }

    private enum ParagraphStyle {
        HEADER1, HEADER2, HEADER3, HEADER4, HEADER5, DEFAULT, CODE
    }

    private final SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm");

    /**
     * The default constructor for PdfValidationReportService.
     */
    public PdfValidationReportService() {
    }

    public void createReport(ValidationReport report, OutputStream pdfStream) throws IOException {

        try {
            Document document = new Document();
            PdfWriter writer = PdfWriter.getInstance(document, pdfStream);
            writer.setPdfVersion(PdfWriter.PDF_VERSION_1_4);
            writer.setPDFXConformance(PdfWriter.PDFA1B);
            document.open();

            document.add(p("Time information", ParagraphStyle.HEADER1));
            document.add(p("Verification Time: " + sdf.format(report.getTimeInformation().getVerificationTime())));

            int i = 1;
            if (report.getSignatureInformationList() != null) {
                for (SignatureInformation si : report.getSignatureInformationList()) {
                    if ( si == null ) {
                        continue;
                    }
                    writeSignatureInformation(document, si, i++);
                }
            }

            writer.createXmpMetadata();
            document.close();
        } catch (DocumentException e) {
            throw new IOException(e);
        }
    }

    private void writeSignatureInformation(Document document, final SignatureInformation si, int index) throws DocumentException {

        document.add(p("Signature information " + index, ParagraphStyle.HEADER1));
        document.add(p("Signature verification", new R() { Result o() { return si.getSignatureVerification().getSignatureVerificationResult(); } }, ParagraphStyle.DEFAULT));
        document.add(p("Signature algorithm: " + new T() { Object o() { return si.getSignatureVerification().getSignatureAlgorithm(); } }));

        document.add(p("Certificate Path Revocation Analysis", ParagraphStyle.HEADER2));
        document.add(p("Summary", new R() { Result o() { return si.getCertPathRevocationAnalysis().getSummary(); } }, null));

        document.add(p("Certificate Verification", ParagraphStyle.HEADER3));
        if (si.getCertPathRevocationAnalysis() == null || si.getCertPathRevocationAnalysis().getCertificatePathVerification() == null || si.getCertPathRevocationAnalysis().getCertificatePathVerification().isEmpty()) {
            document.add(p("No Certificate Verification is available!"));
        } else {
            for (CertificateVerification cert : si.getCertPathRevocationAnalysis().getCertificatePathVerification()) {
                if (cert != null) {
                    writeCertificateVerification(document, cert);
                }
            }
        }

        document.add(p("Trusted List Information", ParagraphStyle.HEADER3));
        document.add(p("Service was found", new B() { boolean o() { return si.getCertPathRevocationAnalysis().getTrustedListInformation().isServiceWasFound(); } }, null));
        document.add(p("Trusted List is well-signed", new B() { boolean o() { return si.getCertPathRevocationAnalysis().getTrustedListInformation().isWellSigned(); } }, null));

        document.add(p("Signature Level Analysis", ParagraphStyle.HEADER2));
        if (si.getSignatureLevelAnalysis() == null) {
            document.add(p("No Signature Level Analysis is available."));
        } else {
            document.add(p("Signature format: " + new T() { Object o() { return si.getSignatureLevelAnalysis().getSignatureFormat(); } }));
            writeLevelBES(document, si);
            writeLevelEPES(document, si);
            writeLevelT(document, si);
            writeLevelC(document, si);
            writeLevelX(document, si);
            writeLevelXL(document, si);
            writeLevelA(document, si);
        }

        document.add(p("Qualification Verification", ParagraphStyle.HEADER2));
        if (si.getQualificationsVerification() == null) {
            document.add(p("No Qualification Verification is available!"));
        } else {
            document.add(p("QCWithSSCD", new R() { Result o() { return si.getQualificationsVerification().getQCWithSSCD(); } }, null));
            document.add(p("QCNoSSCD", new R() { Result o() { return si.getQualificationsVerification().getQCNoSSCD(); } }, null));
            document.add(p("QCSSCDStatusAsInCert", new R() { Result o() { return si.getQualificationsVerification().getQCSSCDStatusAsInCert(); } }, null));
            document.add(p("QCForLegalPerson", new R() { Result o() { return si.getQualificationsVerification().getQCForLegalPerson(); } }, null));
        }

        document.add(p("QC Statement Information", ParagraphStyle.HEADER2));
        if (si.getQcStatementInformation() == null) {
            document.add(p("No QC Statement Information available"));
        } else {
            document.add(p("QCP presence", new R() { Result o() { return si.getQcStatementInformation().getQCPPresent(); } }, null));
            document.add(p("QCP+ presence", new R() { Result o() { return si.getQcStatementInformation().getQCPPlusPresent(); } }, null));
            document.add(p("QcCompliance presence", new R() { Result o() { return si.getQcStatementInformation().getQcCompliancePresent(); } }, null));
            document.add(p("QcSSCD presence", new R() { Result o() { return si.getQcStatementInformation().getQcSCCDPresent(); } }, null));
        }

        document.add(p("Final Conclusion", ParagraphStyle.HEADER2));
        document.add(p("The signature is: " + new T() { Object o() { return si.getFinalConclusion(); } }));
    }

    private void writeLevelBES(final Document document, final SignatureInformation si) throws DocumentException {
        if ( si == null  || si.getSignatureLevelAnalysis() == null || si.getSignatureLevelAnalysis().getLevelBES() == null) {
            document.add(p("Signature Level BES", false, ParagraphStyle.HEADER3));
            return;
        }

        final SignatureLevelBES level = si.getSignatureLevelAnalysis().getLevelBES();

        document.add(p("Signature Level BES", new R() { Result o() { return level.getLevelReached(); } }, ParagraphStyle.HEADER3));

        if (level.getSigningCertificate() != null) {
            document.add(p("Signing certicate: " + new T() { Object o() { return level.getSigningCertificate().getSubjectDN(); } }));
        } else {
            document.add(p("No signing certificate.", ParagraphStyle.DEFAULT));
        }

        if (level.getSigningTime() == null) {
            document.add(p("No signing time attribute.", ParagraphStyle.DEFAULT));
        } else {
            document.add(p("Signing time: " + new T() { Object o() { return sdf.format(level.getSigningTime()); } }));
        }

        document.add(p("Certificates", ParagraphStyle.HEADER4));
        if ( level.getCertificates() == null || level.getCertificates().isEmpty() ) {
            document.add(p("No certificate in the signature.", ParagraphStyle.DEFAULT));
        } else {
            document.add(p("Number of certificates in signature: " + level.getCertificates().size()));
            for (X509Certificate c : level.getCertificates()) {
                writeCertificate(document, c);
            }
        }
    }

    private void writeLevelEPES(final Document document, final SignatureInformation si) throws DocumentException {
        if ( si == null  || si.getSignatureLevelAnalysis() == null || si.getSignatureLevelAnalysis().getLevelEPES() == null) {
            document.add(p("Signature Level EPES", false, ParagraphStyle.HEADER3));
            return;
        }

        final SignatureLevelEPES level = si.getSignatureLevelAnalysis().getLevelEPES();

        document.add(p("Signature Level EPES ", new R() { Result o() { return level.getLevelReached(); } }, ParagraphStyle.HEADER3));
        if (level.getPolicyId() == null) {
            document.add(p("No policy information is given."));
        } else {
            document.add(p("Signature policy: " + new T() { Object o() { return level.getPolicyId(); } }));
        }
    }

    private void writeLevelT(final Document document, final SignatureInformation si) throws DocumentException {
        if ( si == null  || si.getSignatureLevelAnalysis() == null || si.getSignatureLevelAnalysis().getLevelT() == null) {
            document.add(p("Signature Level T", false, ParagraphStyle.HEADER3));
            return;
        }

        final SignatureLevelT level = si.getSignatureLevelAnalysis().getLevelT();

        document.add(p("Signature Level T",  new R() { Result o() { return level.getLevelReached(); } }, ParagraphStyle.HEADER3));
        if (level.getSignatureTimestampVerification() == null || level.getSignatureTimestampVerification().isEmpty()) {
            document.add(p("No timestamp data is found."));
        } else {
            document.add(p("Number of timestamps found: " + level.getSignatureTimestampVerification().size()));
            for (int i = 0; i < level.getSignatureTimestampVerification().size(); i++) {
                TimestampVerificationResult ts = level.getSignatureTimestampVerification().get(i);
                writeTimestampResultInformation(document, ts, "Timestamp " + (i + 1));
            }
        }
    }

    private void writeLevelC(final Document document, final SignatureInformation si) throws DocumentException {
        if ( si == null  || si.getSignatureLevelAnalysis() == null || si.getSignatureLevelAnalysis().getLevelC() == null) {
            // document.add(p("Signature Level C", false, ParagraphStyle.HEADER3));
            return;
        }

        final SignatureLevelC level = si.getSignatureLevelAnalysis().getLevelC();

        document.add(p("Signature Level C", new R() { Result o() { return level.getLevelReached(); } }, ParagraphStyle.HEADER3));

        if (level.getCertificateRefsVerification() != null && level.getCertificateRefsVerification().isValid()) {
            document.add(p("All the certificate references needed are in the signature."));
        } else {
            document.add(p("Some required certificate references are not in the signature."));
        }

        if (level.getRevocationRefsVerification() != null && level.getRevocationRefsVerification().isValid()) {
            document.add(p("All the revocation information references needed are in the signature."));
        } else {
            document.add(p("Some required revocation information references are not in the signature."));
        }
    }

    private void writeLevelX(final Document document, final SignatureInformation si) throws DocumentException {
        if ( si == null  || si.getSignatureLevelAnalysis() == null || si.getSignatureLevelAnalysis().getLevelX() == null) {
            // document.add(p("Signature Level X", false, ParagraphStyle.HEADER3));
            return;
        }

        final SignatureLevelX level = si.getSignatureLevelAnalysis().getLevelX();

        document.add(p("Signature Level X", new R() { Result o() { return level.getLevelReached(); } }, ParagraphStyle.HEADER3));

        int x1Count = ( level.getSignatureAndRefsTimestampsVerification() == null ) ? 0 : level.getSignatureAndRefsTimestampsVerification().length;
        int x2Count = ( level.getReferencesTimestampsVerification() == null ) ? 0 : level.getReferencesTimestampsVerification().length;

        document.add(p("Number of X-Timestamps in the document: " + (x1Count + x2Count)));

            /* Signature and ref */
        for (int i = 0; i < x1Count; i++) {
            TimestampVerificationResult ts = level.getSignatureAndRefsTimestampsVerification()[i];
            writeTimestampResultInformation(document, ts, "X1-Timestamp " + (i + 1));
        }

            /* Signature and ref */
        for (int i = 0; i < x2Count; i++) {
            TimestampVerificationResult ts = level.getReferencesTimestampsVerification()[i];
            writeTimestampResultInformation(document, ts, "X2-Timestamp " + (i + 1));
        }
    }

    private void writeLevelXL(final Document document, final SignatureInformation si) throws DocumentException {
        if ( si == null  || si.getSignatureLevelAnalysis() == null || si.getSignatureLevelAnalysis().getLevelXL() == null) {
            // document.add(p("Signature Level XL", false, ParagraphStyle.HEADER3));
            return;
        }

        final SignatureLevelXL level = si.getSignatureLevelAnalysis().getLevelXL();

        document.add(p("Signature Level XL", new R() { Result o() { return level.getLevelReached(); } }, ParagraphStyle.HEADER3));

        if (level.getCertificateValuesVerification() != null && level.getCertificateValuesVerification().isValid()) {
            document.add(p("All the certificates needed are in the signature."));
        } else {
            document.add(p("Some required certificates are not in the signature."));
        }

        if (level.getRevocationValuesVerification() != null && level.getRevocationValuesVerification().isValid()) {
            document.add(p("All the revocation information needed are in the signature."));
        } else {
            document.add(p("Some required revocation information are not in the signature."));
        }
    }

    private void writeLevelA(final Document document, final SignatureInformation si) throws DocumentException {
        if ( si == null  || si.getSignatureLevelAnalysis() == null || si.getSignatureLevelAnalysis().getLevelA() == null) {
            // document.add(p("Signature Level A", false, ParagraphStyle.HEADER3));
            return;
        }

        final SignatureLevelA level = si.getSignatureLevelAnalysis().getLevelA();

        document.add(p("Signature Level A", new R() { Result o() { return level.getLevelReached(); } }, ParagraphStyle.HEADER3));

        if (level.getArchiveTimestampsVerification() == null || level.getArchiveTimestampsVerification().isEmpty()) {
            document.add(p("No timestamp data is found."));
        } else {
            document.add(p("Number of A-Timestamps in the document: " + level.getArchiveTimestampsVerification().size()));
            for (int i = 0; i < level.getArchiveTimestampsVerification().size(); i++) {
                TimestampVerificationResult ts = level.getArchiveTimestampsVerification().get(i);
                writeTimestampResultInformation(document, ts, "A-Timestamp " + (i + 1));
            }
        }
    }

    private void writeTimestampResultInformation(Document document, final TimestampVerificationResult ts, String title) throws DocumentException {
        document.add(p(title, ParagraphStyle.HEADER5));
        document.add(p("Issuer name: " + new T() { Object o() { return ts.getIssuerName(); } }));
        document.add(p("Serial number: " + new T() { Object o() { return ts.getSerialNumber(); } }));
        document.add(p("Signature algorithm: " + new T() { Object o() { return ts.getSignatureAlgorithm(); } }));
        document.add(p("Signature verification: ", new R() { Result o() { return ts.getSameDigest(); } }, ParagraphStyle.DEFAULT));
        document.add(p("Creation time: " + new T() { Object o() { return sdf.format(ts.getCreationTime()); } }));
    }

    private void writeCertificate(Document document, final X509Certificate cert) throws DocumentException {
        document.add(p("Certificate of " + new T() { Object o() { return cert.getSubjectX500Principal(); } }, ParagraphStyle.HEADER5));
        document.add(p("Version: " + new T() { Object o() { return cert.getVersion(); } }));
        document.add(p("Subject: " + new T() { Object o() { return cert.getSubjectX500Principal(); } }));
        document.add(p("Issuer: " + new T() { Object o() { return cert.getIssuerX500Principal(); } }));

        try {
            StringWriter writer = new StringWriter();
            PEMWriter out = new PEMWriter(writer);
            out.writeObject(cert);
            out.close();

            document.add(p(writer.toString(), ParagraphStyle.CODE));
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    private void writeCertificateVerification(Document document, final CertificateVerification cert) throws DocumentException {
        document.add(p("" + new T() { Object o() { return cert.getCertificate().getSubjectDN(); } }, ParagraphStyle.HEADER5));
        document.add(p("Issuer name: " + new T() { Object o() { return cert.getCertificate().getIssuerDN(); } }));
        document.add(p("Serial Number: " + new T() { Object o() { return cert.getCertificate().getSerialNumber(); } }));
        document.add(p("Validity at signing time: " + new T() { Object o() { return cert.getValidityPeriodVerification().getStatus(); } }));
        document.add(p("Certificate Revocation status: " + new T() { Object o() { return cert.getCertificateStatus().getStatus(); } }));
    }

    /**
     * this provides some convience to avoid NPE or usage of if-else/conditionals in order to get a text
     */
    private static abstract class T {
        abstract Object o();

        @Override
        public String toString() {
            try {
                return o().toString();
            } catch (Exception e) {
                return "N/A";
            }
        }
    }

    /**
     * this provides some convience to avoid NPE or usage of if-else/conditionals in order to get a text
     */
    private static abstract class R {
        abstract Result o();

        public boolean toBoolean() {
            try {
                final Result o = o();
                return o!= null && o.isValid();
            } catch (Exception e) {
                return false;
            }
        }
    }

    /**
     * this provides some convience to avoid NPE or usage of if-else/conditionals in order to get a text
     */
    private static abstract class B {
        abstract boolean o();

        public boolean toBoolean() {
            try {
                return o();
            } catch (Exception e) {
                return false;
            }
        }
    }

    private Paragraph p(String s) {
        return p(s, ParagraphStyle.DEFAULT);
    }

    private Paragraph p(String s, ParagraphStyle style) {
        return p(null, s, style);
    }

    private Paragraph p(String s, R r, ParagraphStyle style) {
        return p(s, r.toBoolean(), style);
    }

    private Paragraph p(String s, B r, ParagraphStyle style) {
        return p(s, r.toBoolean(), style);
    }

    private Paragraph p(String s, Result r, ParagraphStyle style) {
        return p(s, (r!= null && r.isValid()), style);
    }

    private Paragraph p(String s, boolean r, ParagraphStyle style) {
        return p(r ? Resources.okImage : Resources.koImage, s, style);
    }

    private Paragraph p(Image img, String s, ParagraphStyle style) {

        if (style == null) {
            style = ParagraphStyle.DEFAULT;
        }

        Paragraph p = new Paragraph("", Resources.defaultFont);

        Font font = Resources.defaultFont;
        if ( style == ParagraphStyle.HEADER1 ) {
            font = Resources.header1Font;
            p.setSpacingBefore(20);
        } else if ( style == ParagraphStyle.HEADER2 ) {
            font = Resources.header2Font;
            p.setSpacingBefore(8);
        } else if ( style == ParagraphStyle.HEADER3 ) {
            font = Resources.header3Font;
            p.setSpacingBefore(8);
        } else if ( style == ParagraphStyle.HEADER4 ) {
            font = Resources.header4Font;
            p.setSpacingBefore(8);
        } else if ( style == ParagraphStyle.HEADER5 ) {
            font = Resources.header5Font;
            p.setSpacingBefore(8);
        } else if ( style == ParagraphStyle.CODE ) {
            font = Resources.monoFont;
            p.setSpacingBefore(8);
        }

        if (img != null) {
            p.add(new Chunk(img, 0, -1));
            p.add(new Chunk(" ", font));
        }

        p.add(new Chunk(s, font));

        return p;

    }

}
