package eu.europa.ec.markt.dss.applet.wizard.signature;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.applet.controller.ActivityController;
import eu.europa.ec.markt.dss.applet.controller.DSSWizardController;
import eu.europa.ec.markt.dss.applet.main.DSSAppletCore;
import eu.europa.ec.markt.dss.applet.model.SignatureModel;
import eu.europa.ec.markt.dss.applet.util.SigningUtils;
import eu.europa.ec.markt.dss.applet.view.signature.CertificateView;
import eu.europa.ec.markt.dss.applet.view.signature.FileView;
import eu.europa.ec.markt.dss.applet.view.signature.FinishView;
import eu.europa.ec.markt.dss.applet.view.signature.MoccaView;
import eu.europa.ec.markt.dss.applet.view.signature.PKCS11View;
import eu.europa.ec.markt.dss.applet.view.signature.PKCS12View;
import eu.europa.ec.markt.dss.applet.view.signature.PersonalDataView;
import eu.europa.ec.markt.dss.applet.view.signature.SaveView;
import eu.europa.ec.markt.dss.applet.view.signature.SignatureView;
import eu.europa.ec.markt.dss.applet.view.signature.TokenView;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardStep;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.SignatureParameters.Policy;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class SignatureWizardController extends DSSWizardController<SignatureModel> {

    private FileView fileView;
    private SignatureView signatureView;
    private TokenView tokenView;
    private PKCS11View pkcs11View;
    private PKCS12View pkcs12View;
    private MoccaView moccaView;
    private CertificateView certificateView;
    private PersonalDataView personalDataView;
    private SaveView saveView;
    private FinishView signView;

    /**
     * The default constructor for SignatureWizardController.
     *
     * @param core
     * @param model
     */
    @Inject
    SignatureWizardController(final DSSAppletCore core, final SignatureModel model) {
        super(core, model);
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#doCancel()
     */
    @Override
    protected void doCancel() {

        getCore().getController(ActivityController.class).display();
    }

    /**
     *
     */
    public void doRefreshPrivateKeys() {

        try {
            final SignatureTokenConnection tokenConnection = getModel().getTokenConnection();
            getModel().setPrivateKeys(tokenConnection.getKeys());
        } catch (final KeyStoreException e) {
            // FIXME
            e.printStackTrace();
        }

    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#doStart()
     */
    @Override
    protected Class<? extends WizardStep<SignatureModel, ? extends WizardController<SignatureModel>>> doStart() {

        return FileStep.class;
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#registerViews()
     */
    @Override
    protected void registerViews() {

        fileView = new FileView(getCore(), this, getModel());
        signatureView = new SignatureView(getCore(), this, getModel());
        tokenView = new TokenView(getCore(), this, getModel());
        pkcs11View = new PKCS11View(getCore(), this, getModel());
        pkcs12View = new PKCS12View(getCore(), this, getModel());
        moccaView = new MoccaView(getCore(), this, getModel());
        certificateView = new CertificateView(getCore(), this, getModel());
        personalDataView = new PersonalDataView(getCore(), this, getModel());
        saveView = new SaveView(getCore(), this, getModel());
        signView = new FinishView(getCore(), this, getModel());
    }

    /*
     * (non-Javadoc)
     *
     * @see eu.europa.ec.markt.dss.commons.swing.mvc.applet.wizard.WizardController#registerWizardStep()
     */
    @Override
    protected Map<Class<? extends WizardStep<SignatureModel, ? extends WizardController<SignatureModel>>>, ? extends WizardStep<SignatureModel, ? extends WizardController<SignatureModel>>> registerWizardStep() {

        final SignatureModel model = getModel();

        final Map steps = new HashMap();
        steps.put(FileStep.class, new FileStep(model, fileView, this));
        steps.put(SignatureStep.class, new SignatureStep(model, signatureView, this));
        steps.put(TokenStep.class, new TokenStep(model, tokenView, this));
        steps.put(PKCS11Step.class, new PKCS11Step(model, pkcs11View, this));
        steps.put(PKCS12Step.class, new PKCS12Step(model, pkcs12View, this));
        steps.put(MoccaStep.class, new MoccaStep(model, moccaView, this));
        steps.put(CertificateStep.class, new CertificateStep(model, certificateView, this));
        steps.put(PersonalDataStep.class, new PersonalDataStep(model, personalDataView, this));
        steps.put(SaveStep.class, new SaveStep(model, saveView, this));
        steps.put(FinishStep.class, new FinishStep(model, signView, this));

        return steps;
    }

    /**
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws DSSException
     */
    public void signDocument() throws IOException, NoSuchAlgorithmException, DSSException {

        final SignatureModel model = getModel();

        final File fileToSign = model.getSelectedFile();
        final SignatureTokenConnection tokenConnection = model.getTokenConnection();
        final DSSPrivateKeyEntry privateKey = model.getSelectedPrivateKey();

        final SignatureParameters parameters = new SignatureParameters();
        parameters.setSigningDate(new Date());
        // Bob (20130515) Deprecated: parameters.setSigningCertificate(privateKey.getCertificate());
        // Bob (20130515) Deprecated: parameters.setCertificateChain(privateKey.getCertificateChain());
        parameters.setPrivateKeyEntry(privateKey);
        parameters.setSignatureFormat(SignatureFormat.valueByName(model.getLevel()));
        parameters.setSignaturePackaging(model.getPackaging());

        if (model.isClaimedCheck()) {
            parameters.setClaimedSignerRole(model.getClaimedRole());
        }


        String moccaSignatureAlgorithm = model.getMoccaSignatureAlgorithm();
        if ("sha256".equalsIgnoreCase(moccaSignatureAlgorithm)) {

            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        } else {

            parameters.setDigestAlgorithm(DigestAlgorithm.SHA1);
        }

        if (model.isSignaturePolicyCheck()) {
            final byte[] hashValue = Base64.decodeBase64(model.getSignaturePolicyValue());
            final Policy policy = parameters.getSignaturePolicy();
            policy.setHashValue(hashValue);
            policy.setId(model.getSignaturePolicyId());
            DigestAlgorithm digestAlgo = DigestAlgorithm.forName(model.getSignaturePolicyAlgo());
            policy.setDigestAlgo(digestAlgo);
        }

        final DSSDocument signedDocument = SigningUtils
              .signDocument(fileToSign, parameters, tspSource, certificateVerifier, tokenConnection, privateKey);
        IOUtils.copy(signedDocument.openStream(), new FileOutputStream(model.getTargetFile()));
    }
}
