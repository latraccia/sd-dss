package eu.europa.ec.markt.dss.applet.main;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.logging.Level;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

import com.google.inject.Guice;
import com.google.inject.Injector;
import eu.europa.ec.markt.dss.applet.controller.ActivityController;
import eu.europa.ec.markt.dss.applet.main.Parameters.AppletUsage;
import eu.europa.ec.markt.dss.applet.util.DSSStringUtils;
import eu.europa.ec.markt.dss.applet.wizard.extension.ExtensionWizardController;
import eu.europa.ec.markt.dss.applet.wizard.signature.SignatureWizardController;
import eu.europa.ec.markt.dss.applet.wizard.validation.ValidationWizardController;
import eu.europa.ec.markt.dss.applet.wizard.validationpolicy.ValidationPolicyWizardController;
import eu.europa.ec.markt.dss.common.SignatureTokenType;
import eu.europa.ec.markt.dss.commons.swing.mvc.applet.AppletCore;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;

/**
 * 
 * TODO
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
@SuppressWarnings("serial")
public class DSSAppletCore extends AppletCore {

    private static final String PARAM_APPLET_USAGE = "usage";

    private static final String PARAM_SERVICE_URL = "service_url";

    private static final String PARAM_PKCS11_FILE = "pkcs11_file";
    private static final String PARAM_PKCS12_FILE = "pkcs12_file";

    private static final String PARAM_SIGNATURE_POLICY_ALGO = "signature_policy_algo";
    private static final String PARAM_SIGNATURE_POLICY_HASH = "signature_policy_hash";

    private static final String PARAM_STRICT_RFC3370 = "strict_rfc3370";

    private static final String PARAM_TOKEN_TYPE = "token_type";

    private static final String PARAM_SIGNATURE_PACKAGING = "signature_packaging";
    private static final String PARAM_SIGNATURE_FORMAT = "signature_format";
    private static final String PARAM_SIGNATURE_LEVEL = "signature_level";

    private static final String PARAM_DEFAULT_POLICY_URL = "default_policy_url";

    private Parameters parameters;

    private Injector injector;

    /**
     * Default constructor
     */
    public DSSAppletCore() {
        this(true);
    }

    public DSSAppletCore(boolean createInjector) {
        if (createInjector) {
            injector = Guice.createInjector(new AppletModule(this));
        } else {
            LOG.info("Injector will be provided manually");
        }
    }

    public void setInjector(Injector injector) {
        this.injector = injector;
    }

    /**
     * @return the parameters
     */
    public Parameters getParameters() {
        return parameters;
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.ecodex.dss.commons.swing.mvc.AbstractApplet#layout(javax.swing.JApplet)
     */
    @Override
    protected void layout(final AppletCore core) {
        getController(ActivityController.class).display();
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.ecodex.dss.commons.swing.mvc.AbstractApplet#registerControllers()
     */
    @Override
    protected void registerControllers() {
        getControllers().put(ActivityController.class, injector.getInstance(ActivityController.class));
        getControllers().put(ValidationWizardController.class, injector.getInstance(ValidationWizardController.class));
        getControllers().put(SignatureWizardController.class, injector.getInstance(SignatureWizardController.class));
        getControllers().put(ExtensionWizardController.class, injector.getInstance(ExtensionWizardController.class));
        getControllers().put(ValidationPolicyWizardController.class,
              injector.getInstance(ValidationPolicyWizardController.class));
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.ecodex.dss.commons.swing.mvc.applet.AppletCore#registerParameters()
     */
    @Override
    protected void registerParameters(ParameterProvider parameterProvider) {

        LOG.log(Level.INFO, "Register applet parameters ");

        final Parameters parameters = new Parameters();

        final String appletUsageParam = parameterProvider.getParameter(PARAM_APPLET_USAGE);
        if (StringUtils.isNotEmpty(appletUsageParam)) {
            parameters.setAppletUsage(AppletUsage.valueOf(appletUsageParam.toUpperCase()));
        }

        final String signatureFormatParam = parameterProvider.getParameter(PARAM_SIGNATURE_FORMAT);
        if (!StringUtils.isEmpty(signatureFormatParam)) {
            parameters.setSignatureFormat(signatureFormatParam);
            final String signaturePackagingParam = parameterProvider.getParameter(PARAM_SIGNATURE_PACKAGING);
            if (!StringUtils.isEmpty(signaturePackagingParam)) {
                parameters.setSignaturePackaging(SignaturePackaging.valueOf(signaturePackagingParam));
                final String signatureLevelParam = parameterProvider.getParameter(PARAM_SIGNATURE_LEVEL);
                if (!StringUtils.isEmpty(signatureLevelParam)) {
                    parameters.setSignatureLevel(signatureLevelParam);
                }
            }
        }

        // Service URL
        final String serviceParam = parameterProvider.getParameter(PARAM_SERVICE_URL);
        if (StringUtils.isEmpty(serviceParam)) {
            throw new IllegalArgumentException(PARAM_SERVICE_URL + "cannot be empty");
        }
        parameters.setServiceURL(serviceParam);

        // Signature Token
        final String tokenParam = parameterProvider.getParameter(PARAM_TOKEN_TYPE);
        if (DSSStringUtils.contains(tokenParam, SignatureTokenType.MOCCA.name(), SignatureTokenType.MSCAPI.name(),
              SignatureTokenType.PKCS11.name(), SignatureTokenType.PKCS12.name())) {
            parameters.setSignatureTokenType(SignatureTokenType.valueOf(tokenParam));
        } else {
            LOG.log(Level.WARNING, "Invalid value of " + PARAM_TOKEN_TYPE + " parameter: {0}", tokenParam);
        }

        // RFC3370
        final String rfc3370Param = parameterProvider.getParameter(PARAM_STRICT_RFC3370);
        if (StringUtils.isNotEmpty(rfc3370Param)) {
            try {
                parameters.setStrictRFC3370(Boolean.parseBoolean(rfc3370Param));
            } catch (final Exception e) {
                LOG.log(Level.WARNING, "Invalid value of " + PARAM_STRICT_RFC3370 + " parameter: {0}", rfc3370Param);
            }
        }

        // File path PKCS11
        final String pkcs11Param = parameterProvider.getParameter(PARAM_PKCS11_FILE);
        if (StringUtils.isNotEmpty(pkcs11Param)) {
            final File file = new File(pkcs11Param);
            if (!file.exists() || file.isFile()) {
                LOG.log(Level.WARNING, "Invalid value of " + PARAM_PKCS11_FILE + " parameter: {0}", pkcs11Param);
            }
            parameters.setPkcs11File(file);
        }

        // File path PKCS12
        final String pkcs12Param = parameterProvider.getParameter(PARAM_PKCS12_FILE);
        if (StringUtils.isNotEmpty(pkcs12Param)) {
            final File file = new File(pkcs12Param);
            if (!file.exists() || file.isFile()) {
                LOG.log(Level.WARNING, "Invalid value of " + PARAM_PKCS12_FILE + " parameter: {0}", pkcs11Param);
            }
            parameters.setPkcs12File(file);
        }

        final String signaturePolicyAlgoParam = parameterProvider.getParameter(PARAM_SIGNATURE_POLICY_ALGO);
        parameters.setSignaturePolicyAlgo(signaturePolicyAlgoParam);

        final String signaturePolicyValueParam = parameterProvider.getParameter(PARAM_SIGNATURE_POLICY_HASH);
        parameters.setSignaturePolicyValue(Base64.decodeBase64(signaturePolicyValueParam));

        // Default policy URL
        final String defaultPolicyUrl = parameterProvider.getParameter(PARAM_DEFAULT_POLICY_URL);
        if (StringUtils.isNotEmpty(defaultPolicyUrl)) {
            try {
                parameters.setDefaultPolicyUrl(new URL(defaultPolicyUrl));
            } catch (IOException e) {
                throw new IllegalArgumentException(PARAM_DEFAULT_POLICY_URL + " cannot be opened", e);
            }
        }

        this.parameters = parameters;

        LOG.log(Level.INFO, "Parameters - {0}", parameters);

    }
}
