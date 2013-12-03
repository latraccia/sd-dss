package eu.europa.ec.markt.dss.applet.util;

import java.io.IOException;
import java.net.URI;
import java.util.ResourceBundle;

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
public final class ResourceUtils {

    private static final ResourceBundle BUNDLE_I18N;

    static {
        BUNDLE_I18N = ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n");
    }

    /**
     * 
     * @param key
     * @return
     */
    public static String getI18n(final String key) {
        return BUNDLE_I18N.getString(key);
    }

    /**
     * 
     * @param uri
     * @throws IOException
     */
    public static void openFile(final URI uri) throws IOException {
        Runtime.getRuntime().exec("rundll32 url.dll,FileProtocolHandler " + uri.toString());
    }

    private ResourceUtils() {
    }

}
