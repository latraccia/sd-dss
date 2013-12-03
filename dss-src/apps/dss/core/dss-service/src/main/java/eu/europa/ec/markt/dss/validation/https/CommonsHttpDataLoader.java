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

package eu.europa.ec.markt.dss.validation.https;

import eu.europa.ec.markt.dss.exception.CannotFetchDataException;
import eu.europa.ec.markt.dss.exception.CannotFetchDataException.MSG;
import eu.europa.ec.markt.dss.manager.ProxyPreferenceManager;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.util.EntityUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.logging.Logger;

/**
 * Implementation of HTTPDataLoader using HttpClient. More flexible for HTTPS without having to add the certificate to
 * the JVM TrustStore.
 * 
 * @version $Revision: 2823 $ - $Date: 2013-10-29 20:39:42 +0100 (mar., 29 oct. 2013) $
 */
public class CommonsHttpDataLoader implements HTTPDataLoader {

   public static final int PORT_HTTP = 80;
   public static final int PORT_HTTPS = 443;

   // TODO: It was 6000
   public static final int TIMEOUT_CONNECTION = 6000;
   public static final int TIMEOUT_SOCKET = 6000;

   private static final Logger LOG = Logger.getLogger(CommonsHttpDataLoader.class.getName());

   private String contentType;

   private ClientConnectionManager connectionManager;
   private SSLSocketFactory sslSocketFactory;
   private ProxyPreferenceManager proxyPreferenceManager;

   private int portHttp = PORT_HTTP;
   private int portHttps = PORT_HTTPS;
   private int timeoutConnection = TIMEOUT_CONNECTION;
   private int timeoutSocket = TIMEOUT_SOCKET;

   /**
    * The default constructor for CommonsHttpDataLoader.
    */
   public CommonsHttpDataLoader() {
      this(null);
   }

   /**
    * The default constructor for CommonsHttpDataLoader.
    * 
    * @param contentType The content type of each request
    */
   public CommonsHttpDataLoader(final String contentType) {
      setContentType(contentType);
   }

   private ClientConnectionManager getConnectionManager() throws IOException {

      if (connectionManager != null) {
         return connectionManager;
      }
      if (sslSocketFactory != null) {
         return connectionManager;
      }

      LOG.warning("HTTPS TrustStore undefined, using default");
      try {
         sslSocketFactory = new SSLSocketFactory(new OptimistTrustStrategy(), new OptimistX509HostnameVerifier());
      } catch (Exception e) {
         throw new IOException(e);
      }

      connectionManager = new PoolingClientConnectionManager(new SchemeRegistry());
      setConnectionManagerSchemeHttp();
      setConnectionManagerSchemeHttps();

      return connectionManager;
   }

   private void setConnectionManagerSchemeHttp() {
      if (connectionManager == null) {
         return;
      }
      final SchemeRegistry schemeRegistry = connectionManager.getSchemeRegistry();
      schemeRegistry.register(new Scheme("http", portHttp, PlainSocketFactory.getSocketFactory()));
   }

   private void setConnectionManagerSchemeHttps() {
      if (connectionManager == null) {
         return;
      }
      final SchemeRegistry schemeRegistry = connectionManager.getSchemeRegistry();
      schemeRegistry.register(new Scheme("https", portHttps, sslSocketFactory));
   }

   protected HttpClient createClient(final String url) throws IOException {

      final ClientConnectionManager conManager = getConnectionManager();
      final DefaultHttpClient client = new DefaultHttpClient(conManager);

      client.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, timeoutConnection);
      client.getParams().setParameter(CoreConnectionPNames.SO_TIMEOUT, timeoutSocket);

      configureClientProxy(url, client);

      return client;
   }

   private void configureClientProxy(final String url, final DefaultHttpClient client) throws MalformedURLException {
      if (proxyPreferenceManager == null) {
         return;
      }
      final String protocol = new URL(url).getProtocol();

      final boolean proxyHTTPS = protocol.equalsIgnoreCase("https") && proxyPreferenceManager.isHttpsEnabled();
      final boolean proxyHTTP = protocol.equalsIgnoreCase("http") && proxyPreferenceManager.isHttpEnabled();

      if (!proxyHTTPS && !proxyHTTP) {
         return;
      }

      String proxyHost = null;
      int proxyPort = 0;
      String proxyUser = null;
      String proxyPassword = null;

      if (proxyHTTPS) {
         LOG.fine("Use proxy https parameters");
         final Long port = proxyPreferenceManager.getHttpsPort();
         proxyPort = port != null ? port.intValue() : 0;
         proxyHost = proxyPreferenceManager.getHttpsHost();
         proxyUser = proxyPreferenceManager.getHttpsUser();
         proxyPassword = proxyPreferenceManager.getHttpsPassword();
      } else // noinspection ConstantConditions
      if (proxyHTTP) {
         LOG.fine("Use proxy http parameters");
         final Long port = proxyPreferenceManager.getHttpPort();
         proxyPort = port != null ? port.intValue() : 0;
         proxyHost = proxyPreferenceManager.getHttpHost();
         proxyUser = proxyPreferenceManager.getHttpUser();
         proxyPassword = proxyPreferenceManager.getHttpPassword();

      }

      if (StringUtils.isNotEmpty(proxyUser) && StringUtils.isNotEmpty(proxyPassword)) {
         LOG.finer("proxy user: " + proxyUser + ":" + proxyPassword);
         AuthScope proxyAuth = new AuthScope(proxyHost, proxyPort);
         UsernamePasswordCredentials proxyCredentials = new UsernamePasswordCredentials(proxyUser, proxyPassword);
         client.getCredentialsProvider().setCredentials(proxyAuth, proxyCredentials);
      }

      LOG.finer("proxy host/port: " + proxyHost + ":" + proxyPort);
      // TODO SSL peer shut down incorrectly when protocol is https
      // HttpHost proxy = new HttpHost(proxyHost, proxyPort, protocol);
      HttpHost proxy = new HttpHost(proxyHost, proxyPort, "http");
      client.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
   }

   @Override
   public InputStream get(final String url) throws CannotFetchDataException {
      LOG.info("Fetching data via GET from url " + url);

      HttpGet httpRequest = null;
      HttpResponse httpResponse = null;

      try {

         final URI uri = URI.create(url.trim());
         httpRequest = new HttpGet(uri);
         if (contentType != null) {
            httpRequest.setHeader("Content-Type", contentType);
         }

         final HttpClient client = createClient(url);
         httpResponse = client.execute(httpRequest);

         final int statusCode = httpResponse.getStatusLine().getStatusCode();
         final boolean statusOk = statusCode == HttpStatus.SC_OK;
         LOG.fine("status code is " + statusCode + " - " + (statusOk ? "OK" : "NOK"));
         if (!statusOk) {
            LOG.warning("No content available via GET from url - will use nothing: " + url);
            return new ByteArrayInputStream(new byte[0]);
         }

         final HttpEntity responseEntity = httpResponse.getEntity();
         if (responseEntity == null) {
            LOG.warning("No message entity for this response - will use nothing: " + url);
            return new ByteArrayInputStream(new byte[0]);
         }
         final InputStream responseContent = responseEntity.getContent();
         return new ByteArrayInputStream(IOUtils.toByteArray(responseContent));

      } catch (IllegalArgumentException ex) {
         throw new CannotFetchDataException(MSG.UNKNOWN_HOST_EXCEPTION, url);
      } catch (IOException ex) {
         throw new CannotFetchDataException(ex, url);
      } finally {
         if (httpRequest != null) {
            httpRequest.releaseConnection();
         }
         if (httpResponse != null) {
            EntityUtils.consumeQuietly(httpResponse.getEntity());
         }
      }
   }

   @Override
   public InputStream post(final String url, final InputStream content) throws CannotFetchDataException {
      LOG.fine("Fetching data via POST from url " + url);

      HttpPost httpRequest = null;
      HttpResponse httpResponse = null;

      try {
         final URI uri = URI.create(url.trim());
         httpRequest = new HttpPost(uri);

         // The length for the InputStreamEntity is needed, because some receivers (on the other side) need this
         // information.
         // To determine the length, we cannot read the content-stream up to the end and re-use it afterwards.
         // This is because, it may not be possible to reset the stream (= go to position 0).
         // So, the solution is to cache temporarily the complete content data (as we do not expect much here) in a
         // byte-array.
         final ByteArrayOutputStream bos = new ByteArrayOutputStream();
         IOUtils.copy(content, bos);
         final byte[] data = bos.toByteArray();
         final ByteArrayInputStream bis = new ByteArrayInputStream(data);

         final HttpEntity requestEntity = new InputStreamEntity(bis, data.length);
         httpRequest.setEntity(requestEntity);
         if (contentType != null) {
            httpRequest.setHeader("Content-Type", contentType);
         }

         final HttpClient client = createClient(url);
         httpResponse = client.execute(httpRequest);

         final int statusCode = httpResponse.getStatusLine().getStatusCode();
         final boolean statusOk = statusCode == HttpStatus.SC_OK;
         LOG.fine("status code is " + statusCode + " - " + (statusOk ? "OK" : "NOK"));
         if (!statusOk) {
            LOG.warning("No content available via POST from url - will use nothing: " + url);
            return new ByteArrayInputStream(new byte[0]);
         }

         LOG.info("Successfully contacted " + url);
         final HttpEntity responseEntity = httpResponse.getEntity();
         if (responseEntity == null) {
            LOG.warning("No message entity for this response - will use nothing: " + url);
            return new ByteArrayInputStream(new byte[0]);
         }
         final InputStream responseContent = responseEntity.getContent();
         return new ByteArrayInputStream(IOUtils.toByteArray(responseContent));

      } catch (IllegalArgumentException ex) {
         throw new CannotFetchDataException(MSG.UNKNOWN_HOST_EXCEPTION, url);
      } catch (IOException ex) {
         throw new CannotFetchDataException(ex, url);
      } finally {
         if (httpRequest != null) {
            httpRequest.releaseConnection();
         }
         if (httpResponse != null) {
            EntityUtils.consumeQuietly(httpResponse.getEntity());
         }
      }
   }

   /**
    * the port used for the http protocol when creating the connectionmanager
    * 
    * @return the value
    */
   public int getPortHttp() {
      return portHttp;
   }

   /**
    * the port used for the http protocol when creating the connectionmanager.<br/>
    * if the value differs from the current one, then an existing connectionmanager will be amended with a new scheme
    * using this port.
    * 
    * @param portHttp the value
    */
   public void setPortHttp(final int portHttp) {
      final boolean changed = this.portHttp != portHttp;
      this.portHttp = portHttp;
      if (changed) {
         setConnectionManagerSchemeHttp();
      }
   }

   /**
    * the port used for the https protocol when creating the connectionmanager
    * 
    * @return the value
    */
   public int getPortHttps() {
      return portHttps;
   }

   /**
    * the port used for the https protocol when creating the connectionmanager.<br/>
    * if the value differs from the current one, then an existing connectionmanager will be amended with a new scheme
    * using this port.
    * 
    * @param portHttps the value
    */
   public void setPortHttps(final int portHttps) {
      final boolean changed = this.portHttps != portHttps;
      this.portHttps = portHttps;
      if (changed) {
         setConnectionManagerSchemeHttps();
      }
   }

   /**
    * see {@link CoreConnectionPNames#CONNECTION_TIMEOUT}. used when the httpclient is created.
    * 
    * @return the value (millis)
    */
   public int getTimeoutConnection() {
      return timeoutConnection;
   }

   /**
    * see {@link CoreConnectionPNames#CONNECTION_TIMEOUT}. used when the httpclient is created.
    * 
    * @param timeoutConnection the value (millis)
    */
   public void setTimeoutConnection(final int timeoutConnection) {
      this.timeoutConnection = timeoutConnection;
   }

   /**
    * see {@link CoreConnectionPNames#SO_TIMEOUT}. used when the httpclient is created.
    * 
    * @return the value (millis)
    */
   public int getTimeoutSocket() {
      return timeoutSocket;
   }

   /**
    * see {@link CoreConnectionPNames#SO_TIMEOUT}. used when the httpclient is created.
    * 
    * @param timeoutSocket the value (millis)
    */
   public void setTimeoutSocket(final int timeoutSocket) {
      this.timeoutSocket = timeoutSocket;
   }

   /**
    * 
    * @return the contentType
    */
   public String getContentType() {
      return contentType;
   }

   /**
    * @param contentType the contentType to set
    */
   public void setContentType(final String contentType) {
      this.contentType = contentType;
   }

   /**
    * @param proxyPreferenceManager the proxyPreferenceManager to set
    */
   public void setProxyPreferenceManager(final ProxyPreferenceManager proxyPreferenceManager) {
      this.proxyPreferenceManager = proxyPreferenceManager;
   }

}
