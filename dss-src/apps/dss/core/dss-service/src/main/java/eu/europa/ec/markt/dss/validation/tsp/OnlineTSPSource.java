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

package eu.europa.ec.markt.dss.validation.tsp;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;

/**
 * Class encompassing a RFC 3161 TSA, accessed through HTTP(S) to a given URI
 * 
 * 
 * @version $Revision: 2362 $ - $Date: 2013-07-14 21:33:08 +0200 (dim., 14 juil. 2013) $
 */

public class OnlineTSPSource implements TSPSource {

   private String tspServer;

   private String policyOid;

   /**
    * The default constructor for OnlineTSPSource.
    */
   public OnlineTSPSource() {

      this(null);
   }

   /**
    * Build a OnlineTSPSource that will query the specified URL
    * 
    * @param tspServer
    */
   public OnlineTSPSource(String tspServer) {

      this.tspServer = tspServer;
   }

   /**
    * Set the URL of the TSA
    * 
    * @param tspServer
    */
   public void setTspServer(String tspServer) {

      this.tspServer = tspServer;
   }

   /**
    * Set the request policy
    * 
    * @param policyOid
    */
   public void setPolicyOid(String policyOid) {

      this.policyOid = policyOid;
   }

   @Override
   public TimeStampResponse getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) throws IOException {

      try {
         byte[] respBytes = null;

         // Setup the time stamp request
         TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
         tsqGenerator.setCertReq(true);
         if (policyOid != null) {
            tsqGenerator.setReqPolicy(policyOid);
         }
         BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
         TimeStampRequest request = tsqGenerator.generate(digestAlgorithm.getOid(), digest, nonce);
         byte[] requestBytes = request.getEncoded();

         // Call the communications layer
         respBytes = getTSAResponse(requestBytes);

         // Handle the TSA response
         TimeStampResponse response = new TimeStampResponse(respBytes);
         return response;

      } catch (TSPException ex) {
         throw new IOException("Invalid TSP response");
      }

   }

   /**
    * Get timestamp token - communications layer
    * 
    * @return - byte[] - TSA response, raw bytes (RFC 3161 encoded)
    */
   protected byte[] getTSAResponse(byte[] requestBytes) throws IOException {

      // Setup the TSA connection

      URL tspUrl = new URL(tspServer);
      URLConnection tsaConnection = tspUrl.openConnection();

      tsaConnection.setDoInput(true);
      tsaConnection.setDoOutput(true);
      tsaConnection.setUseCaches(false);
      tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
      tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");

      OutputStream out = tsaConnection.getOutputStream();
      out.write(requestBytes);
      out.close();

      // Get TSA response as a byte array
      InputStream inp = tsaConnection.getInputStream();
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      byte[] buffer = new byte[1024];
      int bytesRead = 0;
      while ((bytesRead = inp.read(buffer, 0, buffer.length)) >= 0) {
         baos.write(buffer, 0, bytesRead);
      }
      byte[] respBytes = baos.toByteArray();

      String encoding = tsaConnection.getContentEncoding();
      if (encoding != null && encoding.equalsIgnoreCase("base64")) {
         respBytes = DSSUtils.base64Decode(respBytes);
      }
      return respBytes;
   }

}
