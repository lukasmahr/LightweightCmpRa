/*
 *  Copyright (c) 2020 Siemens AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 */
package com.siemens.pki.lightweightcmpra.test;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.server.BaseHttpServer;
import com.siemens.pki.lightweightcmpra.util.MessageDumper;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

/**
 *
 * a HTTP/HTTPS server needed for REST interfaces
 *
 */
@SuppressWarnings("restriction")
public final class InventoryRestServerMock extends BaseHttpServer {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(InventoryRestServerMock.class);
    private static Decoder urlDecoder = Base64.getUrlDecoder();

    /**
     * @param args
     *            command line arguments.
     * @throws IOException
     * @throws MalformedURLException
     */
    public static void main(final String[] args)
            throws MalformedURLException, IOException {
        if (args == null || args.length != 1) {
            System.err.println("call with <serving URL> as the only parameter");
            return;
        }
        new InventoryRestServerMock(new URL(args[0]));
    }

    private static Map<String, String> parseQuery(final HttpExchange exchange)
            throws IOException {
        final InputStream requestBody = exchange.getRequestBody();
        final byte[] requestBodyBytes = new byte[requestBody.available()];
        requestBody.read(requestBodyBytes);
        final String query = new String(requestBodyBytes);
        final Map<String, String> queryPairs = new LinkedHashMap<>();
        for (final String pair : query.split("&")) {
            final int splitpos = pair.indexOf("=");
            final String key;
            if (splitpos > 0) {
                key = URLDecoder.decode(pair.substring(0, splitpos), "UTF-8");
            } else {
                key = pair;
            }
            final String value;
            if (splitpos > 0 && pair.length() > splitpos + 1) {
                value = URLDecoder.decode(pair.substring(splitpos + 1),
                        "UTF-8");
            } else {
                value = null;
            }
            queryPairs.put(key, value);
        }
        return queryPairs;
    }

    InventoryRestServerMock(final URL servingUrl) throws IOException {
        super(servingUrl);
    }

    private CertTemplate checkAndModifyRequest(
            final String base64EncodedTransactionId, final X500Name requesterDn,
            final X500Name requestedSubjectDn, final CertTemplate template) {

        LOGGER.info(String.format(
                "checkAndModifyRequest called: TransactionId:%s, requesterDn:%s, requestedSubjectDn: %s%ncertTemplate: %n%s",
                base64EncodedTransactionId, requesterDn, requestedSubjectDn,
                MessageDumper.dumpAsn1Object(template)));
        // for test purposes just strip off anything else than subject and public key
        return new CertTemplateBuilder().setPublicKey(template.getPublicKey())
                .setSubject(requestedSubjectDn).build();
    }

    @Override
    public void handle(final HttpExchange exchange) throws IOException {
        try {
            final String method = exchange.getRequestMethod().toUpperCase();
            switch (method) {
            case "POST":
                handlePost(exchange);
                break;
            default:
                sendHttpErrorResponse(exchange,
                        HttpURLConnection.HTTP_BAD_METHOD,
                        "method " + method + " not supported");
            }
        } finally {
            exchange.getResponseBody().close();
        }

    }

    private String handleCheckAndModifyRequest(final HttpExchange exchange)
            throws IOException {
        final Map<String, String> queryParams = parseQuery(exchange);
        final String base64EncodedTransactionId =
                queryParams.get("transactionID");
        if (base64EncodedTransactionId == null) {
            sendHttpErrorResponse(exchange, HttpURLConnection.HTTP_BAD_REQUEST,
                    "transactionID missing in query");
            return null;
        }
        final String requesterDnAsString = queryParams.get("requesterDn");
        if (requesterDnAsString == null) {
            sendHttpErrorResponse(exchange, HttpURLConnection.HTTP_BAD_REQUEST,
                    "requesterDn missing in query");
            return null;
        }
        final X500Name requesterDn = new X500Name(requesterDnAsString);
        final String requestedSubjectDnAsString =
                queryParams.get("requestedSubjectDn");
        if (requestedSubjectDnAsString == null) {
            sendHttpErrorResponse(exchange, HttpURLConnection.HTTP_BAD_REQUEST,
                    "requestedSubjectDn missing in query");
            return null;
        }
        final X500Name requestedSubjectDn =
                new X500Name(requestedSubjectDnAsString);
        final String base64EncodedCertTemplate =
                queryParams.get("certTemplate");
        if (base64EncodedCertTemplate == null) {
            sendHttpErrorResponse(exchange, HttpURLConnection.HTTP_BAD_REQUEST,
                    "certTemplate missing in query");
            return null;
        }
        final CertTemplate certTemplate = CertTemplate
                .getInstance(urlDecoder.decode(base64EncodedCertTemplate));
        final CertTemplate respondedTemplate =
                checkAndModifyRequest(base64EncodedTransactionId, requesterDn,
                        requestedSubjectDn, certTemplate);
        final String base64EncodedResponseTemplate =
                respondedTemplate == null ? ""
                        : Base64.getMimeEncoder()
                                .encodeToString(respondedTemplate.getEncoded());
        final boolean granted = true;
        return String.format(
                "{\"granted\":\"%s\",\"updatedCertTemplate\":\"%s\"}",
                //
                granted, base64EncodedResponseTemplate);
    }

    private void handlePost(final HttpExchange exchange) {
        try {
            final String path = exchange.getRequestURI().getPath();
            String responseString = null;
            if (path.endsWith("checkAndModifyRequest")) {
                responseString = handleCheckAndModifyRequest(exchange);
            } else if (path.endsWith("storeNewCertificate")) {
                responseString = handleStoreNewCertificate(exchange);
            }
            final Headers responseHeaders = exchange.getResponseHeaders();
            responseHeaders.set("Content-Type", MediaType.APPLICATION_JSON);
            responseHeaders.set("Connection", "close");
            if (responseString != null) {
                final byte[] responseBody = responseString.getBytes();
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK,
                        responseBody.length);
                exchange.getResponseBody().write(responseBody);
                exchange.getResponseBody().close();
            }
        } catch (final Exception ex) {
            try {
                sendHttpErrorResponse(exchange,
                        HttpURLConnection.HTTP_INTERNAL_ERROR,
                        "internal error: " + ex.getLocalizedMessage());
            } catch (final IOException e1) {
            }
        }
    }

    private String handleStoreNewCertificate(final HttpExchange exchange)
            throws IOException {
        final Map<String, String> queryParams = parseQuery(exchange);
        final String base64EncodedTransactionId =
                queryParams.get("transactionID");
        if (base64EncodedTransactionId == null) {
            sendHttpErrorResponse(exchange, HttpURLConnection.HTTP_BAD_REQUEST,
                    "transactionID missing in query");
            return null;
        }
        final String base64EncodedCertificate = queryParams.get("certificate");
        if (base64EncodedCertificate == null) {
            sendHttpErrorResponse(exchange, HttpURLConnection.HTTP_BAD_REQUEST,
                    "certificate missing in query");
            return null;
        }
        final Certificate certificate = Certificate
                .getInstance(urlDecoder.decode(base64EncodedCertificate));

        final String subjectDnAsString = queryParams.get("subjectDN");
        if (subjectDnAsString == null) {
            sendHttpErrorResponse(exchange, HttpURLConnection.HTTP_BAD_REQUEST,
                    "subjectDN missing in query");
            return null;
        }
        final X500Name subjectDn = new X500Name(subjectDnAsString);
        final String issuerDnAsString = queryParams.get("issuerDN");
        if (issuerDnAsString == null) {
            sendHttpErrorResponse(exchange, HttpURLConnection.HTTP_BAD_REQUEST,
                    "issuerDN missing in query");
            return null;
        }
        final X500Name issuerDn = new X500Name(issuerDnAsString);
        final String serialNumberAsString = queryParams.get("serialNumber");
        if (serialNumberAsString == null) {
            sendHttpErrorResponse(exchange, HttpURLConnection.HTTP_BAD_REQUEST,
                    "serialNumber missing in query");
            return null;
        }
        storeNewCertificate(base64EncodedTransactionId, certificate,
                serialNumberAsString, subjectDn, issuerDn);
        return "true";
    }

    private void sendHttpErrorResponse(final HttpExchange exchange,
            final int httpStatusCode, final String errorText)
            throws IOException {
        final byte[] responseBody = errorText.getBytes();
        exchange.getResponseHeaders().set("Content-Type", "text/plain");
        exchange.sendResponseHeaders(httpStatusCode, responseBody.length);
        exchange.getResponseBody().write(responseBody);

    }

    private void storeNewCertificate(final String base64EncodedTransactionId,
            final Certificate certificate, final String serialNumberAsString,
            final X500Name subjectDn, final X500Name issuerDn) {
        LOGGER.info(String.format(
                "storeNewCertificate called: transactionID: %s%ncertificate: %n%s%nsubjectDN: %s, issuerDN: %s, serialNumber %s",
                base64EncodedTransactionId,
                MessageDumper.dumpAsn1Object(certificate), subjectDn, issuerDn,
                serialNumberAsString));
    }

}
