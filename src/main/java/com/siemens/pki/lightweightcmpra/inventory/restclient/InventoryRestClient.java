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

package com.siemens.pki.lightweightcmpra.inventory.restclient;

import java.io.IOException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Locale;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.UriBuilder;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;

import com.siemens.pki.lightweightcmpra.config.xmlparser.HTTPCLIENTCONFIGURATION;
import com.siemens.pki.lightweightcmpra.config.xmlparser.HTTPCLIENTCONFIGURATION.TlsConfig;
import com.siemens.pki.lightweightcmpra.cryptoservices.CertUtility;
import com.siemens.pki.lightweightcmpra.cryptoservices.TrustCredentialAdapter;
import com.siemens.pki.lightweightcmpra.msgprocessing.InventoryIF;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpValidationException;

public class InventoryRestClient implements InventoryIF {

    private static Encoder urlEncoder = Base64.getUrlEncoder();

    private final InventoryRestDefinition proxy;

    private final String path;

    private final ResteasyClient client;

    public InventoryRestClient(final HTTPCLIENTCONFIGURATION config)
            throws Exception {
        path = config.getServerUrl();
        final ResteasyClientBuilder cb =
                (ResteasyClientBuilder) ClientBuilder.newBuilder();
        if (path.toLowerCase(Locale.ENGLISH).startsWith("https://")) {
            final TlsConfig tlsConfig = config.getTlsConfig();
            if (tlsConfig == null) {
                throw new IllegalArgumentException(
                        "https client without TlsConfig in configuration");
            }
            final char[] keyStorePassword =
                    tlsConfig.getKeyStorePassword().toCharArray();
            final KeyStore keyStore = CertUtility.loadKeystoreFromFile(
                    tlsConfig.getKeyStorePath(), keyStorePassword);
            final KeyManagerFactory kmf = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keyStorePassword);
            final TrustManagerFactory tmf = TrustCredentialAdapter
                    .createTrustManagerFactoryFromConfig(tlsConfig, true);
            final SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(),
                    new SecureRandom());
            cb.sslContext(sslContext);
        }
        client = cb.build();
        final ResteasyWebTarget target =
                client.target(UriBuilder.fromPath(path));
        proxy = target.proxy(InventoryRestDefinition.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PKIMessage checkAndModifyRequest(final PKIMessage request)
            throws CmpProcessingException {

        final CMPCertificate[] extraCerts = request.getExtraCerts();
        final String requesterDn;
        if (extraCerts != null && extraCerts.length > 0) {
            requesterDn =
                    extraCerts[0].getX509v3PKCert().getSubject().toString();

        } else {
            requesterDn = null;
        }
        final CertRequest certReq =
                ((CertReqMessages) request.getBody().getContent())
                        .toCertReqMsgArray()[0].getCertReq();
        final CertTemplate certTemplate = certReq.getCertTemplate();
        final String requestedSubjectDn = certTemplate.getSubject().toString();
        byte[] encodedCertTemplate;
        try {
            encodedCertTemplate = certTemplate.getEncoded();
        } catch (final IOException e) {
            throw new CmpProcessingException("external component at " + path,
                    PKIFailureInfo.systemFailure, e);
        }
        final String base64EncodedTemplate =
                urlEncoder.encodeToString(encodedCertTemplate);
        final String base64EncodedTransactionId = urlEncoder.encodeToString(
                request.getHeader().getTransactionID().getOctets());
        final CheckAndModifyResult checkAndModifyResult =
                proxy.checkAndModifyRequest(base64EncodedTransactionId,
                        requesterDn, requestedSubjectDn, base64EncodedTemplate);
        if (!checkAndModifyResult.isGranted()) {
            throw new CmpValidationException("external component at " + path,
                    PKIFailureInfo.badMessageCheck,
                    "request not granted by external component at " + path);
        }
        final byte[] updatedCertTemplate =
                checkAndModifyResult.getUpdatedCertTemplate();
        if (updatedCertTemplate == null || updatedCertTemplate.length == 0
                || Arrays.compare(encodedCertTemplate,
                        updatedCertTemplate) == 0) {
            // template was not modified
            return request;
        }
        // template has changed
        final PKIBody newBody =
                new PKIBody(request.getBody().getType(),
                        new CertReqMessages(new CertReqMsg(
                                new CertRequest(certReq.getCertReqId(),
                                        CertTemplate.getInstance(
                                                updatedCertTemplate),
                                        certReq.getControls()),
                                new ProofOfPossession(), null)));
        return new PKIMessage(request.getHeader(), newBody);
    }

    @Override
    public void storeCertificate(final X509Certificate enrolledCertificate,
            final PKIMessage responseFromUpstream) {
        try {
            final String base64EncodedTransactionId =
                    urlEncoder.encodeToString(responseFromUpstream.getHeader()
                            .getTransactionID().getOctets());
            final String base64EncodedCertificate =
                    urlEncoder.encodeToString(enrolledCertificate.getEncoded());
            final String serialNumberAsString =
                    enrolledCertificate.getSerialNumber().toString();
            urlEncoder.encodeToString(enrolledCertificate.getEncoded());

            final String subjectDnAsString =
                    enrolledCertificate.getSubjectX500Principal().getName();
            final String issuerDnAsString =
                    enrolledCertificate.getIssuerX500Principal().getName();
            final boolean result = proxy.storeEnrolledCerificate(
                    base64EncodedTransactionId, base64EncodedCertificate,
                    serialNumberAsString, subjectDnAsString, issuerDnAsString);
            if (!result) {
                throw new CmpProcessingException(
                        "external component at " + path,
                        PKIFailureInfo.systemFailure,
                        "unable to store certificate");
            }
        } catch (final CertificateEncodingException e) {
            throw new CmpProcessingException("external component at " + path,
                    PKIFailureInfo.systemFailure, e);
        }
    }

}
