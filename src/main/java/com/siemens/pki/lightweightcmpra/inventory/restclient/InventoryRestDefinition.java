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

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.jboss.resteasy.annotations.jaxrs.FormParam;

@Path("/ExternalInventory")
public interface InventoryRestDefinition {
    /**
     * check and maybe modify a certificate request
     *
     * @param transactionID
     *            the transactionID of the CMP request as base64url encoded
     *            string
     *
     * @param requesterDn
     *            subject subject DN of the CMP requester (first certificate in
     *            the extraCerts field of the CMP request)
     * @param requestedSubjectDn
     *            subject DN in the CertTemplate of the request
     * @param certTemplate
     *            the CertTemplate of the request as base64url encoded string
     *            encoded string
     * @return result of validation check
     */
    @POST
    @Path("/checkAndModifyRequest")
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    CheckAndModifyResult checkAndModifyRequest(
            @FormParam("transactionID") String transactionID,
            @FormParam("requesterDn") String requesterDn,
            @FormParam("requestedSubjectDn") String requestedSubjectDn,
            @FormParam("certTemplate") String certTemplate);

    /**
     * send the certificate returned by the CA to the external system
     *
     * @param transactionID
     *            the transactionID of the CMP request/response as base64url
     *            encoded string
     * @param certificate
     *            the base64url encoded certificate as returned by the CA
     * @param serialNumber
     *            the serial number of the certificate
     * @param subjectDN
     *            the subjectDN from the certificate
     * @param issuerDN
     *            the issuerDN from the certificate
     * @return true on success
     */
    @POST
    @Path("/storeNewCertificate")
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.TEXT_PLAIN})
    boolean storeEnrolledCerificate(
            @FormParam("transactionID") String transactionID,
            @FormParam("certificate") String certificate,
            @FormParam("serialNumber") String serialNumber,
            @FormParam("subjectDN") String subjectDN,
            @FormParam("issuerDN") String issuerDN);

}
