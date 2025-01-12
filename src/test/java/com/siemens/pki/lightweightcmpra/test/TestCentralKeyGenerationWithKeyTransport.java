/*
 *  Copyright (c) 2021 Siemens AG
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

import org.bouncycastle.asn1.cmp.PKIBody;
import org.junit.Before;
import org.junit.Test;

import com.siemens.pki.lightweightcmpra.cryptoservices.BaseCredentialService;
import com.siemens.pki.lightweightcmpra.cryptoservices.CmsDecryptor;
import com.siemens.pki.lightweightcmpra.protection.PasswordBasedMacProtection;
import com.siemens.pki.lightweightcmpra.protection.ProtectionProvider;
import com.siemens.pki.lightweightcmpra.protection.SignatureBasedProtection;

public class TestCentralKeyGenerationWithKeyTransport
        extends CkgOnlineEnrollmentTestcaseBase {

    private CmsDecryptor keyTransportDecryptor;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        final BaseCredentialService eeRsaCredentials =
                new BaseCredentialService("credentials/CMP_EE_Keystore_RSA.p12",
                        TestUtils.PASSWORD_AS_CHAR_ARRAY);
        keyTransportDecryptor =
                new CmsDecryptor(eeRsaCredentials.getEndCertificate(),
                        eeRsaCredentials.getPrivateKey(), null);
    }

    @Test
    public void testCrWithKeyTransport() throws Exception {
        executeCrmfCertificateRequestWithoutKey(PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP,
                new SignatureBasedProtection(
                        "credentials/CMP_EE_Keystore_RSA.p12",
                        TestUtils.PASSWORD_AS_CHAR_ARRAY),
                TestUtils.createCmpClient("http://localhost:6010/ckgtrans"),
                keyTransportDecryptor, verifier);
    }

    @Test
    public void testCrWithPassword() throws Exception {
        final ProtectionProvider macBasedProvider =
                new PasswordBasedMacProtection("keyIdentification",
                        "myPresharedSecret", 6, 1234,
                        PasswordBasedMacProtection.DEFAULT_OWF_OID,
                        PasswordBasedMacProtection.DEFAULT_MAC_OID);
        executeCrmfCertificateRequestWithoutKey(PKIBody.TYPE_CERT_REQ,
                PKIBody.TYPE_CERT_REP, macBasedProvider,
                TestUtils.createCmpClient("http://localhost:6012/ckgwithmac"),
                new CmsDecryptor(null, null, "myPresharedSecret".toCharArray()),
                verifier);
    }

}
