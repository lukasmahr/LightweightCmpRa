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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "result", propOrder = {"granted", "updatedCertTemplate"})
public class CheckAndModifyResult {

    private boolean granted;

    private byte[] updatedCertTemplate;

    /**
     * return <code>null</code> or updated CertTemplate of the request
     *
     * @return updated CertTemplate of the request or <code>null</code> if the
     *         called service agrees to the template
     */
    byte[] getUpdatedCertTemplate() {
        return updatedCertTemplate;
    }

    /**
     * return true if request was granted
     *
     * @return true if request was granted
     */
    boolean isGranted() {
        return granted;
    }

}
