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
package com.siemens.pki.lightweightcmpra.client.online;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import com.siemens.pki.lightweightcmpra.msgvalidation.BaseCmpException;
import com.siemens.pki.lightweightcmpra.msgvalidation.CmpProcessingException;

/**
 * Implementation of a CMP over HTTP client.
 */
public class HttpSession extends ClientSession {

    private final URL remoteUrl;

    /**
     *
     * @param remoteUrl
     *            servers HTTP URL to connect to
     * @throws Exception
     *             in case of error
     */
    public HttpSession(final URL remoteUrl) throws Exception {
        this.remoteUrl = remoteUrl;
    }

    /**
     * send a CMP message to the connected server and return response
     *
     * @param message
     *            the message to send
     *
     * @return responded message or <code>null</code> if something went wrong
     *
     */
    @Override
    public InputStream apply(final byte[] message) {
        try {
            final HttpURLConnection httpConnection =
                    (HttpURLConnection) remoteUrl.openConnection();
            return sendReceivePkiMessageIntern(message, httpConnection);
        } catch (final BaseCmpException ex) {
            throw ex;
        } catch (final Exception e) {
            throw new CmpProcessingException(
                    "client connection to " + remoteUrl, e);
        }
    }

}
