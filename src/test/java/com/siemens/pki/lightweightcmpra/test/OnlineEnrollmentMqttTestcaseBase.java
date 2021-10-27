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

import org.apache.activemq.broker.BrokerService;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

public class OnlineEnrollmentMqttTestcaseBase
        extends OnlineEnrollmentTestcaseBase {

    private static final String URL = "tcp://localhost:61616";

    private static BrokerService broker;

    @BeforeClass
    public static void onlyOnce() throws Exception {
        // Start message broker for testing (the embedded message broker was
        // removed as it conflicts with the connection to the ActiveMQ server)
        broker = new BrokerService();
        broker.setPersistent(false);
        broker.setUseJmx(false);
        broker.addConnector(URL);
        broker.start();
    }

    @AfterClass
    public static void tearDown() throws Exception {
        // Stop the message broker
        if (broker != null) {
            broker.stop();
        }
    }

    @Before
    public void setUp() throws Exception {
        initTestbed("OnlineEnrollmentTestConfigWithMqtt.xml",
                URL + ",client.messages");
    }
}
