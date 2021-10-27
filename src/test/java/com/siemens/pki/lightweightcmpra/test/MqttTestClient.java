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

import java.util.Base64;
import java.util.Random;
import java.util.function.Function;

import javax.jms.Connection;
import javax.jms.DeliveryMode;
import javax.jms.Destination;
import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageListener;
import javax.jms.MessageProducer;
import javax.jms.Session;
import javax.jms.TextMessage;

import org.apache.activemq.ActiveMQConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MqttTestClient
        implements MessageListener, Function<byte[], byte[]> {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(MqttTestClient.class);
    private MessageProducer producer;
    private Destination tempDest;
    private Session session;

    private volatile byte[] lastReceivedMessage;

    public MqttTestClient(final String config) {
        final String[] parsedConfig = config.split(",");
        final String messageBrokerUrl = parsedConfig[0];
        final String clientQueueName = parsedConfig[1];
        final ActiveMQConnectionFactory connectionFactory =
                new ActiveMQConnectionFactory(messageBrokerUrl);
        Connection connection;
        try {
            connection = connectionFactory.createConnection();
            connection.start();
            session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            final Destination adminQueue = session.createQueue(clientQueueName);

            //Setup a message producer to send message to the queue the server is consuming from
            this.producer = session.createProducer(adminQueue);
            this.producer.setDeliveryMode(DeliveryMode.NON_PERSISTENT);

            tempDest = session.createTemporaryQueue();
            final MessageConsumer responseConsumer =
                    session.createConsumer(tempDest);

            //This class will handle the messages to the temp queue as well
            responseConsumer.setMessageListener(this);
        } catch (final JMSException e) {
            LOGGER.error("error creating MQTT client", e);
        }
    }

    @Override
    public synchronized byte[] apply(final byte[] request) {
        lastReceivedMessage = null;
        try {
            //Now create the actual message you want to send
            final TextMessage txtMessage = session.createTextMessage();
            txtMessage.setText(Base64.getEncoder().encodeToString(request));
            //Set the reply to field to the temp queue you created above, this is the queue the server
            //will respond to
            txtMessage.setJMSReplyTo(tempDest);

            //Set a correlation ID so when you get a response you know which sent message the response is for
            //If there is never more than one outstanding message to the server then the
            //same correlation ID can be used for all the messages...if there is more than one outstanding
            //message to the server you would presumably want to associate the correlation ID with this
            //message somehow...a Map works good
            final String correlationId = this.createRandomString();
            txtMessage.setJMSCorrelationID(correlationId);
            this.producer.send(txtMessage);

            for (int i = 0; i < 20; i++) {

                wait(1000);
                if (lastReceivedMessage != null) {
                    return lastReceivedMessage;
                }
            }
        } catch (final Exception e) {
            LOGGER.error("error sending message", e);
        }
        return null;
    }

    private String createRandomString() {
        final Random random = new Random(System.currentTimeMillis());
        final long randomLong = random.nextLong();
        return Long.toHexString(randomLong);
    }

    @Override
    public void onMessage(final Message message) {
        try {
            if (message instanceof TextMessage) {
                final TextMessage textMessage = (TextMessage) message;
                lastReceivedMessage =
                        Base64.getDecoder().decode(textMessage.getText());
                synchronized (this) {
                    notifyAll();
                }
            }
        } catch (final JMSException e) {
            LOGGER.error("error processing MQTT response", e);
        }
    }

}