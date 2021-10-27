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

package com.siemens.pki.lightweightcmpra.server;

import java.io.IOException;
import java.util.Base64;
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
import javax.xml.bind.JAXB;

import org.apache.activemq.ActiveMQConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.siemens.pki.lightweightcmpra.config.xmlparser.MQTTSERVERCONFIGURATION;

public class MqttServer implements MessageListener {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(MqttServer.class);

    private final Session session;

    private final boolean transacted = false;

    private final MessageProducer replyProducer;

    private final Function<byte[], byte[]> messageHandler;

    /**
     *
     * @param config
     *            {@link JAXB} configuration subtree from XML configuration file
     * @param messageHandler
     *            related downstream interface handler
     * @throws IOException
     *             in case of error
     */
    public MqttServer(final MQTTSERVERCONFIGURATION config,
            final Function<byte[], byte[]> messageHandler) throws Exception {
        this.messageHandler = messageHandler;

        LOGGER.debug("Try to connect to: " + config.getMessageBrokerUrl());

        // This message broker is embedded
        final ActiveMQConnectionFactory connectionFactory =
                new ActiveMQConnectionFactory(config.getUser(),
                        config.getPassword(), config.getMessageBrokerUrl());

        final Connection connection = connectionFactory.createConnection();
        connection.start();
        this.session = connection.createSession(this.transacted,
                Session.AUTO_ACKNOWLEDGE);
        final Destination adminQueue =
                this.session.createQueue(config.getMessageQueueName());

        //Setup a message producer to respond to messages from clients, we will get the destination
        //to send to from the JMSReplyTo header field from a Message
        this.replyProducer = this.session.createProducer(null);
        this.replyProducer.setDeliveryMode(DeliveryMode.NON_PERSISTENT);

        //Set up a consumer to consume messages off of the admin queue
        final MessageConsumer consumer =
                this.session.createConsumer(adminQueue);
        consumer.setMessageListener(this);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void onMessage(final Message message) {
        try {
            final TextMessage response = this.session.createTextMessage();
            if (message instanceof TextMessage) {
                final TextMessage txtMsg = (TextMessage) message;
                final byte[] cmpRequestMessage =
                        Base64.getDecoder().decode(txtMsg.getText());
                final byte[] cmpResponseMessage =
                        messageHandler.apply(cmpRequestMessage);
                response.setText(
                        Base64.getEncoder().encodeToString(cmpResponseMessage));
            }

            //Set the correlation ID from the received message to be the correlation id of the response message
            //this lets the client identify which message this is a response to if it has more than
            //one outstanding message to the server
            response.setJMSCorrelationID(message.getJMSCorrelationID());

            //Send the response to the Destination specified by the JMSReplyTo field of the received message,
            //this is presumably a temporary queue created by the client
            this.replyProducer.send(message.getJMSReplyTo(), response);
        } catch (final JMSException e) {
            LOGGER.error("error processing MQTT message", e);
        }
    }
}
