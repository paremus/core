/*-
 * #%L
 * com.paremus.netty.tls
 * %%
 * Copyright (C) 2018 - 2019 Paremus Ltd
 * %%
 * Licensed under the Fair Source License, Version 0.9 (the "License");
 * 
 * See the NOTICE.txt file distributed with this work for additional 
 * information regarding copyright ownership. You may not use this file 
 * except in compliance with the License. For usage restrictions see the 
 * LICENSE.txt file distributed with this work
 * #L%
 */
package com.paremus.netty.dtls.jsse;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.junit.Test;

import com.paremus.netty.dtls.adapter.JdkDtlsEngineAdapter;
import com.paremus.netty.test.AbstractDTLSTest;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.DatagramPacket;
import io.netty.util.concurrent.Future;

public class JsseDTLSTest extends AbstractDTLSTest {

    @Test
    public void testECCertificate() throws Exception {
        setupEC();
        sayHello();
    }

    @Test
    public void testRSACertificate() throws Exception {
        setupRSA();
        sayHello();
    }

    private void sayHello() throws InterruptedException, Exception {
       
            udpBootstrap.handler( new ChannelInitializer<Channel>() {
                @Override
                protected void initChannel(Channel ch) throws Exception {
                    SSLContext instance = SSLContext.getInstance("DTLSv1.2");
                    instance.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
                    
                    SSLEngine engine = instance.createSSLEngine();
                    engine.setUseClientMode(true);
                    ch.pipeline().addFirst(new ParemusClientDTLSHandler(new JdkDtlsEngineAdapter(engine)));
                }
            });
        
        
        Channel alice = udpBootstrap.bind(InetAddress.getLoopbackAddress(), 0).sync().channel();
        
        udpBootstrap.handler( new ChannelInitializer<Channel>() {
            @Override
            protected void initChannel(Channel ch) throws Exception {
                SSLContext instance = SSLContext.getInstance("DTLSv1.2");
                instance.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
                
                SSLEngine engine = instance.createSSLEngine();
                engine.setUseClientMode(false);
                ch.pipeline().addFirst(new ParemusServerDTLSHandler(new JdkDtlsEngineAdapter(engine)));
            }
        });
        
        
        Channel bob = udpBootstrap.bind(InetAddress.getLoopbackAddress(), 0).sync().channel();
        
        BlockingQueue<String> aliceMessages = new LinkedBlockingQueue<>();
        BlockingQueue<String> bobMessages = new LinkedBlockingQueue<>();
        
        alice.pipeline().addLast(new CapturingHandler(aliceMessages));
        bob.pipeline().addLast(new CapturingHandler(bobMessages));
        
        
        alice.connect(bob.localAddress()).sync();
        
        Future<Channel> handshakeFuture = alice.pipeline().get(ParemusClientDTLSHandler.class).handshakeFuture();
        assertTrue(handshakeFuture.await(1000));
        handshakeFuture.get(0, TimeUnit.MILLISECONDS);

        handshakeFuture = bob.pipeline().get(ParemusServerDTLSHandler.class).handshakeFuture();
        assertTrue(handshakeFuture.await(1000));
        handshakeFuture.get(0, TimeUnit.MILLISECONDS);
        
     
        ByteBuf buffer = Unpooled.buffer();
        buffer.writeCharSequence("Hello from Alice", UTF_8);
        assertTrue(alice.writeAndFlush(new DatagramPacket(buffer, (InetSocketAddress) bob.localAddress())).await(2000)); 
        
        buffer = Unpooled.buffer();
        buffer.writeCharSequence("Hello from Bob", UTF_8);
        assertTrue(bob.writeAndFlush(new DatagramPacket(buffer, (InetSocketAddress) alice.localAddress())).await(2000)); 
        
        assertEquals("Hello from Alice", bobMessages.poll(100, TimeUnit.MILLISECONDS));
        assertEquals("Hello from Bob", aliceMessages.poll(100, TimeUnit.MILLISECONDS));
        
        assertTrue(alice.close().await(1000));
        assertTrue(bob.close().await(1000));
    }
    
}
