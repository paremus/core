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

import java.net.InetSocketAddress;
import java.util.List;

import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.HandshakeType;

import com.paremus.netty.dtls.adapter.DtlsEngine;
import com.paremus.netty.tls.DTLSHandler;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.DatagramPacket;

public class ParemusServerDTLSHandler extends ParemusBaseDTLSHandler implements DTLSHandler {

    public ParemusServerDTLSHandler(DtlsEngine engine) {
        super(engine);
    }
    
    ParemusServerDTLSHandler(DtlsEngine engine, ChannelHandlerContext ctx, InetSocketAddress remotePeer) {
        super(engine, ctx, remotePeer);
    }
    
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        
        if(remotePeer == null) {
            DatagramPacket dp = (DatagramPacket) msg;
            remotePeer = dp.sender();
        }
        
        super.channelRead(ctx, msg);
    }

    @Override
    protected boolean shouldRegisterForRetransmission(ByteBuf msg) {
        if(!isHandshakeMessage(msg)) {
            return false;
        }
        
        // Note that we do *not* retransmit server hello
        switch(getHandshakeMessageType(msg)) {
            case HandshakeType.certificate:
            case HandshakeType.certificate_request:
            case HandshakeType.server_key_exchange:
            case HandshakeType.certificate_verify:
            case HandshakeType.server_hello_done:
            case HandshakeType.finished:
                return true;
        }
        return false;
    }

    @Override
    protected void clearRetransmitBuffer(ByteBuf received, List<ByteBuf> currentlyRetransmitting) {
        int index = received.readerIndex();
        int epoch = received.getUnsignedShort(index + 3);
        if(isHandshakeMessage(received)) {
            switch(getHandshakeMessageType(received)) {
                case HandshakeType.certificate:
                case HandshakeType.certificate_request:
                case HandshakeType.certificate_verify:
                case HandshakeType.client_key_exchange:
                case HandshakeType.finished:
                    removeMessages(currentlyRetransmitting, epoch);
                    break;
            }
        } else if(received.getUnsignedByte(index) == 25) {
             // This is an ACK
             // TODO log that we don't handle ACKS properly at the moment
            removeMessages(currentlyRetransmitting, epoch - 1);
        } else if(received.getUnsignedByte(index) == ContentType.application_data ||
                (received.getUnsignedByte(index) & 0b00100000) != 0) {
            removeMessages(currentlyRetransmitting, epoch);
        }
        
    }
}
