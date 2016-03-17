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
package com.paremus.netty.tls;

import java.net.SocketAddress;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.util.concurrent.Future;

/**
 * This interface represents a DTLS Handler which is capable of being
 * a client or server, and that can maintain a separate DTLS session
 * per address that it communicates with.
 */
public interface DTLSHandler extends ChannelHandler {

    /**
     * Get the handshake future for this handler
     * 
     * @return a future representing the state of the current handshake,
     * or null if no handshake or connection is ongoing
     */
    public Future<Channel> handshakeFuture();

    /**
     * Get the close future for this handler
     * 
     * @return a future representing the state of the current connection,
     * or null if no connection is ongoing
     */
    public Future<Void> closeFuture();
    
    /**
     * Get the address of the remote peer which this Handler is for
     * 
     * @return the remote address, or null if this hander is not yet connected
     */
    public SocketAddress getRemotePeerAddress();
}
