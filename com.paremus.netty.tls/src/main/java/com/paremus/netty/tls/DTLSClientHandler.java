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
import io.netty.util.concurrent.Future;

/**
 * This interface represents a DTLS Handler which is capable of being
 * a client or server, and that can maintain a separate DTLS session
 * per address that it communicates with.
 */
public interface DTLSClientHandler extends DTLSHandler {

    /**
     * Begin a handshake with the supplied remote address.
     * 
     * Note that a handshake will be implicitly started if the channel
     * is connected to a remote peer.
     * 
     * @param socketAddress The address to handshake with
     * @return Either:
     * <ul>
     *   <li>A Future representing the state of the initial handshake</li>
     *   <li>A failed Future if the handshake has already started with a different address</li>
     * </ul>
     */
    public Future<Channel> handshake(SocketAddress socketAddress);
}
