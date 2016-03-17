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

import com.paremus.netty.tls.DTLSHandler;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandler;
import io.netty.channel.ChannelOutboundHandler;
import io.netty.util.concurrent.Future;

public interface InternalDTLSHandler extends DTLSHandler, ChannelInboundHandler, ChannelOutboundHandler {
    
    public Future<Void> close(ChannelHandlerContext ctx, boolean sendData);
    
}
