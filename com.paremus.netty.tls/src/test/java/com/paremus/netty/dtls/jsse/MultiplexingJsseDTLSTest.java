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

import java.security.SecureRandom;
import java.util.function.Supplier;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import com.paremus.netty.dtls.adapter.DtlsEngine;
import com.paremus.netty.dtls.adapter.JdkDtlsEngineAdapter;
import com.paremus.netty.test.AbstractMultiplexingDTLSTest;

import io.netty.channel.ChannelHandler;

public class MultiplexingJsseDTLSTest extends AbstractMultiplexingDTLSTest {

    @Override
    protected ChannelHandler getMultiplexingHandler(KeyManagerFactory kmf, TrustManagerFactory tmf,
            SSLParameters parameters) throws Exception {
        
        SSLContext instance = SSLContext.getInstance("DTLSv1.2");
        
        instance.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        
        Supplier<DtlsEngine> sslEngineSupplier = () -> {
                SSLEngine engine = instance.createSSLEngine();
                engine.setSSLParameters(parameters);
                return new JdkDtlsEngineAdapter(engine);
            };
        return new ParemusDTLSHandler(sslEngineSupplier);
    }
}
