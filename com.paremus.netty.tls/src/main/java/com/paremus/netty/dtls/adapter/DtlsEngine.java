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
package com.paremus.netty.dtls.adapter;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import com.paremus.netty.dtls.adapter.DtlsEngineResult.OperationRequired;

import io.netty.buffer.ByteBuf;

public interface DtlsEngine {

    DtlsEngineResult generateDataToSend(ByteBuf input, ByteBuf output) throws SSLException;

    DtlsEngineResult handleReceivedData(ByteBuf input, ByteBuf output) throws SSLException;
    
    Runnable getTaskToRun();
    
    void closeOutbound();
    
    SSLParameters getSSLparameters();
    
    int getMaxSendOutputBufferSize();
    
    int getMaxReceiveOutputBufferSize();
    
    void setClient(boolean isClient);

    boolean isClient();
    
    OperationRequired getOperationRequired();
    
    void startHandshaking() throws SSLException;
}
