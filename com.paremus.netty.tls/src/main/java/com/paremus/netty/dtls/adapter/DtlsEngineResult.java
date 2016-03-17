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

public interface DtlsEngineResult {

    OperationResult getOperationResult();
    
    OperationRequired getOperationRequired();
    
    public enum OperationResult {
        INSUFFICIENT_INPUT,
        TOO_MUCH_OUTPUT,
        OK,
        ENGINE_CLOSED;
    }
    
    public enum OperationRequired {
        NONE,
        RUN_TASK,
        DATA_TO_SEND,
        AWAITING_DATA,
        PENDING_RECEIVED_DATA;
    }
    
}
