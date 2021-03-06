/*-
 * #%L
 * com.paremus.cert
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
package com.paremus.cert.api;

/**
 * This DTO encapsulates the information about a key pair 
 */
public class KeyPairInfo {

    /**
     * The name of the key pair
     */
    public String name;
    
    /**
     * The algorithm used by this key pair
     */
    public String algorithm;
    
    /**
     * The public key for this key pair
     */
    public byte[] publicKey;
    
}
