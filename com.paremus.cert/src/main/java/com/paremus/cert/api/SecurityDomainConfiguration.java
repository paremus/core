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
 * This interface provides constants used to interact with the Security Domain Manager
 * managed keystores and truststores.
 * 
 * Key stores and trust stores are accessed by name using property values of the form 
 * <code>${name}</code>. These values will be replaced by a file path, or a password,
 * as appropriate.
 * 
 * To tell the configuration plugin which property keys require replacement the configuration
 * must contain one or more of the following properties:
 */
public interface SecurityDomainConfiguration {
    
    /**
     * This key maps to one or more keys in the configuration that should be transformed
     * into key store locations
     */
    public static final String KEYSTORE_LOCATION = ".com.paremus.cert.keystore.location";
    /**
     * This key maps to one or more keys in the configuration that should be transformed
     * into the type of the key store
     */
    public static final String KEYSTORE_TYPE = ".com.paremus.cert.keystore.type";
    /**
     * This key maps to one or more keys in the configuration that should be transformed
     * into key store passwords
     */
    public static final String KEYSTORE_PW = ".com.paremus.cert.keystore.pw";
    /**
     * This key maps to one or more keys in the configuration that should be transformed
     * into the alias of the private key stored in the key store.
     */
    public static final String KEYSTORE_ALIAS = ".com.paremus.cert.keystore.alias";
    /**
     * This key maps to one or more keys in the configuration that should be transformed
     * into trust store locations
     */
    public static final String TRUSTSTORE_LOCATION = ".com.paremus.cert.truststore.location";
    /**
     * This key maps to one or more keys in the configuration that should be transformed
     * into the type of the trust store
     */
    public static final String TRUSTSTORE_TYPE = ".com.paremus.cert.truststore.type";
    /**
     * This key maps to one or more keys in the configuration that should be transformed
     * into trust store passwords
     */
    public static final String TRUSTSTORE_PW = ".com.paremus.cert.truststore.pw";

}
