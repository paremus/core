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
package com.paremus.cert.domain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.paremus.cert.api.KeyPairInfo;
import com.paremus.cert.domain.KeyPairManager;

public class KeyPairManagerTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    @Test
    public void testCreateKey() throws IOException {
        
        KeyPairManager manager = new KeyPairManager(tempFolder.newFolder().toPath(), new BouncyCastleProvider(), new SecureRandom());

        assertNotNull(manager.newKeyPair("test"));
        
        KeyPairInfo info = manager.getKeyPairInfo("test");
        
        assertEquals("test", info.name);
        assertEquals("ECDSA", info.algorithm);
        assertNotNull(info.publicKey);
    }

}
