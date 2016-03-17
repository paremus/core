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

import static java.time.Duration.ofHours;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.paremus.cert.api.CertificateInfo;
import com.paremus.cert.domain.CertificateGenerator;
import com.paremus.cert.domain.KeyPairManager;
import com.paremus.cert.domain.KeyStoreManager;

public class KeyStoreManagerTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    private final BouncyCastleProvider provider = new BouncyCastleProvider();
    private final SecureRandom secureRandom = new SecureRandom();
    
    private KeyPairManager keyPairManager;
    private CertificateGenerator certificateGenerator;
    
    
    @Before
    public void setUp() throws IOException {
        keyPairManager = new KeyPairManager(tempFolder.newFolder().toPath(), provider, secureRandom);
        certificateGenerator = new CertificateGenerator(provider, secureRandom);
    }
    
    @Test
    public void testCreateKeyStore() throws IOException {
        
        KeyStoreManager ksm = new KeyStoreManager(tempFolder.newFolder().toPath(), provider, secureRandom);
        
        KeyPair keyPair = keyPairManager.newKeyPair("TEST");
        
        Certificate certificate = certificateGenerator.generateRootCertificate(keyPair, "TEST_CERT", ofHours(1));
        
        assertTrue(ksm.listKeyStores().isEmpty());
        
        ksm.createKeyStore("TEST_STORE", keyPair, new Certificate[] {certificate});
        
        Map<String, CertificateInfo> stores = ksm.listKeyStores();
        assertEquals(1, stores.size());

        CertificateInfo info = stores.get("TEST_STORE");
        assertNotNull(info);

        assertEquals("test_store", info.alias);
        assertEquals("TEST_CERT", info.subject);
        assertEquals(keyPair.getPublic().getAlgorithm(), info.algorithm);
        assertArrayEquals(keyPair.getPublic().getEncoded(), info.publicKey);
    }
}
