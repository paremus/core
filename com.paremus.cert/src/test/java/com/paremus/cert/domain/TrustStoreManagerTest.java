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
import static java.util.Arrays.asList;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.paremus.cert.api.CertificateInfo;
import com.paremus.cert.domain.CertificateGenerator;
import com.paremus.cert.domain.KeyPairManager;
import com.paremus.cert.domain.TrustStoreManager;
import com.paremus.cert.domain.KeyPairManager.Algorithm;

public class TrustStoreManagerTest {

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
    public void testCreateTrustStore() throws IOException {

        TrustStoreManager tsm = new TrustStoreManager(tempFolder.newFolder().toPath(), provider, secureRandom);

        KeyPair keyPair = keyPairManager.newKeyPair("TEST", Algorithm.EC, 384);

        KeyPair keyPair2 = keyPairManager.newKeyPair("TEST2", Algorithm.RSA, 2048);

        Certificate certificate = certificateGenerator.generateRootCertificate(keyPair, "TEST_CERT", ofHours(1));
        Certificate certificate2 = certificateGenerator.generateRootCertificate(keyPair2, "TEST_CERT2", ofHours(1));

        assertTrue(tsm.listTrustStores().isEmpty());

        tsm.createTrustStore("TEST_STORE", asList(certificate, certificate2));

        Map<String, Collection<CertificateInfo>> stores = tsm.listTrustStores();
        assertEquals(1, stores.size());

        Collection<CertificateInfo> info = stores.get("TEST_STORE");
        assertNotNull(info);
        assertEquals(2, info.size());

        List<CertificateInfo> list = new ArrayList<>(info);

        Collections.sort(list, (a, b) -> a.alias.compareTo(b.alias));

        assertEquals("TEST_CERT".toLowerCase(), list.get(0).alias);
        assertEquals("TEST_CERT", list.get(0).subject);
        assertEquals(keyPair.getPublic().getAlgorithm(), list.get(0).algorithm);
        assertArrayEquals(keyPair.getPublic().getEncoded(), list.get(0).publicKey);

        assertEquals("TEST_CERT2".toLowerCase(), list.get(1).alias);
        assertEquals("TEST_CERT2", list.get(1).subject);
        assertEquals(keyPair2.getPublic().getAlgorithm(), list.get(1).algorithm);
        assertArrayEquals(keyPair2.getPublic().getEncoded(), list.get(1).publicKey);
    }

    @Test
    public void testAddAndRemoveTrustStoreCerts() throws IOException {

        TrustStoreManager tsm = new TrustStoreManager(tempFolder.newFolder().toPath(), provider, secureRandom);

        KeyPair keyPair = keyPairManager.newKeyPair("TEST", Algorithm.EC, 384);

        KeyPair keyPair2 = keyPairManager.newKeyPair("TEST2", Algorithm.RSA, 2048);

        Certificate certificate = certificateGenerator.generateRootCertificate(keyPair, "TEST_CERT", ofHours(1));
        Certificate certificate2 = certificateGenerator.generateRootCertificate(keyPair2, "TEST_CERT2", ofHours(1));

        assertTrue(tsm.listTrustStores().isEmpty());

        tsm.createTrustStore("TEST_STORE", asList(certificate));

        Map<String, Collection<CertificateInfo>> stores = tsm.listTrustStores();
        assertEquals(1, stores.size());

        Collection<CertificateInfo> info = stores.get("TEST_STORE");
        assertNotNull(info);
        assertEquals(1, info.size());

        List<CertificateInfo> list = new ArrayList<>(info);

        assertEquals("TEST_CERT".toLowerCase(), list.get(0).alias);
        assertEquals("TEST_CERT", list.get(0).subject);
        assertEquals(keyPair.getPublic().getAlgorithm(), list.get(0).algorithm);
        assertArrayEquals(keyPair.getPublic().getEncoded(), list.get(0).publicKey);

        // Add a new cert
        
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(certificate2);
            pemWriter.flush();
            pemWriter.close();
        }

        tsm.addTrustedCertificates("TEST_STORE", writer.toString());

        stores = tsm.listTrustStores();
        assertEquals(1, stores.size());

        info = stores.get("TEST_STORE");
        assertNotNull(info);
        assertEquals(2, info.size());

        list = new ArrayList<>(info);

        Collections.sort(list, (a, b) -> a.alias.compareTo(b.alias));

        assertEquals("TEST_CERT".toLowerCase(), list.get(0).alias);
        assertEquals("TEST_CERT", list.get(0).subject);
        assertEquals(keyPair.getPublic().getAlgorithm(), list.get(0).algorithm);
        assertArrayEquals(keyPair.getPublic().getEncoded(), list.get(0).publicKey);

        assertEquals("TEST_CERT2".toLowerCase(), list.get(1).alias);
        assertEquals("TEST_CERT2", list.get(1).subject);
        assertEquals(keyPair2.getPublic().getAlgorithm(), list.get(1).algorithm);
        assertArrayEquals(keyPair2.getPublic().getEncoded(), list.get(1).publicKey);
        
        
        // Remove the original cert
        
        tsm.removeTrustedCertificate("TEST_STORE", "TEST_CERT");
        
        stores = tsm.listTrustStores();
        assertEquals(1, stores.size());

        info = stores.get("TEST_STORE");
        assertNotNull(info);
        assertEquals(1, info.size());

        list = new ArrayList<>(info);

        assertEquals("TEST_CERT2".toLowerCase(), list.get(0).alias);
        assertEquals("TEST_CERT2", list.get(0).subject);
        assertEquals(keyPair2.getPublic().getAlgorithm(), list.get(0).algorithm);
        assertArrayEquals(keyPair2.getPublic().getEncoded(), list.get(0).publicKey);
    }
}
