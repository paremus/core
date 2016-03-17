/*-
 * #%L
 * com.paremus.cert.test
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
package com.paremus.cert.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.osgi.namespace.service.ServiceNamespace.SERVICE_NAMESPACE;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.KeyStore;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.osgi.annotation.bundle.Requirement;
import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.service.cm.ManagedService;
import org.osgi.util.tracker.ServiceTracker;

import com.paremus.cert.api.CertificateInfo;
import com.paremus.cert.api.SecurityDomainConfiguration;
import com.paremus.cert.api.SecurityDomainManager;

@RunWith(JUnit4.class)
@Requirement(namespace=SERVICE_NAMESPACE, filter="(objectClass=com.paremus.cert.api.SecurityDomainManager)")
public class ParemusCertTest {

	private final BundleContext context = FrameworkUtil.getBundle(this.getClass()).getBundleContext();
	
	private ServiceTracker<ConfigurationAdmin, ConfigurationAdmin> cfgTracker;
	
	private ConfigurationAdmin cm;
	
	private ServiceTracker<SecurityDomainManager, SecurityDomainManager> tracker;
	
	
	@Before
	public void setUp() throws Exception {
		
		cfgTracker = new ServiceTracker<>(context, ConfigurationAdmin.class, null);
		cfgTracker.open();
		
		cm = cfgTracker.waitForService(5000);
		assertNotNull(cm);
		
		configureSecurityDomainManager();
		
		tracker = new ServiceTracker<>(context, SecurityDomainManager.class, null);
		tracker.open();
		
		assertNotNull(tracker.waitForService(10000));
	}
	
	private void configureSecurityDomainManager() throws Exception {
		Dictionary<String, Object> props = new Hashtable<>();
		props.put("storage.folder", "target/certs");
		
		cm.getConfiguration("com.paremus.cert.security.domain", "?").update(props);
		
		Thread.sleep(500);
	}

	@After
	public void tearDown() throws Exception {
	    
	    cm.getConfiguration("com.paremus.cert.security.domain", "?").delete();
	    
	    Files.walkFileTree(Paths.get("target", "certs"), new SimpleFileVisitor<Path>() {

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
            }
	        
	    });
	    
		tracker.close();
	}
	
	@Test
	public void testCreatingAndSigningCertificates() {
		
	    SecurityDomainManager service = tracker.getService();
	    
	    service.createCertificateAuthority("ca");
		
	    service.createKeyPair("TEST");
	    String csr = service.createNewCertificateSigningRequest("my_cert", "TEST");
	    
	    String cert = service.signCertificateSigningRequest("ca", csr);
	    
	    service.createKeyStore("signed", "TEST", cert);
	    
	    CertificateInfo ci = service.getCertificateInfo("signed");
	    
	    assertEquals("signed", ci.alias);
	    assertEquals("my_cert", ci.subject);
	}
	
	@Test
	public void testConfigurationAdminPlugin() throws Exception {
	    testCreatingAndSigningCertificates();
	    
	    SecurityDomainManager service = tracker.getService();
	    
	    service.createTrustStore("trust", service.getCertificateChain("ca"));
	    
	    AtomicReference<Dictionary<String, ?>> ref = new AtomicReference<>(null);
	    Semaphore s = new Semaphore(0);
	    
	    Dictionary<String, Object> props = new Hashtable<>();
	    props.put("service.pid", "com.paremus.cert.test");
	    
	    context.registerService(ManagedService.class, d -> { ref.set(d); s.release();}, props);
	    
	    assertTrue(s.tryAcquire(1, TimeUnit.SECONDS));
	    assertNull(ref.get());
	    
	    props = new Hashtable<>();
	    props.put(SecurityDomainConfiguration.KEYSTORE_LOCATION, "key.loc");
	    props.put(SecurityDomainConfiguration.KEYSTORE_TYPE, "key.type");
	    props.put(SecurityDomainConfiguration.KEYSTORE_PW, "key.pw");
	    props.put(SecurityDomainConfiguration.KEYSTORE_ALIAS, "key.alias");
	    props.put(SecurityDomainConfiguration.TRUSTSTORE_LOCATION, "trust.loc");
	    props.put(SecurityDomainConfiguration.TRUSTSTORE_TYPE, "trust.type");
	    props.put(SecurityDomainConfiguration.TRUSTSTORE_PW, "trust.pw");
	    props.put("key.loc", "${signed}");
	    props.put("key.type", "${signed}");
	    props.put("key.pw", "${signed}");
	    props.put("key.alias", "${signed}");
	    props.put("trust.loc", "${trust}");
	    props.put("trust.type", "${trust}");
	    props.put("trust.pw", "${trust}");
	    
	    Configuration cfg = cm.getConfiguration("com.paremus.cert.test");
        
	    try {
	        cfg.update(props);
	        assertTrue(s.tryAcquire(1, TimeUnit.SECONDS));
	        Dictionary<String, ?> config = ref.get();
	        assertNotNull(config);
	        
	        Path path = Paths.get((String) config.get("key.loc"));
	        assertTrue(Files.exists(path));
	        
	        KeyStore ks = KeyStore.getInstance((String) config.get("key.type"));
	        try (InputStream stream = Files.newInputStream(path)) {
	            ks.load(stream, ((String) config.get("key.pw")).toCharArray());
	            
	            assertNotNull(ks.getCertificateChain((String) config.get("key.alias")));
	        }
	        
	        path = Paths.get((String) config.get("trust.loc"));
	        assertTrue(Files.exists(path));
	        
	        ks = KeyStore.getInstance((String) config.get("trust.type"));
	        try (InputStream stream = Files.newInputStream(path)) {
	            ks.load(stream, ((String) config.get("trust.pw")).toCharArray());
	        }
	    } finally {
	        cfg.delete();
	    }
	    
	}
}
