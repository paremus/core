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
import static org.junit.Assert.assertEquals;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;

import javax.ws.rs.Consumes;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response.Status;

import org.apache.cxf.jaxrs.servlet.CXFNonSpringJaxrsServlet;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.paremus.cert.api.CertificateInfo;
import com.paremus.cert.domain.AbstractStoreManager.StoreInfo;

public class CertificateSigningRequestSubmitterTest {
    
    
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    private final BouncyCastleProvider provider = new BouncyCastleProvider();
    private final SecureRandom secureRandom = new SecureRandom();
    
    private KeyPairManager keyPairManager;
    private CertificateGenerator certificateGenerator;
    private KeyStoreManager keyStoreManager;
    private TrustStoreManager trustStoreManager;

    private Server server;

    private int localPort;
    

    @Before
    public void start() throws Exception {
        keyPairManager = new KeyPairManager(tempFolder.newFolder().toPath(), provider, secureRandom);
        certificateGenerator = new CertificateGenerator(provider, secureRandom);
        keyStoreManager = new KeyStoreManager(tempFolder.newFolder().toPath(), provider, secureRandom);
        trustStoreManager = new TrustStoreManager(tempFolder.newFolder().toPath(), provider, secureRandom);
        
        KeyPair keyPair = keyPairManager.newKeyPair("test");
        
        Certificate certificate = certificateGenerator.generateRootCertificate(keyPair, "localhost", ofHours(1));
        
        keyStoreManager.createKeyStore("test_store", keyPair, new Certificate[] {certificate});
        
        StoreInfo storeInfo = keyStoreManager.getStoreFor("test_store", "test_pid");
        
        server = new Server();

        HttpConfiguration https = new HttpConfiguration();
        https.addCustomizer(new SecureRequestCustomizer());
        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setKeyStorePath(storeInfo.location);
        sslContextFactory.setKeyStorePassword(storeInfo.password);
        sslContextFactory.setKeyManagerPassword(storeInfo.password);
        ServerConnector sslConnector = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory, "http/1.1"), new HttpConnectionFactory(https));
        sslConnector.setPort(0);
        
        server.addConnector(sslConnector);
        
        CXFNonSpringJaxrsServlet servlet = new CXFNonSpringJaxrsServlet(new SigningResource());
        
        ServletHandler handler = new ServletHandler();
        handler.addServletWithMapping(new ServletHolder(servlet), "/*");
        server.setHandler(handler);
        
        server.start();
        
        localPort = sslConnector.getLocalPort();
    }

    @After
    public void stop() throws Exception {
        server.stop();
        server.destroy();
    }
    
    public class SigningResource {
        
        @Path("sign")
        @POST
        @Consumes("text/plain")
        @Produces("text/plain")
        public String sign(@HeaderParam("Paremus-One-Time-Token")String token, String body) {
            
            if(!"SECRET".equals(token)) {
                throw new WebApplicationException(Status.FORBIDDEN);
            }
            
            return certificateGenerator.signCertificate(keyStoreManager.getSignerInfo("test_store"), body);
        }
    }
    
    @Test
    public void testSigning() throws MalformedURLException {
        CertificateSigningRequestSubmitter submitter = new CertificateSigningRequestSubmitter(trustStoreManager, secureRandom);
        
        URL url = new URL("https", "localhost", localPort, "/sign");
        
        KeyPair keyPair = keyPairManager.newKeyPair("to_sign");
        String signingRequest = certificateGenerator.generateCertificateSigningRequest(keyPair, "client_cert");
        
        String signedCertAndChain = submitter.issueCertificateSigningRequest(url, signingRequest, 
                "SECRET", keyStoreManager.getCertificateChain("test_store"));
        
        keyStoreManager.createKeyStore("signed", keyPair, signedCertAndChain);
        
        CertificateInfo certificateInfo = keyStoreManager.getCertificateInfo("signed");
        
        assertEquals("client_cert", certificateInfo.subject);
    }

}
