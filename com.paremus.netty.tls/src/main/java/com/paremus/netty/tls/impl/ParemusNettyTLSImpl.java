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
package com.paremus.netty.tls.impl;

import static com.paremus.license.License.requireFeature;
import static org.osgi.service.component.annotations.ConfigurationPolicy.REQUIRE;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;

import com.paremus.netty.dtls.adapter.JdkDtlsEngineAdapter;
import com.paremus.netty.tls.DTLSClientHandler;
import com.paremus.netty.tls.DTLSHandler;
import com.paremus.netty.tls.MultiplexingDTLSHandler;
import com.paremus.netty.tls.ParemusNettyTLS;

import io.netty.handler.ssl.SslHandler;

@Component(configurationPid="com.paremus.netty.tls", configurationPolicy=REQUIRE)
public class ParemusNettyTLSImpl implements ParemusNettyTLS {

    private final boolean insecure;
    
    private final SSLContext tlsSslContext;
    
    private final SSLContext dtlsSslContext;
    
    private final KeyManagerFactory kmf;
    
    private final TrustManagerFactory tmf;
    
    private final SSLParameters tlsParameters;

    private final SSLParameters dtlsParameters;
    
    @Activate
    public ParemusNettyTLSImpl(Config config) throws Exception {
        
        requireFeature("core", null);
        
        insecure = config.insecure();
        
        if(insecure) {
            tlsSslContext = null;
            dtlsSslContext = null;
            kmf = null;
            tmf = null;
            tlsParameters =  null;
            dtlsParameters =  null;
            return;
        }
        
        String tlsProtocol = config.tls_protocol();
        String dtlsProtocol = config.dtls_protocol();
        
        Provider jceProvider;
        Provider jsseProvider;
        
        switch(config.provider()) {
            case BOUNCYCASTLE:
                jceProvider = new BouncyCastleProvider();
                jsseProvider = new BouncyCastleJsseProvider(jceProvider);
                tlsSslContext = SSLContext.getInstance(tlsProtocol, jsseProvider);
                // TODO log this BouncyCastle complexity?
                dtlsSslContext = tlsSslContext;
                break;
            case JRE_DEFAULT:
                jceProvider = null;
                tlsSslContext = SSLContext.getInstance(tlsProtocol);
                dtlsSslContext = SSLContext.getInstance(dtlsProtocol);
                jsseProvider = tlsSslContext.getProvider();
                break;
            default:
                throw new IllegalArgumentException("The configuration provider was not understood " + config.provider());
        }
        
        kmf = setupKeyManager(config, jceProvider, jsseProvider);

        tmf = setupTrustManager(config, jceProvider, jsseProvider);
        
        tlsSslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        dtlsSslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        
        tlsParameters = tlsSslContext.getDefaultSSLParameters();
        dtlsParameters = dtlsSslContext.getDefaultSSLParameters();
        
        switch (config.client_auth()) {
            case NEED:
                tlsParameters.setNeedClientAuth(true);
                dtlsParameters.setNeedClientAuth(true);
                break;
            case WANT:
                tlsParameters.setWantClientAuth(true);
                dtlsParameters.setWantClientAuth(true);
                break;
            case NONE:
                tlsParameters.setWantClientAuth(false);
                dtlsParameters.setWantClientAuth(false);
                break;
            default:
                break;
        }
    }

    private KeyManagerFactory setupKeyManager(Config config, Provider jceProvider, Provider jsseProvider)
            throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException,
            UnrecoverableKeyException {
        String keyManagerAlgorithm = config.key_manager_algorithm();
        
        if(keyManagerAlgorithm.isEmpty()) {
            keyManagerAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
        }
        
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(keyManagerAlgorithm, jsseProvider);
        
        KeyStore keyStore = jceProvider == null ? KeyStore.getInstance(config.keystore_type()) :
            KeyStore.getInstance(config.keystore_type(), jceProvider);
        
        try (InputStream is = Files.newInputStream(new File(config.keystore_location()).toPath())) {
            keyStore.load(is, config._keystore_password().toCharArray());
        }
        
        String keystoreKeyPassword = config._keystore_key_password();
        
        kmf.init(keyStore, keystoreKeyPassword.isEmpty() ? config._keystore_password().toCharArray() :
            keystoreKeyPassword.toCharArray());
        return kmf;
    }

    private TrustManagerFactory setupTrustManager(Config config, Provider jceProvider, Provider jsseProvider)
            throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {
        
        String trustManagerAlgorithm = config.trust_manager_algorithm();
        
        if(trustManagerAlgorithm.isEmpty()) {
            trustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        }
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(trustManagerAlgorithm, jsseProvider);

        KeyStore trustStore = jceProvider == null ? KeyStore.getInstance(config.truststore_type()) :
            KeyStore.getInstance(config.truststore_type(), jceProvider);
        try (InputStream is = Files.newInputStream(new File(config.truststore_location()).toPath())) {
            trustStore.load(is, config._truststore_password().toCharArray());
        }
        
        tmf.init(trustStore);
        
        return tmf;
    }
    
    @Override
    public MultiplexingDTLSHandler getDTLSHandler() {
        if(insecure) {
            return null;
        }
        return new com.paremus.netty.dtls.jsse.ParemusDTLSHandler(() -> {
                SSLEngine engine = dtlsSslContext.createSSLEngine();
                engine.setSSLParameters(dtlsParameters);
                return new JdkDtlsEngineAdapter(engine);
            });
    }

    @Override
    public DTLSClientHandler getDTLSClientHandler() {
        if(insecure) {
            return null;
        }
        SSLEngine engine = dtlsSslContext.createSSLEngine();
        engine.setSSLParameters(dtlsParameters);
        engine.setUseClientMode(true);
        
        return new com.paremus.netty.dtls.jsse.ParemusClientDTLSHandler(new JdkDtlsEngineAdapter(engine));
    }

    @Override
    public DTLSHandler getDTLSServerHandler() {
        if(insecure) {
            return null;
        }
        SSLEngine engine = dtlsSslContext.createSSLEngine();
        engine.setSSLParameters(dtlsParameters);
        engine.setUseClientMode(false);
        
        return new com.paremus.netty.dtls.jsse.ParemusServerDTLSHandler(new JdkDtlsEngineAdapter(engine));
    }
    
    @Override
    public SslHandler getTLSClientHandler() {
        if(insecure) {
            return null;
        }
        
        SSLEngine engine = tlsSslContext.createSSLEngine();
        engine.setSSLParameters(tlsParameters);
        engine.setUseClientMode(true);
        
        return new SslHandler(engine);
    }

    @Override
    public SslHandler getTLSServerHandler() {
        if(insecure) {
            return null;
        }
        
        SSLEngine engine = tlsSslContext.createSSLEngine();
        engine.setSSLParameters(tlsParameters);
        engine.setUseClientMode(false);
        
        return new SslHandler(engine);
    }

    @Override
    public boolean hasCertificate() {
        return kmf != null;
    }

    @Override
    public boolean hasTrust() {
        return tmf != null;
    }
}
