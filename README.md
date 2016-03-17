# The Paremus Core Repository

This repository contains core components used to support higher-level Paremus services, and also any boms/code related to building and testing.

## Repository Contents

This repository contains:

### com.paremus.cert & com.paremus.cert.test

The certificate management component is responsible for creating, storing and providing access to cryptographically secure certificates. The certificate management component also provides facilities for managing certificate trust, and for signing certificate requests.

The integration tests for the certificate management component demonstrate the use of the service, and validate the configuration injection for certificate details

Note that the certificate management component makes use of functions from the [Bouncy Castle](https://www.bouncycastle.org) project

### com.paremus.netty.tls

The Netty TLS component provides SSL and DTLS integration for [Netty](https://netty.io) based on the Paremus certificate management component. This allows for simple configuration of Netty with a consistent security and trust domain, as well as adding DTLS support. 
 

# How to build this repository

This repository can be built using Maven 3.5.4 and Java 9. The output bundles will work with Java 8, however DTLS 1.2 support is only available within the JDK since Java 9. On Java 8 the bouncy castle DTLS provider must be used instead. 

## Build profiles

By default the build will run with all tests, and lenient checks on copyright headers. To enable strict copyright checking (required for deployment) then the `strict-license-check` profile should be used, for example

    mvn -P strict-license-check clean install

If you make changes and do encounter licensing errors then the license headers can be regenerated using the `generate-licenses` profile

    mvn -P generate-licenses process-sources
