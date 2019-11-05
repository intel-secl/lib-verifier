/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import com.intel.dcsg.cpg.extensions.WhiteboardExtensionProvider;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
import com.intel.dcsg.cpg.tls.policy.impl.InsecureTlsPolicy;
import com.intel.kunit.annotations.BeforeAll;
import com.intel.kunit.annotations.Integration;
import com.intel.mtwilson.core.flavor.PlatformFlavor;
import com.intel.mtwilson.core.flavor.PlatformFlavorFactory;
import com.intel.mtwilson.core.flavor.model.SignedFlavor;
import com.intel.mtwilson.core.host.connector.*;
import com.intel.mtwilson.core.host.connector.intel.IntelHostConnectorFactory;
import com.intel.mtwilson.core.host.connector.intel.MicrosoftHostConnectorFactory;
import com.intel.mtwilson.core.host.connector.vmware.VmwareHostConnectorFactory;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.core.common.model.HostManifest;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import com.intel.mtwilson.core.verifier.Verifier;
import com.intel.mtwilson.core.verifier.policy.TrustReport;
import com.intel.mtwilson.core.common.tag.model.X509AttributeCertificate;
import com.intel.mtwilson.util.crypto.keystore.PrivateKeyStore;

import java.security.PrivateKey;
import java.util.List;

/**
 *
 * @author dtiwari
 */
public class TestVerifierIntegration {

    final TlsPolicy tlsPolicy = new InsecureTlsPolicy();
    final PlatformFlavorFactory flavorFactory = new PlatformFlavorFactory();

    public TestVerifierIntegration() throws Exception {
    }

    @BeforeAll
    public static void setup() throws IOException {
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, IntelHostConnectorFactory.class);
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, MicrosoftHostConnectorFactory.class);
        WhiteboardExtensionProvider.register(VendorHostConnectorFactory.class, VmwareHostConnectorFactory.class);
    }

    @Integration
    public void testGenerateTrustReport(String hostConnectionString, String aasApiUrl) throws IOException, Exception {
        FileInputStream keystoreFIS = new FileInputStream("/root/mtwilson-flavor-signing-cert.p12");
        PrivateKeyStore privateKeyStore = new PrivateKeyStore("PKCS12", new File("/root/mtwilson-flavor-signing-cert.p12"), "H6mpW8iKFOzytOFoAquvbw==".toCharArray());
        PrivateKey privateKey = privateKeyStore.getPrivateKey("flavor-signing-key");

        HostConnectorFactory factory = new HostConnectorFactory();
        HostConnector hostConnector = factory.getHostConnector(hostConnectionString, aasApiUrl, tlsPolicy);
        HostManifest hostManifest = hostConnector.getHostManifest();
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
        String tagCerAsJson = Resources.toString(Resources.getResource("tagcer.json"), Charsets.UTF_8);
        X509AttributeCertificate tagCer = mapper.readValue(tagCerAsJson, X509AttributeCertificate.class);

        PlatformFlavor platformFlavor = flavorFactory.getPlatformFlavor(hostManifest, tagCer);

        for(String flavorPart: platformFlavor.getFlavorPartNames()) {
            List<SignedFlavor> signedFlavorsList = platformFlavor.getFlavorPartWithSignature(flavorPart, (PrivateKey)privateKey);
            for (SignedFlavor signedFlavor : signedFlavorsList) {
                System.out.println("=== Generated " + flavorPart + " Flavor ===");
                System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(signedFlavor));

                Verifier verifier = new Verifier("/root/PrivacyCA.pem", "/root/tag-cacerts.pem", "/root/flavor-signer.crt.pem", "/root/cms-ca.crt.pem");
                TrustReport report = verifier.verify(hostManifest, signedFlavor, false);
                System.out.println("=== Generated Trust Report for " + flavorPart + " ===");
                System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(report));
            }            
        }
        keystoreFIS.close();
    }
    
}
