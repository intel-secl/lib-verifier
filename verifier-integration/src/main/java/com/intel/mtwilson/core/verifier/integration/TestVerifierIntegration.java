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
import com.intel.mtwilson.core.host.connector.*;
import com.intel.mtwilson.core.host.connector.intel.IntelHostConnectorFactory;
import com.intel.mtwilson.core.host.connector.intel.MicrosoftHostConnectorFactory;
import com.intel.mtwilson.core.host.connector.vmware.VmwareHostConnectorFactory;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.core.common.model.HostManifest;
import java.io.IOException;
import com.intel.mtwilson.core.verifier.Verifier;
import com.intel.mtwilson.core.verifier.policy.TrustReport;
import com.intel.mtwilson.core.common.tag.model.X509AttributeCertificate;

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
    public void testGenerateTrustReport(String hostConnectionString) throws IOException, Exception {

        HostConnectorFactory factory = new HostConnectorFactory();
        HostConnector hostConnector = factory.getHostConnector(hostConnectionString, tlsPolicy);
        HostManifest hostManifest = hostConnector.getHostManifest();
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
        String hostManifestwithTagCertificateAsJson = mapper.writeValueAsString(hostManifest);
        String tagCerAsJson = Resources.toString(Resources.getResource("tagcer.json"), Charsets.UTF_8);
        X509AttributeCertificate tagCer = mapper.readValue(tagCerAsJson, X509AttributeCertificate.class);

        PlatformFlavor platformFlavor = flavorFactory.getPlatformFlavor(hostManifest, tagCer);        

        for(String flavorPart: platformFlavor.getFlavorPartNames()) {
            String flavor = platformFlavor.getFlavorPart(flavorPart);
            System.out.println("=== Generated " + flavorPart + " Flavor ===");
            System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(flavor));

            Verifier verifier = new Verifier("/root/PrivacyCA.pem", "/root/tag-cacerts.pem");
            TrustReport report = verifier.verify(hostManifestwithTagCertificateAsJson, flavor);
            System.out.println("=== Generated Trust Report for " + flavorPart + " ===");
            System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(report));
        }
    }
    
}
