/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.flavor;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import com.intel.dcsg.cpg.extensions.Extensions;

import com.intel.mtwilson.core.common.model.HostManifest;

import com.intel.mtwilson.core.flavor.common.FlavorPart;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;

import com.intel.mtwilson.core.verifier.Verifier;
import com.intel.mtwilson.core.verifier.policy.TrustReport;

import com.intel.mtwilson.jackson.bouncycastle.BouncyCastleModule;
import com.intel.mtwilson.jackson.validation.ValidationModule;

import com.intel.mtwilson.core.common.tag.model.X509AttributeCertificate;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import java.util.Map.Entry;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Verifier for Intel DA TPM 2.0 host
 *
 * @author dtiwari
 */
public class TestVerifierEsxiHost {
    
    String pathPrefix = "esxi-host";
    ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
    File tempPrivacyCA;
    File temptagCA;
    String hostManifestwithTagCertificateAsJson;
    String assetTagFlavor;

    @BeforeClass
    public static void registerJacksonModules() {
        Extensions.register(Module.class, BouncyCastleModule.class);
        Extensions.register(Module.class, ValidationModule.class);
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() throws Exception {
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

        try (InputStream fi = this.getClass().getClassLoader().getResourceAsStream( pathPrefix + "/PrivacyCA.pem")) {
            tempPrivacyCA = File.createTempFile("temp_privacyca", "");
            Files.copy(fi, tempPrivacyCA.toPath(), REPLACE_EXISTING);
            tempPrivacyCA.setReadable(true);
        }
        
        try (InputStream fi = this.getClass().getClassLoader().getResourceAsStream( pathPrefix + "/tag-cacerts.pem")) {
            temptagCA = File.createTempFile("temp_tagca", "");
            Files.copy(fi, temptagCA.toPath(), REPLACE_EXISTING);
            temptagCA.setReadable(true);
        }

        String hostManifestAsJson = Resources.toString(Resources.getResource(pathPrefix + "/hostmanifest.json"), Charsets.UTF_8);
        String tagCerAsJson = Resources.toString(Resources.getResource(pathPrefix + "/tagcer.json"), Charsets.UTF_8);

        X509AttributeCertificate tagCer = mapper.readValue(tagCerAsJson, X509AttributeCertificate.class);
        HostManifest hostManifest = mapper.readValue(hostManifestAsJson, HostManifest.class);
        //hostManifest.setTagCertificate(tagCer);
        hostManifestwithTagCertificateAsJson = mapper.writeValueAsString(hostManifest);

        ESXPlatformFlavor esxPlatformFlavor = new ESXPlatformFlavor(hostManifest, tagCer);
        assetTagFlavor = esxPlatformFlavor.getFlavorPart(FlavorPart.ASSET_TAG.getValue());
    }

    @After
    public void tearDown() {
        tempPrivacyCA.delete();
        temptagCA.delete();
    }

    @Test
    public void testTrustReportResults() throws Exception {
        Verifier verifier = new Verifier(tempPrivacyCA.getPath(), temptagCA.getPath());
        TrustReport report = verifier.verify(hostManifestwithTagCertificateAsJson, assetTagFlavor);
        
        System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(report));
        for(Entry<String, String> entry : report.getTags().entrySet()){
            System.out.println(entry.getKey() + " " + entry.getValue());
        }
    }
}
