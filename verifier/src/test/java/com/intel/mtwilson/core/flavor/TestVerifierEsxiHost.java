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
import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.core.flavor.model.SignedFlavor;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;

import com.intel.mtwilson.core.verifier.Verifier;
import com.intel.mtwilson.core.verifier.policy.TrustReport;

import com.intel.mtwilson.jackson.bouncycastle.BouncyCastleModule;
import com.intel.mtwilson.jackson.validation.ValidationModule;

import com.intel.mtwilson.core.common.tag.model.X509AttributeCertificate;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Map.Entry;

import com.intel.mtwilson.util.crypto.keystore.PrivateKeyStore;
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
    File tempFlavorSigningCert;
    File tempFlavorSigningKeystore;
    String hostManifestwithTagCertificateAsJson;
    SignedFlavor assetTagFlavor;

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

        try (InputStream fi = this.getClass().getClassLoader().getResourceAsStream( pathPrefix + "/flavor-signer.crt.pem")) {
            tempFlavorSigningCert = File.createTempFile("temp_flavor_signing_cert", "");
            Files.copy(fi, tempFlavorSigningCert.toPath(), REPLACE_EXISTING);
            tempFlavorSigningCert.setReadable(true);
        }

        try (InputStream fi = this.getClass().getClassLoader().getResourceAsStream( pathPrefix + "/mtwilson-flavor-signing-cert.p12")) {
            tempFlavorSigningKeystore = File.createTempFile("temp_flavor_signing_keystore", "");
            Files.copy(fi, tempFlavorSigningKeystore.toPath(), REPLACE_EXISTING);
            tempFlavorSigningKeystore.setReadable(true);
        }
        PrivateKeyStore privateKeyStore = new PrivateKeyStore("PKCS12", new File(tempFlavorSigningKeystore.getPath()), "H6mpW8iKFOzytOFoAquvbw==".toCharArray());
        PrivateKey privateKey = privateKeyStore.getPrivateKey("flavor-signing-key");
        String hostManifestAsJson = Resources.toString(Resources.getResource(pathPrefix + "/hostmanifest.json"), Charsets.UTF_8);
        String tagCerAsJson = Resources.toString(Resources.getResource(pathPrefix + "/tagcer.json"), Charsets.UTF_8);

        X509AttributeCertificate tagCer = mapper.readValue(tagCerAsJson, X509AttributeCertificate.class);
        HostManifest hostManifest = mapper.readValue(hostManifestAsJson, HostManifest.class);
        //hostManifest.setTagCertificate(tagCer);
        hostManifestwithTagCertificateAsJson = mapper.writeValueAsString(hostManifest);

        ESXPlatformFlavor esxPlatformFlavor = new ESXPlatformFlavor(hostManifest, tagCer);
        assetTagFlavor = esxPlatformFlavor.getFlavorPartWithSignature(FlavorPart.ASSET_TAG.getValue(), (PrivateKey)privateKey).get(0);
    }

    @After
    public void tearDown() {
        tempPrivacyCA.delete();
        temptagCA.delete();
        tempFlavorSigningCert.delete();
        tempFlavorSigningKeystore.delete();
    }

    @Test
    public void testTrustReportResults() throws Exception {
        Verifier verifier = new Verifier(tempPrivacyCA.getPath(), temptagCA.getPath(), tempFlavorSigningCert.getPath());
        TrustReport report = verifier.verify(hostManifestwithTagCertificateAsJson, Flavor.serialize(assetTagFlavor.getFlavor()), assetTagFlavor.getSignature(), true);
        
        System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(report));
        for(Entry<String, String> entry : report.getTags().entrySet()){
            System.out.println(entry.getKey() + " " + entry.getValue());
        }
    }
}
