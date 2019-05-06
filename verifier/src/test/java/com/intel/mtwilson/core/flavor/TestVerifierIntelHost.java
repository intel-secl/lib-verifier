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
import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.dcsg.cpg.extensions.Extensions;

import com.intel.mtwilson.core.common.model.*;

import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.core.verifier.policy.RuleResult;
import com.intel.mtwilson.core.verifier.policy.rule.PcrEventLogIntegrity;
import com.intel.mtwilson.core.verifier.policy.rule.XmlMeasurementLogEquals;
import com.intel.mtwilson.core.verifier.policy.rule.XmlMeasurementLogIntegrity;
import com.intel.mtwilson.core.verifier.policy.rule.XmlMeasurementsDigestEquals;
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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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
public class TestVerifierIntelHost {
    
    String pathPrefix = "intel-host";
    ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
    File tempPrivacyCA;
    File temptagCA;
    String hostManifestwithTagCertificateAsJson;
    GenericPlatformFlavor gpf;

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

        String hostManifestAsJson = Resources.toString(Resources.getResource(pathPrefix + "/RHEL_Manifest.json"), Charsets.UTF_8);
        String tagCerAsJson = Resources.toString(Resources.getResource(pathPrefix + "/tagcer.json"), Charsets.UTF_8);

        X509AttributeCertificate tagCer = mapper.readValue(tagCerAsJson, X509AttributeCertificate.class);
        HostManifest hostManifest = mapper.readValue(hostManifestAsJson, HostManifest.class);
        //hostManifest.setTagCertificate(tagCer);
        hostManifestwithTagCertificateAsJson = mapper.writeValueAsString(hostManifest);

        //PlatformFlavorFactory factory = new PlatformFlavorFactory();
        //PlatformFlavor platformFlavor = factory.getPlatformFlavor(hostManifest, tagCer);
        gpf = new GenericPlatformFlavor("INTEL", tagCer);
    }

    @After
    public void tearDown() {
        tempPrivacyCA.delete();
        temptagCA.delete();
    }

    @Test
    public void testTrustReportResults() throws Exception {
        for(String flavorPart: gpf.getFlavorPartNames()) {
            Verifier verifier = new Verifier(tempPrivacyCA.getPath(), temptagCA.getPath());
            TrustReport report = verifier.verify(hostManifestwithTagCertificateAsJson, gpf.getFlavorPart(flavorPart).get(0));

            System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(report));

            //Trust Report trust status
            //assertTrue("Trust Report is untrusted", report.isTrusted());

            for (Map.Entry<String, String> entry : report.getTags().entrySet()) {
                System.out.println(entry.getKey() + " " + entry.getValue());
            }
        }
    }

    @Test
    public void testMeasure() throws Exception {
        String flavorString = "{\"meta\":{\"schema\":{\"uri\":\"lib:wml:measurements:1.0\"},\"id\":\"01ed22ca-73c6-11e8-adc0-fa7ae01blalalala2222\",\"description\":{\"flavor_part\":\"SOFTWARE\",\"label\":\"ISecL_Default_Application_Flavor_v1\",\"digest_algorithm\":\"SHA256\"}},\"software\":{\"measurements\":{\"/opt/trustagent/hypertext/web-inf\":{\"type\":\"directoryMeasurementType\",\"value\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"Path\":\"/opt/trustagent/hypertext/web-inf\",\"Include\":\".*\",\"Exclude\":\"\"},\"/opt/trustagent/bin/module_analysis_da.sh\":{\"type\":\"fileMeasurementType\",\"value\":\"0896695e930565be3c8e85cc4a49a2a0662fa5c004473dfe24728bacb2a74798\",\"Path\":\"/opt/trustagent/bin/module_analysis_da.sh\"}},\"cumulative_hash\":\"057367afa72d572655ab6fa21ac7ce7922fb364557f5225de70308c65d4e85d3\"}}";
        String measurement = "<?xml version='1.0'?><Measurement xmlns='lib:wml:measurements:1.0' Label='ISecL_Default_Application_Flavor_v1' Uuid='01ed22ca-73c6-11e8-adc0-fa7ae01blalalala2222' DigestAlg='SHA256'><Dir Exclude='' Include='.*' Path='/opt/trustagent/hypertext/web-inf'>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</Dir><File Path='/opt/trustagent/bin/module_analysis_da.sh'>0896695e930565be3c8e85cc4a49a2a0662fa5c004473dfe24728bacb2a74798</File><CumulativeHash>057367afa72d572655ab6fa21ac7ce7922fb364557f5225de70308c65d4e85d3</CumulativeHash></Measurement>";
        HostManifest hostManifest = new HostManifest();
        HostInfo hostInfo = new HostInfo();
        hostInfo.setTpmVersion("2.0");
        hostManifest.setHostInfo(hostInfo);
        PcrManifest p = new PcrManifest();
        List<String> measurements = new ArrayList<>();
        measurements.add(measurement);
        Pcr pcr = new PcrSha256(PcrIndex.PCR15, "d28e82847ed4aa3c24c6a8106129a112794b13fda98d2170b89e54ec5112f4fb");
        p.setPcr(pcr);
        List<MeasurementSha256> moduleManifest = new ArrayList<>();
        moduleManifest.add(new MeasurementSha256(Sha256Digest.valueOf("057367afa72d572655ab6fa21ac7ce7922fb364557f5225de70308c65d4e85d3"), "ISecL_Default_Application_Flavor_v1-01ed22ca-73c6-11e8-adc0-fa7ae01blalalala2222"));
        PcrEventLog pcrEventLog = new PcrEventLogSha256(PcrIndex.PCR15, moduleManifest);
        p.setPcrEventLog(pcrEventLog);

        p.setMeasurementXmls(measurements);
        hostManifest.setPcrManifest(p);


        PcrEventLogIntegrity pcrEventLogIntegrity = new PcrEventLogIntegrity(pcr);
        RuleResult report = pcrEventLogIntegrity.apply(hostManifest);
        assertTrue("Trust Report is untrusted for pcrs", report.isTrusted());

        Flavor flavor = Flavor.deserialize(flavorString);
        XmlMeasurementsDigestEquals e = new XmlMeasurementsDigestEquals(flavor);
        report = e.apply(hostManifest);
        assertTrue("Trust Report is untrusted for digests", report.isTrusted());

        XmlMeasurementLogIntegrity xl = new XmlMeasurementLogIntegrity(flavor);
        report = xl.apply(hostManifest);
        assertTrue("Trust Report is untrusted for integrity", report.isTrusted());

        XmlMeasurementLogEquals xmlMeasurementLogEquals = new XmlMeasurementLogEquals(flavor);
        report = xmlMeasurementLogEquals.apply(hostManifest);
        assertTrue("Trust Report is untrusted for equality", report.isTrusted());
    }
}
