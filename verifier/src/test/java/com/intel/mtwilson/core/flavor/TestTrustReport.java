/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.flavor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import com.intel.mtwilson.core.verifier.policy.TrustReport;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author rksavino
 */
public class TestTrustReport {
    private final ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();

    @BeforeClass
    public static void registerJacksonModules() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() {
    }
    
    @Test
    public void serializeTrustReport() throws Exception {
        String trustReportAsJson = Resources.toString(Resources.getResource("trust-report-rhel-tpm2.json"), Charsets.UTF_8);
        TrustReport trustReport = mapper.readValue(trustReportAsJson, TrustReport.class);
        System.out.println(String.format("Successfully deserialized file to trust report with host name: %s", trustReport.getHostManifest().getHostInfo().getHostName()));
        
        System.out.println(String.format("Serialized host manifest:\n%s", mapper.writeValueAsString(trustReport)));
    }
}
