/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.core.flavor;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.common.base.Charsets;
import com.google.common.io.Resources;
import com.intel.dcsg.cpg.extensions.Extensions;
import com.intel.mtwilson.core.verifier.policy.RuleResult;
import com.intel.mtwilson.core.verifier.policy.TrustReport;
import com.intel.mtwilson.jackson.bouncycastle.BouncyCastleModule;
import com.intel.mtwilson.jackson.validation.ValidationModule;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import java.io.File;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author dtiwari
 */
public class TestFlavorVerify {
    
    String pathPrefix = "flavorverify";
    ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
    TrustReport combinedTrustReport;

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

        String combinedTrustReportInString = Resources.toString(Resources.getResource(pathPrefix + "/combined_trustreport.json"), Charsets.UTF_8);
        //String individualTrustReportInString = Resources.toString(Resources.getResource(pathPrefix + "/individual_trustreport.json"), Charsets.UTF_8);

        combinedTrustReport = mapper.readValue(combinedTrustReportInString, TrustReport.class);
        //individualTrustReport = mapper.readValue(individualTrustReportInString, TrustReport.class);
    }
    
    @Test
    public void testCombinedTrustReportResults() throws Exception {
//        for (RuleResult r : individualTrustReport.getResults()){
//            combinedTrustReport.addResult(r);
//        }
        System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(combinedTrustReport));
    }
    
    
}
