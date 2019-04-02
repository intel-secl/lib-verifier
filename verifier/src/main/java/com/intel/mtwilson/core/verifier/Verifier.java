/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;

import com.intel.mtwilson.core.verifier.policy.HostTrustPolicyManager;
import com.intel.mtwilson.core.verifier.policy.RuleResult;
import com.intel.mtwilson.core.verifier.policy.TrustReport;

import com.intel.mtwilson.core.flavor.model.Flavor;

import com.intel.mtwilson.core.verifier.policy.Policy;
import com.intel.mtwilson.core.verifier.policy.Rule;
import com.intel.mtwilson.core.verifier.policy.rule.AikCertificateTrusted;
import com.intel.mtwilson.core.verifier.policy.rule.TagCertificateTrusted;
import com.intel.mtwilson.core.verifier.policy.vendor.VendorTrustPolicyReader;

import com.intel.mtwilson.core.common.model.HostManifest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Verifier library for applying the Trust Policy to the Host Manifest and
 * generate the Trust Report
 * 
 * @author  dtiwari
 * @since   IAT 1.0
 */
public class Verifier {

    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Verifier.class);
    private final String privacyCaCertificatepath;
    private final String assetTagCaCertificatepath;
    
    public Verifier(String privacyCaCertificatepath, String assetTagCaCertificatepath) {
        this.privacyCaCertificatepath = privacyCaCertificatepath;
        this.assetTagCaCertificatepath = assetTagCaCertificatepath;
    }
    
    /**
     * Generate the Trust Report for the given Host Manifest and Flavor
     * 
     * @param hostManifest  Host Manifest 
     * @param flavor  Flavor
     * @return  TrustReport
     * @throws IOException
     */
    public TrustReport verify(String hostManifest, String flavor) throws IOException {
        ObjectMapper mapper = JacksonObjectMapperProvider.createDefaultMapper();
        HostManifest hostManifestObj = mapper.readValue(hostManifest, HostManifest.class);
        Flavor flavorObj = mapper.readValue(flavor, Flavor.class);
        return verify(hostManifestObj, flavorObj);
    }
    
    /**
     * Generate the Trust Report for the given Host Manifest and Flavor
     * 
     * @param hostManifest  Host Manifest 
     * @param flavor  Flavor
     * @return  TrustReport
     */
    public TrustReport verify(HostManifest hostManifest, Flavor flavor) {
        HostTrustPolicyManager policymanager = new HostTrustPolicyManager(flavor, hostManifest, privacyCaCertificatepath, assetTagCaCertificatepath);
        VendorTrustPolicyReader trustpolicy = policymanager.getVendorTrustPolicyReader();
        //log.debug("PolicyEngine.apply policy {}", policy.getName());
        Policy policy = trustpolicy.loadTrustRules();
        return applyPolicy(hostManifest, policy, flavor.getMeta().getId());
    }
    
    /**
     * Apply the given Trust Policy to the Host Manifest and generate a Trust Report
     * 
     * @param  hostManifest  
     * @param  policy
     * @return  Generated TrustReport
     */
    private TrustReport applyPolicy(HostManifest hostManifest, Policy policy, String flavorId) {
        log.debug("PolicyEngine.apply policy {}", policy.getName());
        TrustReport policyReport = new TrustReport(hostManifest, policy.getName());
        List<RuleResult> results = applyTrustRules(hostManifest, policy.getRules());
        Iterator<RuleResult> it = results.iterator();
        while(it.hasNext()) {
            RuleResult result = it.next();
            if(!(result.getRuleName().equals(TagCertificateTrusted.class.getName()) || result.getRuleName().equals(AikCertificateTrusted.class.getName()))){
                result.setFlavorId(flavorId);
            }
            policyReport.addResult(result);
        }
        return policyReport;
    }
    
    /**
     * Given a set of rules, apply them all, and combine the results into one report.
     * 
     * @param  hostManifest  
     * @param  Set of rules to be applied   
     * @return  Generated TrustReport
     */
    private List<RuleResult> applyTrustRules(HostManifest hostManifest, Set<Rule> rules) {
        log.debug("PolicyEngine.applyAll(set of {} rules)", rules.size());
        ArrayList<RuleResult> list = new ArrayList<>();
        for(Rule rule : rules) {
            log.debug("Applying rule {}", rule.getClass().getName());
            RuleResult result = rule.apply(hostManifest);
            list.add(result);
        }
        return list;
    }
}