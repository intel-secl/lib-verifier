/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.mtwilson.core.verifier.policy.rule.AssetTagMatches;

import com.intel.mtwilson.core.common.model.HostManifest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Note: passing policy name instead of policy itself because do not want to just "return policy",
 * since that will have all the same information that you already get in the reports, and anything
 * that serializes this class would then show redundant info.  Every rule result already includes
 * the rule itself, and since there is a result for every rule in the policy,  the entire policy
 * is represented by the set of rule results.
 *
 * The host manifest is also included, which is somewhat redundant but not completely, because it
 * has information that may not be present in the rules, which the UI may want to show. For example,
 * for vmware PCR 19 which has a different value for every host due to a host-specific UUID
 * being extended into it,  the UI may want to show the actual value of PCR 19. however, if the
 * rules only check for PCR integrity and for some modules to be included, then it doesn't really
 * say what is the PCR value (and if it did, it would show the expected PCR, not the actual PCR).
 * Also if module names mismatch even though their digests are the same, that wouldn't normally
 * be reflected in the results.
 *
 * @author jbuhacoff
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class TrustReport {
    private HostManifest hostManifest;
    private String policyName;
    private ArrayList<RuleResult> results = new ArrayList<RuleResult>();
    private Logger log = LoggerFactory.getLogger(getClass());

    public TrustReport() { } // for desearializing jackson

    public TrustReport(HostManifest hostManifest, String policyName) {
        this.hostManifest = hostManifest;
        this.policyName = policyName;
    }

    public HostManifest getHostManifest() { return hostManifest; }
    public String getPolicyName() { return policyName; }

    public void addResult(RuleResult result)  {
        if (!checkResultExists(result)){
            results.add(result);
        }
    }

    public List<RuleResult> getResults() { return results; } // contains the set of rules and their parameters AND faults AND isTrusted for each one

    private boolean isTrustedForResults(List<RuleResult> list) {
        if( list.isEmpty() ) {
            return false; // empty policy is not trusted;  like RequireAllEmptySet fault.
        }
        boolean trusted = true;
        Iterator<RuleResult> it = list.iterator();
        while(it.hasNext()) {
            RuleResult result = it.next();
            trusted = trusted && result.isTrusted();
        }
        return trusted;
    }

    public boolean isTrusted() {
        return isTrustedForResults(results);
    }

    // returns a list of trust reports corresponding to the specified marker
    // they are already included in the overall "getReports" but this allows
    // you to look specifically at what caused a specific marker to be trusted
    // or untrusted
    public List<RuleResult> getResultsForMarker(String marker) {
        ArrayList<RuleResult> markerReports = new ArrayList<RuleResult>();
        for(RuleResult report : results) {
            String[] markers = report.getRule().getMarkers();
            if( markers != null ) {
                List<String> markerList = Arrays.asList(markers);
                if( markerList.contains(marker) ) {
                    markerReports.add(report);
                }
            }
        }
        return markerReports;
    }

    public boolean isTrustedForMarker(String marker) {
        return isTrustedForResults(getResultsForMarker(marker));
    }

    public boolean checkResultExists(RuleResult result) {
        String marker = result.getRule().getMarkers()[0];
        List<RuleResult> combinedRuleResults = this.getResultsForMarker(marker);
        for (RuleResult ruleResult : combinedRuleResults) {
            if (result.equals(ruleResult)) {
                if (result.getRule() instanceof PcrRule) {
                    PcrRule pcrRule = (PcrRule) result.getRule();
                    PcrRule pcrRuleResult = (PcrRule) ruleResult.getRule();
                    if (pcrRule.getExpectedPcr() == null || (pcrRule.getExpectedPcr() != null &&
                            !pcrRule.getExpectedPcr().equals(pcrRuleResult.getExpectedPcr()))) {
                        return false;
                    }
                }
                return true;
            }
        }
        return false;
    }

    @JsonIgnore
    public int getFaultsCount() {
        int faultsCount = 0;
        for(RuleResult ruleResult : results) {
            faultsCount += ruleResult.getFaults().size();
        }
        return faultsCount;
    }

    @JsonIgnore
    public Map<String, String> getTags() {
        Map<String, String> tags = new HashMap();
        for(RuleResult ruleResult: getResultsForMarker(TrustMarker.ASSET_TAG.name())){
            if (ruleResult.getRuleName().equals(AssetTagMatches.class.getName())){
                AssetTagMatches rule = (AssetTagMatches)ruleResult.getRule();
                tags = rule.getTags();
            }
        }
        return tags;
    }
}
