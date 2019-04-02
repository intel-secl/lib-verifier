/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import com.intel.mtwilson.core.verifier.policy.BaseRule;
import com.intel.mtwilson.core.verifier.policy.RuleResult;
import com.intel.mtwilson.core.verifier.policy.fault.PcrManifestMissing;
import com.intel.mtwilson.core.verifier.policy.fault.PcrValueMismatch;
import com.intel.mtwilson.core.verifier.policy.fault.PcrValueMissing;

import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.mtwilson.core.common.model.Pcr;
import java.util.Objects;

/**
 * The PcrMatchesConstant policy enforces that a specific PCR contains a specific 
 * pre-determined constant value. This is typical for values that are known in 
 * advance such as PLATFORM or trusted module measurements.
 *
 * For example, "PCR {index} must equal {hex-value}"
 * 
 * @author dtiwari
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class PcrMatchesConstant extends BaseRule {
    private final Pcr expected;
    
    @JsonCreator
    public PcrMatchesConstant(@JsonProperty("expected_pcr") Pcr expected) {
        this.expected = expected;
    }
    
    public Pcr getExpectedPcr() { return expected; }
    
    @Override
    public RuleResult apply(HostManifest hostManifest) {
        RuleResult report = new RuleResult(this);
        if( hostManifest.getPcrManifest() == null ) {
            report.fault(new PcrManifestMissing());            
        }
        else {
            Pcr actual = hostManifest.getPcrManifest().getPcr(expected.getPcrBank(), expected.getIndex().toInteger());
            if( actual == null ) {
                report.fault(new PcrValueMissing(expected.getIndex()));
            }
            else {
                if( !expected.equals(actual) ) {
                    report.fault(PcrValueMismatch.newInstance(expected.getPcrBank(), expected.getIndex(), expected.getValue(), actual.getValue()) );
                }
            }
        }
        return report;
    }
    
    @Override
    public String toString() {
        return String.format("PCR %s, %s", expected.getIndex().toString(), expected.getValue().toString());
    }
    
    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof PcrMatchesConstant)) {
            return false;
        }
        PcrMatchesConstant rule = (PcrMatchesConstant) o;
        return Objects.equals(expected, rule.expected)
                && Objects.equals(markers, rule.markers);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(expected, markers);
    }
}
