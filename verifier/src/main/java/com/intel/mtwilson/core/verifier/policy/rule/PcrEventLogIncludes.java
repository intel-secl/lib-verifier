/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import com.intel.dcsg.cpg.crypto.DigestAlgorithm;

import com.intel.mtwilson.core.verifier.policy.BaseRule;
import com.intel.mtwilson.core.verifier.policy.RuleResult;
import com.intel.mtwilson.core.verifier.policy.fault.PcrEventLogMissing;
import com.intel.mtwilson.core.verifier.policy.fault.PcrEventLogMissingExpectedEntries;

import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.mtwilson.core.common.model.Measurement;
import com.intel.mtwilson.core.common.model.PcrEventLog;
import com.intel.mtwilson.core.common.model.PcrIndex;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * A TrustPolicy implementation that checks whether the HostReport contains a
 * ModuleManifest for a given PCR that includes the expected ModuleManifest. The
 * expected ModuleManifest in this case is considered a subset manifest - the
 * host may have the same modules, or additional modules, and pass; but if the
 * host is missing any modules from the manifest it will trigger a fault.
 * 
 * @author dtiwari
 *
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PcrEventLogIncludes extends BaseRule {
    protected DigestAlgorithm pcrBank;
    protected PcrIndex pcrIndex;
    protected Set<Measurement> expected;
    
    protected PcrEventLogIncludes() {
    } // for desearializing jackson

    public PcrEventLogIncludes(DigestAlgorithm pcrBank, PcrIndex pcrIndex, Measurement expected) {
        this.pcrBank = pcrBank;
        this.pcrIndex = pcrIndex;
        this.expected = new HashSet(1);
        this.expected.add(expected);
    }

    public PcrEventLogIncludes(DigestAlgorithm pcrBank, PcrIndex pcrIndex, Set<Measurement> expected) {
        this.pcrBank = pcrBank;
        this.pcrIndex = pcrIndex;
        this.expected = expected;
    }
    
    public DigestAlgorithm getPcrBank() {
        return pcrBank;
    }
    
    public PcrIndex getPcrIndex() {
        return pcrIndex;
    }

    public Set<Measurement> getExpected() {
        return expected;
    }
    
    @Override
    public RuleResult apply(HostManifest hostManifest) {
        RuleResult report = new RuleResult(this);
//        report.check(this);
//        report.check(getClass().getSimpleName()); // the minimum... show that the host was evaluated by this policy
        if (hostManifest.getPcrManifest() == null) {
            report.fault(new PcrEventLogMissing());
        } else {
            PcrEventLog pcrEventLog = hostManifest.getPcrManifest().getPcrEventLog(pcrBank, pcrIndex);
            if (pcrEventLog == null) {
                report.fault(new PcrEventLogMissing(pcrIndex));
            } else {
                List<Measurement> moduleManifest = pcrEventLog.getEventLog();
                if (moduleManifest == null || moduleManifest.isEmpty()) {
                    report.fault(new PcrEventLogMissing(pcrIndex));
                } else {
                    HashSet<Measurement> hostActualMissing = new HashSet(expected);
                    hostActualMissing.removeAll(moduleManifest); // hostActualMissing = expected modules - actual modules = only modules that should be there but aren't 
                    if (!hostActualMissing.isEmpty()) {
                        report.fault(new PcrEventLogMissingExpectedEntries(pcrIndex, hostActualMissing));
                    }
                }
            }
        }
        return report;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final PcrEventLogIncludes other = (PcrEventLogIncludes) obj;
        if (this.pcrBank != other.pcrBank) {
            return false;
        }
        if (!Objects.equals(this.pcrIndex, other.pcrIndex)) {
            return false;
        }
        if (!Objects.equals(this.expected, other.expected)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        return expected.hashCode();
    }
}
