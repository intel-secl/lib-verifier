/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import com.intel.mtwilson.core.verifier.policy.PcrRule;
import com.intel.mtwilson.core.verifier.policy.RuleResult;
import com.intel.mtwilson.core.verifier.policy.fault.PcrEventLogContainsUnexpectedEntries;
import com.intel.mtwilson.core.verifier.policy.fault.PcrEventLogMissing;
import com.intel.mtwilson.core.verifier.policy.fault.PcrEventLogMissingExpectedEntries;

import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.mtwilson.core.common.model.Measurement;
import com.intel.mtwilson.core.common.model.PcrEventLog;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A TrustPolicy implementation that checks whether the HostManifest contains a
 * ModuleManifest for a given PCR that equals the expected ModuleManifest. The
 * expected ModuleManifest in this case is a complete manifest and any change
 * (less modules, more modules, different modules) in the actual ModuleManifest
 * will trigger a fault.
 *
 * @author dtiwari
 * @since IAT 1.0
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PcrEventLogEquals extends PcrRule {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private PcrEventLog expected;

    protected PcrEventLogEquals() {
    } // for desearializing jackson

    public PcrEventLogEquals(PcrEventLog expected) {
        this.expected = expected;
    }

    public PcrEventLog getExpected() {
        return expected;
    }

    @Override
    public RuleResult apply(HostManifest hostManifest) {
        RuleResult report = new RuleResult(this);
        if (hostManifest.getPcrManifest() == null) {
            log.debug("PcrManifest null fault is being raised.");
            report.fault(new PcrEventLogMissing());
        } else {
            PcrEventLog pcrEventLog = getPcrEventLog(hostManifest);
            if (pcrEventLog == null) {
                log.debug("PcrEventLog missing fault is being raised.");
                report.fault(new PcrEventLogMissing(expected.getPcrIndex()));
            } else {
                List<Measurement> moduleManifest = pcrEventLog.getEventLog();
                if (moduleManifest == null || moduleManifest.isEmpty()) {
                    report.fault(new PcrEventLogMissing(expected.getPcrIndex()));
                } else {
                    log.debug("About to apply the PcrEventLogEquals policy for {} entries.", moduleManifest.size());
                    // we check that for the PCR defined in the policy, the HostManifest's PcrModuleManifest contains the exact set of expected modules
                    ArrayList<Measurement> hostActualUnexpected = new ArrayList<>(moduleManifest);
                    hostActualUnexpected.removeAll(expected.getEventLog()); //  hostActualUnexpected = actual modules - expected modules = only extra modules that shouldn't be there;  comparison is done BY HASH VALUE,  not by name or any "other info"
                    hostActualUnexpected.removeAll(getPcrEventLogToBeIgnored(moduleManifest));
                    if (!hostActualUnexpected.isEmpty()) {
                        log.debug("PcrEventLogEquals : Host is having #{} additional modules compared to the white list.", hostActualUnexpected.size());
                        report.fault(new PcrEventLogContainsUnexpectedEntries(expected.getPcrIndex(), hostActualUnexpected));
                    }
                    ArrayList<Measurement> hostActualMissing = new ArrayList<>(expected.getEventLog());
                    hostActualMissing.removeAll(moduleManifest); // hostActualMissing = expected modules - actual modules = only modules that should be there but aren't 
                    if (!hostActualMissing.isEmpty()) {
                        log.debug("PcrEventLogEquals : Host is missing #{} modules compared to the white list.", hostActualMissing.size());
                        report.fault(new PcrEventLogMissingExpectedEntries(expected.getPcrIndex(), new HashSet<>(hostActualMissing)));
                    }
                }
            }
        }
        return report;
    }

    private ArrayList<Measurement> getPcrEventLogToBeIgnored(List<Measurement> moduleManifest) {
        ArrayList<Measurement> measurementsToBeIgnored = new ArrayList<>();
        for(Measurement m : moduleManifest) {
            if(m.getLabel().equalsIgnoreCase("0x4fe")) {
                measurementsToBeIgnored.add(m);
            }
        }
        return measurementsToBeIgnored;
    }

    protected PcrEventLog getPcrEventLog(HostManifest hostManifest) {
        return hostManifest.getPcrManifest().getPcrEventLog(expected.getPcrBank(), expected.getPcrIndex());
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
        final PcrEventLogEquals other = (PcrEventLogEquals) obj;
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
