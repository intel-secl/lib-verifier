/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import com.intel.dcsg.cpg.crypto.AbstractDigest;
import com.intel.dcsg.cpg.crypto.DigestAlgorithm;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.crypto.Sha256Digest;

import com.intel.mtwilson.core.common.model.*;
import com.intel.mtwilson.core.verifier.policy.PcrRule;
import com.intel.mtwilson.core.verifier.policy.RuleResult;
import com.intel.mtwilson.core.verifier.policy.fault.PcrEventLogInvalid;
import com.intel.mtwilson.core.verifier.policy.fault.PcrEventLogMissing;
import com.intel.mtwilson.core.verifier.policy.fault.PcrManifestMissing;
import com.intel.mtwilson.core.verifier.policy.fault.PcrValueMissing;

import java.util.List;
import java.util.Objects;

/**
 * The PcrMatchesConstant policy enforces that a specific PCR contains a
 * specific pre-determined constant value. This is typical for values that are
 * known in advance such as PLATFORM or trusted module measurements.
 *
 * The PcrEventLogIncludes and PcrEventLogEquals policies enforce that the event
 * log for a specific PCR contain certain measurements.
 *
 * This policy, PcrEventLogIntegrity, is a complement to the other PcrEventLog*
 * policies because it checks that the PCR value is equal to the result of
 * extending all the measurements in the event log. If this policy is applied to
 * a host and it fails, then results from the other PcrEventLog* may not be
 * trustworthy since the event log integrity cannot be verified -- that is it
 * can contain any list of modules and we don't know if it's accurate (and must
 * assume it isn't).
 *
 *
 * @author dtiwari
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PcrEventLogIntegrity extends PcrRule {
    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PcrEventLogIntegrity.class);
    private DigestAlgorithm pcrBank;
    protected PcrIndex pcrIndex;

    protected PcrEventLogIntegrity() {
    } // for desearializing jackson

    public PcrEventLogIntegrity(Pcr expected) {
        this.expected = expected;
        this.pcrIndex = expected.getIndex();
    }

    @Override
    public RuleResult apply(HostManifest hostManifest) {
        RuleResult report = new RuleResult(this);
        if (hostManifest.getPcrManifest() == null) {
            report.fault(new PcrManifestMissing());
        } else {
            Pcr actualValue = hostManifest.getPcrManifest().getPcr(expected.getPcrBank(), expected.getIndex());
            if (actualValue == null) {
                report.fault(new PcrValueMissing(pcrIndex));
            } else {
                PcrEventLog eventLog = hostManifest.getPcrManifest().getPcrEventLog(expected.getPcrBank(), expected.getIndex());
                if (eventLog == null) {
                    report.fault(new PcrEventLogMissing(pcrIndex));
                } else {
                    List<Measurement> measurements = eventLog.getEventLog();
                    if (measurements != null) {
                        AbstractDigest expectedValue = computeHistory(measurements, expected.getPcrBank()); // calculate expected' based on history
                        log.debug("PcrEventLogIntegrity: About to compare {} with {}.", actualValue.getValue().toString(), expectedValue.toString());
                        // make sure the expected pcr value matches the actual pcr value
                        if (!expectedValue.equals(actualValue.getValue())) {
                            report.fault(new PcrEventLogInvalid(expected.getIndex()));
                        }
                    }
                }
            }
        }
        return report;
    }

    private AbstractDigest computeHistory(List<Measurement> list, DigestAlgorithm bank) {
        // start with a default value of zero...  that should be the initial value of every PCR ..  if a pcr is reset after boot the tpm usually sets its starting value at -1 so the end result is different , which we could then catch here when the hashes don't match
        AbstractDigest result = bank == DigestAlgorithm.SHA256 ? new Sha256Digest(new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) : Sha1Digest.ZERO;
        for (Measurement m : list) {
            log.debug("computeHistory: About to extend {} with {}.", result.toString(), m.getValue().toString());
            //result = result.extend(m.getValue());
            if (bank == DigestAlgorithm.SHA256) {
                result = ((Sha256Digest) result).extend(m.getValue().toByteArray());
            } else {
                result = ((Sha1Digest) result).extend(m.getValue().toByteArray());
            }
            log.debug("computeHistory: Result of extension is {}.", result.toString());
        }
        return result;
    }
    
    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof PcrEventLogIntegrity)) {
            return false;
        }
        PcrEventLogIntegrity rule = (PcrEventLogIntegrity) o;
        return Objects.equals(markers, rule.markers)
                && Objects.equals(expected.getPcrBank(), rule.pcrBank)
                && Objects.equals(expected.getIndex(), rule.pcrIndex);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(markers, pcrBank, pcrIndex);
    }
}
