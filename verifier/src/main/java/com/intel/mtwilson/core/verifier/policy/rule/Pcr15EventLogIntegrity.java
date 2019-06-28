/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.dcsg.cpg.crypto.DigestAlgorithm;
import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.mtwilson.core.common.model.PcrIndex;
import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.core.verifier.policy.RuleResult;

/**
 * This policy extends PcrEventLogIntegrity to evaluate PCR 14 integrity
 *
 * @author ddhawale
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Pcr15EventLogIntegrity extends PcrEventLogIntegrity {
    private String flavorId;

    public Pcr15EventLogIntegrity() {
    }

    public Pcr15EventLogIntegrity(Flavor flavor) {
        this.flavorId = flavor.getMeta().getId();
    }

    public String getFlavorId() {
        return flavorId;
    }

    @Override
    public RuleResult apply(HostManifest hostManifest) {
        super.expected = hostManifest.getPcrManifest().getPcr(getDigestAlgorithmFromTpmVersion(hostManifest.getHostInfo().getTpmVersion()), PcrIndex.PCR15);
        super.pcrIndex = expected.getIndex();
        RuleResult ruleResult = super.apply(hostManifest);
        ruleResult.setFlavorId(flavorId);
        return ruleResult;
    }

    private DigestAlgorithm getDigestAlgorithmFromTpmVersion(String tpmVersion) {
        if (isTpm2(tpmVersion))
            return DigestAlgorithm.SHA256;
        return DigestAlgorithm.SHA1;
    }

    private boolean isTpm2(String tpmVersion) {
        return tpmVersion != null && tpmVersion.equals("2.0");
    }
}
