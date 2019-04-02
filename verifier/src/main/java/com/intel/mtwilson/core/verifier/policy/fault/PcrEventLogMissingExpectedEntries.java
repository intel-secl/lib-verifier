/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import com.intel.mtwilson.core.verifier.policy.Fault;

import com.intel.mtwilson.core.common.model.Measurement;
import com.intel.mtwilson.core.common.model.PcrIndex;

import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PcrEventLogMissingExpectedEntries extends Fault {

    private PcrIndex pcrIndex;
    private Set<Measurement> missingEntries;

    public PcrEventLogMissingExpectedEntries() {
    } // for desearializing jackson

    public PcrEventLogMissingExpectedEntries(PcrIndex pcrIndex, Set<Measurement> missingEntries) {
        super("Module manifest for PCR %d missing %d expected entries", pcrIndex.toInteger(), missingEntries.size());
        this.pcrIndex = pcrIndex;
        this.missingEntries = missingEntries;
    }

    public PcrIndex getPcrIndex() {
        return pcrIndex;
    }

    public Set<Measurement> getMissingEntries() {
        return missingEntries;
    }
}
