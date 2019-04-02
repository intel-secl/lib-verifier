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

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PcrEventLogContainsUnexpectedEntries extends Fault {

    private PcrIndex pcrIndex;
    private List<Measurement> unexpectedEntries;

    public PcrEventLogContainsUnexpectedEntries() {
    } // for desearializing jackson

    public PcrEventLogContainsUnexpectedEntries(PcrIndex pcrIndex, List<Measurement> unexpectedEntries) {
        super("Module manifest for PCR %d contains %d unexpected entries", pcrIndex.toInteger(), unexpectedEntries.size());
        this.pcrIndex = pcrIndex;
        this.unexpectedEntries = unexpectedEntries;
    }

    public PcrIndex getPcrIndex() {
        return pcrIndex;
    }

    public List<Measurement> getUnexpectedEntries() {
        return unexpectedEntries;
    }
}
