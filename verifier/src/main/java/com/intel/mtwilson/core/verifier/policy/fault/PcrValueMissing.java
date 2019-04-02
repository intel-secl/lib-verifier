/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import com.intel.mtwilson.core.verifier.policy.Fault;

import com.intel.mtwilson.core.common.model.PcrIndex;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PcrValueMissing extends Fault {

    private PcrIndex missingPcrIndex;

    public PcrValueMissing() {
    } // for desearializing jackson

    public PcrValueMissing(PcrIndex missingPcrIndex) {
        super("Host report does not include required PCR %d", missingPcrIndex.toInteger());
        this.missingPcrIndex = missingPcrIndex;
    }

    public PcrIndex getPcrIndex() {
        return missingPcrIndex;
    }
}
