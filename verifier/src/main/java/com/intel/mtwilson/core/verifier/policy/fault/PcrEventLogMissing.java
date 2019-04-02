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
public class PcrEventLogMissing extends Fault {

    public PcrEventLogMissing() {
        super("Host report does not include a PCR Event Log");
    }

    public PcrEventLogMissing(PcrIndex pcrIndex) {
        super("Host report does not include a PCR Event Log for PCR %d", pcrIndex.toInteger());
    }
}
