/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import com.intel.mtwilson.core.verifier.policy.Fault;

import com.intel.mtwilson.core.common.model.PcrIndex;


@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PcrEventLogInvalid extends Fault {

    public PcrEventLogInvalid() {
    } // for desearializing jackson

    public PcrEventLogInvalid(PcrIndex pcrIndex) {
        super("PCR %d Event Log is invalid", pcrIndex.toInteger());
    }
}
