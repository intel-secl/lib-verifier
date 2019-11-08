/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package com.intel.mtwilson.core.verifier.policy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.mtwilson.core.common.model.Pcr;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class PcrRule extends BaseRule{
    protected Pcr expected = null;

    public Pcr getExpectedPcr() {return expected;}

    public void setExpectedPcr(Pcr expected) {this.expected = expected;}
}
