/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import com.intel.mtwilson.core.common.model.HostManifest;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class BaseRule implements Rule {

    protected String[] markers = null;

    @Override
    abstract public RuleResult apply(HostManifest hostManifest);

    @Override
    public String[] getMarkers() {
        return markers;
    }

    public void setMarkers(String... markers) {
        this.markers = markers;
    }
}
