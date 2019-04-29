/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy;

/**
 * A list of well-known markers to use when generating trust policies
 *
 * @author dtiwari
 */
public enum TrustMarker {
    PLATFORM("PLATFORM"),
    OS("OS"),
    HOST_UNIQUE("HOST_UNIQUE"),
    ASSET_TAG("ASSET_TAG"),
    SOFTWARE("SOFTWARE");

    private String value;

    TrustMarker(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
