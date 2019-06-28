/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.utils;

import com.intel.mtwilson.core.flavor.model.Flavor;

public class FlavorUtils {
    public static boolean isTbootInstalled(Flavor flavor) {
        return flavor.getMeta().getDescription().getTbootInstalled() == null || Boolean.valueOf(flavor.getMeta().getDescription().getTbootInstalled());
    }
}
