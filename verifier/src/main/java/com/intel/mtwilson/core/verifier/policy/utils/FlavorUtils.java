package com.intel.mtwilson.core.verifier.policy.utils;

import com.intel.mtwilson.core.flavor.model.Flavor;

public class FlavorUtils {
    public static boolean isTbootInstalled(Flavor flavor) {
        return flavor.getMeta().getDescription().getTbootInstalled() == null || Boolean.valueOf(flavor.getMeta().getDescription().getTbootInstalled());
    }
}
