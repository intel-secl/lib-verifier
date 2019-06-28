/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.vendor;

import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.core.verifier.policy.Rule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

public class TrustRulesHolder {
    private static Logger log = LoggerFactory.getLogger(TrustRulesHolder.class);

    /**
     * Prepare trust rules for Software
     *
     * Rules:
     *
     * @return  Set of rules
     */
    public static Set<Rule> loadTrustRulesForSoftware(Flavor flavor) {
        HashSet<Rule> rules = new HashSet<>();
        if (flavor.getSoftware() == null)
            return rules;

        // Verify Software
        Set<Rule> softwareRules = VendorTrustPolicyRules.createSoftwareRules(flavor);
        rules.addAll(softwareRules);
        log.debug("Created Trust rules for SOFTWARE");
        return rules;
    }
}
