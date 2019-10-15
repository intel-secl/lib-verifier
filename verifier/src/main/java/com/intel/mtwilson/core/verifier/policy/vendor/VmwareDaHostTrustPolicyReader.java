/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.vendor;

import com.intel.mtwilson.core.flavor.model.SignedFlavor;
import com.intel.mtwilson.core.verifier.policy.Rule;
import com.intel.mtwilson.core.verifier.policy.TrustMarker;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class VmwareDaHostTrustPolicyReader extends VmwareHostTrustPolicyReader {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(VmwareDaHostTrustPolicyReader.class);
    public VmwareDaHostTrustPolicyReader(SignedFlavor signedFlavor, String privacyCaCertificatepath, String assetTagCaCertificatepath, String flavorSigningCertificatePath, String flavorCaCertPath, Boolean skipFlavorVerify) {
        super(signedFlavor, privacyCaCertificatepath, assetTagCaCertificatepath, flavorSigningCertificatePath, flavorCaCertPath, skipFlavorVerify);
    }

    @Override
    protected Set<Rule> loadTrustRulesForPlatform() {
        HashSet<Rule> rules = new HashSet<>();

        // Verify PLATFORM
        Set<Rule> pcrMatchesConstantRules = VendorTrustPolicyRules.createPcrMatchesConstantRules(flavor.getPcrs(), Arrays.asList(0, 17, 18), TrustMarker.PLATFORM.name());
        rules.addAll(pcrMatchesConstantRules);

        Set<Rule> pcrEventLogEqualsRules = VendorTrustPolicyRules.createPcrEventLogEqualsRules(flavor.getPcrs(), Arrays.asList(17, 18), TrustMarker.PLATFORM.name());
        rules.addAll(pcrEventLogEqualsRules);

        Set<Rule> pcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(flavor.getPcrs(), Arrays.asList(17, 18), TrustMarker.PLATFORM.name());
        rules.addAll(pcrEventLogIntegrityRules);

        log.debug("Created Trust rules for PLATFORM");

        return rules;
    }

    @Override
    protected Set<Rule> loadTrustRulesForOS() {
        HashSet<Rule> rules = new HashSet<>();


        // Verify OS

        Set<Rule> pcrMatchesConstantRules = VendorTrustPolicyRules.createPcrMatchesConstantRules(flavor.getPcrs(), Arrays.asList(19), TrustMarker.OS.name());
        rules.addAll(pcrMatchesConstantRules);

        Set<Rule> pcrEventLogEqualsRules = VendorTrustPolicyRules.createPcrEventLogEqualsRules(flavor.getPcrs(), Arrays.asList(19), TrustMarker.OS.name());
        rules.addAll(pcrEventLogEqualsRules);

        Set<Rule> pcrEventLogExcludingRules = VendorTrustPolicyRules.createPcrEventLogEqualsExcludingRules(flavor.getPcrs(), Arrays.asList(20, 21), TrustMarker.OS.name());
        rules.addAll(pcrEventLogExcludingRules);

        Set<Rule> pcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(flavor.getPcrs(), Arrays.asList(19, 20, 21), TrustMarker.OS.name());
        rules.addAll(pcrEventLogIntegrityRules);

        log.debug("Created Trust rules for OS");

        return rules;
    }

    @Override
    protected Set<Rule> loadTrustRulesForHostUnique() {
        HashSet<Rule> rules = new HashSet<>();

        // Verify Host Unique
        Set<Rule> PcrEventLogIncludesRules = VendorTrustPolicyRules.createPcrEventLogIncludesRules(flavor.getPcrs(), Arrays.asList(20,21), TrustMarker.HOST_UNIQUE.name());
        rules.addAll(PcrEventLogIncludesRules);

        Set<Rule> PcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(flavor.getPcrs(), Arrays.asList(20, 21), TrustMarker.HOST_UNIQUE.name());
        rules.addAll(PcrEventLogIntegrityRules);

        log.debug("Created Trust rules for HOST_UNIQUE");

        return rules;
    }

}
