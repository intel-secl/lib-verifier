/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.vendor;

import com.intel.mtwilson.core.flavor.common.FlavorPart;
import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.core.flavor.model.SignedFlavor;
import com.intel.mtwilson.core.verifier.policy.Policy;

import com.intel.mtwilson.core.verifier.policy.Rule;
import com.intel.mtwilson.core.verifier.policy.TrustMarker;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Trust Policy for VMware Platform(Host) with TPM 1.2 chip
 *
 * @author dtiwari
 * @since  IAT 1.0
 */
public class VmwareHostTrustPolicyReader implements VendorTrustPolicyReader {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(VmwareHostTrustPolicyReader.class);
    protected final Flavor flavor;
    protected final String privacyCaCertificatepath; //TODO(dtiwari): Remove this variable as it is not being used like other Vendors ?
    protected final String assetTagCaCertificatepath;
    protected final String flavorSigningCertificatePath;
    private final Boolean skipFlavorSignatureVerification;
    private final SignedFlavor signedFlavor;


    public VmwareHostTrustPolicyReader(SignedFlavor signedFlavor, String privacyCaCertificatepath, String assetTagCaCertificatepath, String flavorSigningCertificatePath, Boolean skipFlavorSignatureVerification) {
        this.flavor = signedFlavor.getFlavor();
        this.privacyCaCertificatepath = privacyCaCertificatepath;
        this.assetTagCaCertificatepath = assetTagCaCertificatepath;
        this.flavorSigningCertificatePath = flavorSigningCertificatePath;
        this.signedFlavor = signedFlavor;
        this.skipFlavorSignatureVerification = skipFlavorSignatureVerification;

    }

    @Override
    public Policy loadTrustRules() {
        String flavortype = flavor.getMeta().getDescription().getFlavorPart().toUpperCase();
        Set<Rule> trustrules = new HashSet<>();
        log.debug("Flavor Type for Trust rules creation is {}", flavortype);

        switch (FlavorPart.valueOf(flavortype)) {
            case PLATFORM:
                trustrules.addAll(loadTrustRulesForPlatform());
                break;
            case OS:
                trustrules.addAll(loadTrustRulesForOS());
                break;
            case HOST_UNIQUE:
                trustrules.addAll(loadTrustRulesForHostUnique());
                break;
            case ASSET_TAG:
                trustrules.addAll(loadTrustRulesForAssetTag());
                break;
            case SOFTWARE:
                trustrules.addAll(TrustRulesHolder.loadTrustRulesForSoftware(flavor));
                break;
        }
        if (!skipFlavorSignatureVerification) {
            trustrules.addAll(TrustRulesHolder.loadFlavorIntegrityTrustRules(signedFlavor, flavortype, flavorSigningCertificatePath));
        }
        return new Policy("VMware Host Trust Policy", trustrules);
    }

    /**
     * Prepare Trust rules for PLATFORM Flavor
     *
     * Rules:
     * - PcrMatchesConstant rule for PCR 0
     * - PcrMatchesConstant rule for PCR 17
     *
     * @return Set of rules
     */
    protected Set<Rule> loadTrustRulesForPlatform() {
        HashSet<Rule> rules = new HashSet<>();

        // Verify PLATFORM
        Set<Rule> pcrMatchesConstantRules = VendorTrustPolicyRules.createPcrMatchesConstantRules(flavor.getPcrs(), Arrays.asList(0, 17), TrustMarker.PLATFORM.getValue());
        rules.addAll(pcrMatchesConstantRules);

        log.debug("Created Trust rules for PLATFORM");

        return rules;
    }

    /**
     * Prepare Trust rules for OS Flavor
     *
     * Rules: 
     * - PcrMatchesConstant rule for PCR 18
     * - PcrMatchesConstant rule for PCR 20
     * - PcrEventLogEqualsExcluding rule for PCR 19
     * - PcrEventLogIntegrity rule for PCR 19
     *
     * @return Set of rules
     */
    protected Set<Rule> loadTrustRulesForOS() {
        HashSet<Rule> rules = new HashSet<>();

        // Verify OS
        Set<Rule> pcrMatchesConstantRules = VendorTrustPolicyRules.createPcrMatchesConstantRules(flavor.getPcrs(), Arrays.asList(18, 20), TrustMarker.OS.getValue());
        rules.addAll(pcrMatchesConstantRules);

        Set<Rule> pcrEventLogEqualsExcludingRules = VendorTrustPolicyRules.createPcrEventLogEqualsExcludingRules(flavor.getPcrs(), Arrays.asList(19), TrustMarker.OS.getValue());
        rules.addAll(pcrEventLogEqualsExcludingRules);
        
        Set<Rule> pcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(flavor.getPcrs(), Arrays.asList(19), TrustMarker.OS.getValue());
        rules.addAll(pcrEventLogIntegrityRules);
        
        log.debug("Created Trust rules for OS");

        return rules;
    }

    /**
     * Prepare Trust rules for Host Unique Flavor
     *
     * Rules:
     * - PcrEventLogIncludes rule for PCR 19
     * - PcrEventLogIntegrity rule for PCR 19
     *
     * @return Set of rules
     */
    protected Set<Rule> loadTrustRulesForHostUnique() {
        HashSet<Rule> rules = new HashSet<>();

        // Verify Host Unique
        Set<Rule> pcrEventLogIncludesRules = VendorTrustPolicyRules.createPcrEventLogIncludesRules(flavor.getPcrs(), Arrays.asList(19), TrustMarker.HOST_UNIQUE.getValue());
        rules.addAll(pcrEventLogIncludesRules);
        
        Set<Rule> pcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(flavor.getPcrs(), Arrays.asList(19), TrustMarker.HOST_UNIQUE.getValue());
        rules.addAll(pcrEventLogIntegrityRules);
        
        log.debug("Created Trust rules for HOST_UNIQUE");

        return rules;
    }
    
    /**
     * Prepare trust rules for Asset Tag
     *
     * Rules: 
     * - TagCertificateTrusted rule
     * - PcrMatchesConstant rule for PCR 22
     *
     * @return Set of rules
     */
    protected Set<Rule> loadTrustRulesForAssetTag() {
        HashSet<Rule> rules = new HashSet<>();

        if (flavor.getExternal() == null)
            return rules;
        
        // Verify Asset Tag
        Set<Rule> tagCertificateTrustedRules = VendorTrustPolicyRules.createTagCertificateTrustedRules(flavor, assetTagCaCertificatepath);
        rules.addAll(tagCertificateTrustedRules);

        Set<Rule> pcrMatchesConstantRules = VendorTrustPolicyRules.createPcrMatchesConstantRules(flavor.getPcrs(), Arrays.asList(22), TrustMarker.ASSET_TAG.getValue());
        rules.addAll(pcrMatchesConstantRules);
        
        log.debug("Created Trust rules for ASSET_TAG");

        return rules;
    }
}
