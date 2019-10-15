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
 * Trust Policy for Microsoft Platform(Host) with TPM 1.2 and 2.0 chip
 *
 * @author dtiwari
 * @since IAT 1.0
 */
public class MicrosoftHostTrustPolicyReader implements VendorTrustPolicyReader {

    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MicrosoftHostTrustPolicyReader.class);
    private final Flavor flavor;
    private final String privacyCaCertificatepath;
    private final String assetTagCaCertificatepath;
    private final String flavorSigningCertificatePath;
    private final String flavorCaCertPath;
    private final Boolean skipFlavorSignatureVerification;
    private final SignedFlavor signedFlavor;

    public MicrosoftHostTrustPolicyReader(SignedFlavor signedFlavor, String privacyCaCertificatepath, String assetTagCaCertificatepath, String flavorSigningCertificatePath, String flavorCaCertPath, Boolean skipFlavorSignatureVerification) {
        this.flavor = signedFlavor.getFlavor();
        this.privacyCaCertificatepath = privacyCaCertificatepath;
        this.assetTagCaCertificatepath = assetTagCaCertificatepath;
        this.flavorSigningCertificatePath = flavorSigningCertificatePath;
        this.flavorCaCertPath = flavorCaCertPath;
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
            trustrules.addAll(TrustRulesHolder.loadFlavorIntegrityTrustRules(signedFlavor, flavortype, flavorSigningCertificatePath, flavorCaCertPath));
        }
        return new Policy("Microsoft Host Trust Policy", trustrules);
    }

    /**
     * Prepare Trust rules for PLATFORM Flavor
     *
     * Rules: 
     * - AIK Verification
     * - PcrMatchesConstant rule for PCR 0
     *
     * @return Set of rules
     */
    private Set<Rule> loadTrustRulesForPlatform() {
        HashSet<Rule> rules = new HashSet<>();

        // Verify AIK Certificate
        Set<Rule> AikCertificateTrustedRule = VendorTrustPolicyRules.createAikCertificateTrustedRules(FlavorPart.PLATFORM.getValue(), privacyCaCertificatepath);
        rules.addAll(AikCertificateTrustedRule);

        // Verify PLATFORM
        Set<Rule> pcrMatchesConstantRules = VendorTrustPolicyRules.createPcrMatchesConstantRules(flavor.getPcrs(), Arrays.asList(0), TrustMarker.PLATFORM.getValue());
        rules.addAll(pcrMatchesConstantRules);

        log.debug("Created Trust rules for PLATFORM");

        return rules;
    }

    /**
     * Prepare Trust rules for OS Flavor
     *
     * Rules: 
     * - AIK Verification
     * - PcrMatchesConstant rule for PCR 13
     * - PcrMatchesConstant rule for PCR 14
     *
     * @return Set of rules
     */
    private Set<Rule> loadTrustRulesForOS() {
        HashSet<Rule> rules = new HashSet<>();

        // Verify AIK Certificate
        Set<Rule> AikCertificateTrustedRule = VendorTrustPolicyRules.createAikCertificateTrustedRules(FlavorPart.OS.getValue(), privacyCaCertificatepath);
        rules.addAll(AikCertificateTrustedRule);

        // Verify OS
        Set<Rule> pcrMatchesConstantRules = VendorTrustPolicyRules.createPcrMatchesConstantRules(flavor.getPcrs(), Arrays.asList(13, 14), TrustMarker.OS.getValue());
        rules.addAll(pcrMatchesConstantRules);

        log.debug("Created Trust rules for OS");

        return rules;
    }

    /**
     * Prepare Trust rules for Host Unique Flavor
     *
     * Note: Commented out the below rule as Windows don't support the 
     * HostUnique flavor. Not removing the method or call to this method as this
     * will be a placeholder for future rules.
     * 
     * Rules: 
     * - AIK Verification 
     *
     * @return Set of rules
     */
    private Set<Rule> loadTrustRulesForHostUnique() {
        HashSet<Rule> rules = new HashSet<>();

        // Verify AIK Certificate 
        //Set<Rule> AikCertificateTrustedRule = VendorTrustPolicyRules.createAikCertificateTrustedRules(FlavorPart.HOST_UNIQUE.getValue(), privacyCaCertificatepath);
        //rules.addAll(AikCertificateTrustedRule);

        log.debug("Created Trust rules for HOST_UNIQUE");

        return rules;
    }

    /**
     * Prepare trust rules for Asset Tag
     *
     * Rules: 
     * - TagCertificateTrusted rule 
     * - AssetTagMatches rule
     *
     * @return Set of rules
     */
    private Set<Rule> loadTrustRulesForAssetTag() {
        HashSet<Rule> rules = new HashSet<>();

        if (flavor.getExternal() == null)
            return rules;
        
        // Verify Asset Tag
        Set<Rule> tagCertificateTrustedRules = VendorTrustPolicyRules.createTagCertificateTrustedRules(flavor, assetTagCaCertificatepath);
        rules.addAll(tagCertificateTrustedRules);

        Set<Rule> tagAssetTagMacthesRules = VendorTrustPolicyRules.createAssetTagMacthesRules(flavor);
        rules.addAll(tagAssetTagMacthesRules);

        log.debug("Created Trust rules for ASSET_TAG");

        return rules;
    }
}