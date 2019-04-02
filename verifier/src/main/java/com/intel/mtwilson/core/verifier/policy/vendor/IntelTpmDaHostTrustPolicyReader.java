/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.vendor;

import com.intel.mtwilson.core.flavor.common.FlavorPart;
import com.intel.mtwilson.core.flavor.model.Flavor;

import com.intel.mtwilson.core.verifier.policy.Policy;
import com.intel.mtwilson.core.verifier.policy.Rule;
import com.intel.mtwilson.core.verifier.policy.TrustMarker;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static com.intel.mtwilson.core.flavor.common.FlavorPart.*;

/**
 * Trust Policy for Intel DA Platform(Host) with TPM 2.0 chip
 *
 * @author dtiwari
 * @version 1.0
 */
public class IntelTpmDaHostTrustPolicyReader implements VendorTrustPolicyReader {

    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(IntelHostTrustPolicyReader.class);
//    private final List<String> biosLogIncludesLabels = Arrays.asList("LCP_DETAILS_HASH", "BIOSAC_REG_DATA", "OSSINITDATA_CAP_HASH", "STM_HASH", "MLE_HASH", "NV_INFO_HASH", "tb_policy", "CPU_SCRTM_STAT", "HASH_START", "LCP_CONTROL_HASH");
//    private final List<String> osLogIncludeLables = Arrays.asList("vmlinuz");
//    private final List<String> hostUniqueLogIncludeLabels = Arrays.asList("initrd");
    private final Flavor flavor;
    private final String privacyCaCertificatepath;
    private final String assetTagCaCertificatepath;

    public IntelTpmDaHostTrustPolicyReader(Flavor flavor, String privacyCaCertificatepath, String assetTagCaCertificatepath) {
        this.flavor = flavor;
        this.privacyCaCertificatepath = privacyCaCertificatepath;
        this.assetTagCaCertificatepath = assetTagCaCertificatepath;
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
        }

        return new Policy("Intel Host Trust Policy", trustrules);
    }

    /**
     * Prepare Trust rules for PLATFORM Flavor
     *
     * Rules:
     * - AIK Verification
     * - PcrMatchesConstant rule for PCR 0
     * - PcrEventLogIncludes rule for PCR 17 (LCP_DETAILS_HASH, BIOSAC_REG_DATA,
     *    OSSINITDATA_CAP_HASH, STM_HASH, MLE_HASH, NV_INFO_HASH, tb_policy,
     *    CPU_SCRTM_STAT, HASH_START, LCP_CONTROL_HASH)
     * - PcrEventLogIntegrity rule for PCR 17
     *
     * @return Set of rules
     */
    private Set<Rule> loadTrustRulesForPlatform() {
        HashSet<Rule> rules = new HashSet<>();

        // Verify AIK Certificate
        Set<Rule> aikCertificateTrustedRules = VendorTrustPolicyRules.createAikCertificateTrustedRules(PLATFORM.getValue(), privacyCaCertificatepath);
        rules.addAll(aikCertificateTrustedRules);

        // Verify PLATFORM
        Set<Rule> pcrMatchesConstantRules = VendorTrustPolicyRules.createPcrMatchesConstantRules(flavor.getPcrs(), Arrays.asList(0), TrustMarker.PLATFORM.name());
        rules.addAll(pcrMatchesConstantRules);

        Set<Rule> pcrEventLogEqualsExcludingRules = VendorTrustPolicyRules.createPcrEventLogEqualsExcludingRules(flavor.getPcrs(), Arrays.asList(17, 18), TrustMarker.PLATFORM.name());
        rules.addAll(pcrEventLogEqualsExcludingRules);

//        Set<Rule> pcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(removeLabels(flavor.getPcrs(), Arrays.asList(17, 18), biosLogIncludesLabels), Arrays.asList(17, 18), TrustMarker.PLATFORM.name());
        Set<Rule> pcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(flavor.getPcrs(), Arrays.asList(17, 18), TrustMarker.PLATFORM.name());
        rules.addAll(pcrEventLogIntegrityRules);

        log.debug("Created Trust rules for PLATFORM");

        return rules;
    }

    /**
     * Prepare Trust rules for OS Flavor
     *
     * Rules:
     * - AIK Verification
     * - PcrEventLogIntegrity rule for PCR 17
     * - PcrEventLogIncludes rule for PCR 17
     *
     * @return Set of rules
     */
    private Set<Rule> loadTrustRulesForOS() {
        HashSet<Rule> rules = new HashSet<>();

        // Verify AIK Certificate
        Set<Rule> AikCertificateTrustedRule = VendorTrustPolicyRules.createAikCertificateTrustedRules(OS.getValue(), privacyCaCertificatepath);
        rules.addAll(AikCertificateTrustedRule);

        // Verify OS
        Set<Rule> pcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(flavor.getPcrs(), Arrays.asList(17), TrustMarker.OS.name());
        rules.addAll(pcrEventLogIntegrityRules);

        //Set<Rule> pcrEventLogIncludesRules = VendorTrustPolicyRules.createPcrEventLogIncludesRules(removeLabels(flavor.getPcrs(), Arrays.asList(17), osLogIncludeLables), Arrays.asList(17), TrustMarker.OS.name());
        Set<Rule> pcrEventLogIncludesRules = VendorTrustPolicyRules.createPcrEventLogIncludesRules(flavor.getPcrs(), Arrays.asList(17), TrustMarker.OS.name());
        rules.addAll(pcrEventLogIncludesRules);

        log.debug("Created Trust rules for OS");

        return rules;
    }

    /**
     * Prepare trust rules for Host Unique Flavor
     *
     * Rules:
     * - AIK Verification
     * - PcrEventLogIncludes rule for PCR 19
     * - PcrEventLogIntegrity rule for PCR 19
     *
     * @return Set of rules
     */
    private Set<Rule> loadTrustRulesForHostUnique() {
        HashSet<Rule> rules = new HashSet<>();

        // Verify AIK Certificate
        Set<Rule> AikCertificateTrustedRule = VendorTrustPolicyRules.createAikCertificateTrustedRules(HOST_UNIQUE.getValue(), privacyCaCertificatepath);
        rules.addAll(AikCertificateTrustedRule);

        // Verify Host Unique
        //Set<Rule> PcrEventLogIncludesRules = VendorTrustPolicyRules.createPcrEventLogIncludesRules(removeLabels(flavor.getPcrs(), Arrays.asList(17, 18), hostUniqueLogIncludeLabels), Arrays.asList(17, 18), TrustMarker.HOST_UNIQUE.name());
        Set<Rule> PcrEventLogIncludesRules = VendorTrustPolicyRules.createPcrEventLogIncludesRules(flavor.getPcrs(), Arrays.asList(17, 18), TrustMarker.HOST_UNIQUE.name());
        rules.addAll(PcrEventLogIncludesRules);

        Set<Rule> PcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(flavor.getPcrs(), Arrays.asList(17, 18), TrustMarker.HOST_UNIQUE.name());
        rules.addAll(PcrEventLogIntegrityRules);

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

    /**
     *
     *
     * @param pcrList List of PCRs along with their the Digest Bank(Algorithm),
     * value and events
     * @param pcrIndexList List of PCR index required for rules creation
     * @param eventLabels
     * @return List of PCRs along with labels removed
     */
    /*
    private Map<DigestAlgorithm, Map<PcrIndex, PcrEx>> removeLabels(Map<DigestAlgorithm, Map<PcrIndex, PcrEx>> pcrList, List<Integer> pcrIndexList, List<String> eventLabels) {
        for (DigestAlgorithm pcrDigest : pcrList.keySet()) {
            Map<PcrIndex, PcrEx> pcrs = pcrList.get(pcrDigest);
            if (pcrs.isEmpty()) {
                continue;
            }
            for (Integer index : pcrIndexList) {
                PcrEx ex = pcrs.get(new PcrIndex(index));
                ex.getEvent().removeIf((Measurement m) -> !eventLabels.contains(m.getLabel()));
            }
        }
        return pcrList;
    }
    */
}
