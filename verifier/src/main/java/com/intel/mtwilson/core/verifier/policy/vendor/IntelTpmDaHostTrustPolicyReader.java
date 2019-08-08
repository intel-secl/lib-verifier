/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.vendor;

import com.intel.mtwilson.core.common.model.BootGuardProfile;
import com.intel.mtwilson.core.common.model.PcrIndex;
import com.intel.mtwilson.core.flavor.common.FlavorPart;
import com.intel.mtwilson.core.flavor.model.Flavor;

import com.intel.mtwilson.core.flavor.model.PcrEx;
import com.intel.mtwilson.core.flavor.model.SignedFlavor;
import com.intel.mtwilson.core.verifier.policy.Policy;
import com.intel.mtwilson.core.verifier.policy.Rule;
import com.intel.mtwilson.core.verifier.policy.TrustMarker;

import java.util.*;

import static com.intel.mtwilson.core.verifier.policy.utils.FlavorUtils.isTbootInstalled;

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
    private final String flavorSigningCertificatePath;
    private final Boolean skipFlavorSignatureVerification;
    private final SignedFlavor signedFlavor;

    public IntelTpmDaHostTrustPolicyReader(SignedFlavor signedFlavor, String privacyCaCertificatepath, String assetTagCaCertificatepath, String flavorSigningCertificatePath, Boolean skipFlavorSignatureVerification) {
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
        Set<Rule> aikCertificateTrustedRules = VendorTrustPolicyRules.createAikCertificateTrustedRules(FlavorPart.PLATFORM.getValue(), privacyCaCertificatepath);
        rules.addAll(aikCertificateTrustedRules);

        // Verify PLATFORM
        Set<Integer> pcrIndexSet = new HashSet<>();
        pcrIndexSet.add(0);
        pcrIndexSet.addAll(getCbntPcrs(flavor));
        pcrIndexSet.addAll(getSuefiPcrs(flavor));
        Set<Rule> pcrMatchesConstantRules = VendorTrustPolicyRules.createPcrMatchesConstantRules(flavor.getPcrs(), new ArrayList<>(pcrIndexSet), TrustMarker.PLATFORM.getValue());
        rules.addAll(pcrMatchesConstantRules);
        
        Set<Rule> pcrEventLogEqualsExcludingRules = VendorTrustPolicyRules.createPcrEventLogEqualsExcludingRules(flavor.getPcrs(), Arrays.asList(17, 18), TrustMarker.PLATFORM.getValue());
        rules.addAll(pcrEventLogEqualsExcludingRules);

//        Set<Rule> pcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(removeLabels(flavor.getPcrs(), Arrays.asList(17, 18), biosLogIncludesLabels), Arrays.asList(17, 18), TrustMarker.PLATFORM.getValue());
        if(isTbootInstalled(flavor)) {
            Set<Rule> pcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(flavor.getPcrs(), Arrays.asList(17, 18), TrustMarker.PLATFORM.getValue());
            rules.addAll(pcrEventLogIntegrityRules);
        }
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
        Set<Rule> AikCertificateTrustedRule = VendorTrustPolicyRules.createAikCertificateTrustedRules(FlavorPart.OS.getValue(), privacyCaCertificatepath);
        rules.addAll(AikCertificateTrustedRule);

        // Verify OS
        if(isTbootInstalled(flavor)) {
            Set<Rule> pcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(flavor.getPcrs(), Arrays.asList(17), TrustMarker.OS.getValue());
            rules.addAll(pcrEventLogIntegrityRules);
        }

        //Set<Rule> pcrEventLogIncludesRules = VendorTrustPolicyRules.createPcrEventLogIncludesRules(removeLabels(flavor.getPcrs(), Arrays.asList(17), osLogIncludeLables), Arrays.asList(17), TrustMarker.OS.getValue());
        Set<Rule> pcrEventLogIncludesRules = VendorTrustPolicyRules.createPcrEventLogIncludesRules(flavor.getPcrs(), Arrays.asList(17), TrustMarker.OS.getValue());
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
        Set<Rule> AikCertificateTrustedRule = VendorTrustPolicyRules.createAikCertificateTrustedRules(FlavorPart.HOST_UNIQUE.getValue(), privacyCaCertificatepath);
        rules.addAll(AikCertificateTrustedRule);

        // Verify Host Unique
        //Set<Rule> PcrEventLogIncludesRules = VendorTrustPolicyRules.createPcrEventLogIncludesRules(removeLabels(flavor.getPcrs(), Arrays.asList(17, 18), hostUniqueLogIncludeLabels), Arrays.asList(17, 18), TrustMarker.HOST_UNIQUE.getValue());
        Set<Rule> PcrEventLogIncludesRules = VendorTrustPolicyRules.createPcrEventLogIncludesRules(flavor.getPcrs(), Arrays.asList(17, 18), TrustMarker.HOST_UNIQUE.getValue());
        rules.addAll(PcrEventLogIncludesRules);

        if(isTbootInstalled(flavor)) {
            Set<Rule> PcrEventLogIntegrityRules = VendorTrustPolicyRules.createPcrEventLogIntegrityRules(flavor.getPcrs(), Arrays.asList(17, 18), TrustMarker.HOST_UNIQUE.getValue());
            rules.addAll(PcrEventLogIntegrityRules);
        }

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

    private static List<Integer> getCbntPcrs(Flavor flavor) {
        List<Integer> cbntPcrs = new ArrayList<>();
        if(flavor.getHardware().getFeature().getCBNT() != null &&
                flavor.getHardware().getFeature().getCBNT().getEnabled() &&
                flavor.getHardware().getFeature().getCBNT().getProfile().equalsIgnoreCase(BootGuardProfile.BTGP5.getName())) {
            cbntPcrs = getPcrsPresentInFlavor(flavor, Arrays.asList(7));
        }
        return cbntPcrs;
    }

    private static List<Integer> getSuefiPcrs(Flavor flavor) {
        List<Integer> cbntPcrs = new ArrayList<>();
        if(flavor.getHardware().getFeature().getSUEFI() != null && flavor.getHardware().getFeature().getSUEFI().getEnabled()) {
            cbntPcrs = getPcrsPresentInFlavor(flavor, Arrays.asList(0,1,2,3,4,5,6,7));
        }
        return cbntPcrs;
    }

    private static List<Integer> getPcrsPresentInFlavor(Flavor flavor, List<Integer> pcrs) {
        List<Integer> cbntPcrs = new ArrayList<>();
        if(pcrs.isEmpty()) {
            return cbntPcrs;
        }

        for (Map<PcrIndex, PcrEx> entry : flavor.getPcrs().values()) {
            for (PcrIndex p : entry.keySet()) {
                if (pcrs.contains(p.toInteger())) {
                    cbntPcrs.add(p.toInteger());
                }
            }
        }
        return cbntPcrs;
    }
}
