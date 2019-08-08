/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy;

import com.intel.mtwilson.core.flavor.model.Flavor;

import com.intel.mtwilson.core.flavor.model.SignedFlavor;
import com.intel.mtwilson.core.verifier.policy.vendor.*;
import com.intel.mtwilson.core.common.model.HostInfo;
import com.intel.mtwilson.core.common.model.HostManifest;

import java.util.HashMap;
import java.util.Map;

/**
 * This class selects the appropriate TrustPolicy Reader based on the Flavor
 * vendor
 *
 * @author dtiwari
 * @since IAT 1.0
 */
public class HostTrustPolicyManager {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(HostTrustPolicyManager.class);
    private final Map<String, VendorTrustPolicyReader> vendorFactoryMap = new HashMap();
    Flavor flavor;
    HostManifest hostManifest;
    SignedFlavor signedFlavor;

    public HostTrustPolicyManager(SignedFlavor signedFlavor, HostManifest hostManifest, String privacyCaCertificatepath, String assetTagCaCertificatepath, String flavorSigningCertificatePath, Boolean skipFlavorSignatureVerification) {
        this.signedFlavor = signedFlavor;
        this.hostManifest = hostManifest;
        vendorFactoryMap.put("intel", new IntelHostTrustPolicyReader(signedFlavor, privacyCaCertificatepath, assetTagCaCertificatepath, flavorSigningCertificatePath, skipFlavorSignatureVerification));
        vendorFactoryMap.put("intel-da", new IntelTpmDaHostTrustPolicyReader(signedFlavor, privacyCaCertificatepath, assetTagCaCertificatepath, flavorSigningCertificatePath, skipFlavorSignatureVerification));
        vendorFactoryMap.put("microsoft", new MicrosoftHostTrustPolicyReader(signedFlavor, privacyCaCertificatepath, assetTagCaCertificatepath, flavorSigningCertificatePath, skipFlavorSignatureVerification));
        vendorFactoryMap.put("microsoft-da", new MicrosoftHostTrustPolicyReader(signedFlavor, privacyCaCertificatepath, assetTagCaCertificatepath, flavorSigningCertificatePath, skipFlavorSignatureVerification));
        vendorFactoryMap.put("vmware", new VmwareHostTrustPolicyReader(signedFlavor, privacyCaCertificatepath, assetTagCaCertificatepath, flavorSigningCertificatePath, skipFlavorSignatureVerification));
        vendorFactoryMap.put("vmware-da", new VmwareDaHostTrustPolicyReader(signedFlavor, privacyCaCertificatepath, assetTagCaCertificatepath, flavorSigningCertificatePath, skipFlavorSignatureVerification));
    }

    /**
     *
     * This method delegates to vendor-specific reader/factories for the work of
     * instantiating the Rules
     *
     * @return Appropriate Host Trust Policy Reader
     */
    public VendorTrustPolicyReader getVendorTrustPolicyReader() {
        try {
            String vendorKey;
            String tpmVersion;

            // get vendorKey from flavor metadata, check hostManifest if it is null, or is not valid (negative test cases, like fakeVendorId)
            if (flavor != null && flavor.getMeta() != null
                    && flavor.getMeta().getVendor() != null
                    && vendorFactoryMap.containsKey(flavor.getMeta().getVendor())) {
                vendorKey = flavor.getMeta().getVendor();
            } else {
                vendorKey = getVendorName(hostManifest.getHostInfo());
            }
            log.debug("Selected Policy Reader:" + vendorKey);
            // get tpmVersion from flavor metadata's description, check hostManifest if it is null
            if (flavor != null && flavor.getMeta() != null && flavor.getMeta().getDescription() != null
                    && flavor.getMeta().getDescription().getTpmVersion() != null) {
                tpmVersion = flavor.getMeta().getDescription().getTpmVersion();
            } else {
                tpmVersion = hostManifest.getHostInfo().getTpmVersion();
            }
            if("2.0".equalsIgnoreCase(tpmVersion)) {
                vendorKey += "-da";
            }
            log.debug("Selected Policy Reader:" + vendorKey);
            VendorTrustPolicyReader factory = vendorFactoryMap.get(vendorKey.toLowerCase());
            if (factory != null) {
                return factory;
            }
        } catch (Exception e) {
            log.error("Unable to select a Trust Policy Reader", e);
        }
        throw new UnsupportedOperationException("No policy reader registered for this flavor");
    }

    private static String getVendorName(HostInfo hostInfo) {
        String vendor;
        switch (hostInfo.getOsName().trim().toUpperCase()) {
            case "REDHATENTERPRISESERVER":
            case "RHEL":
            case "UBUNTU":
                vendor = "INTEL";
                break;
            case "WINDOWS":
            case "MICROSOFT WINDOWS SERVER 2016 DATACENTER":
            case "MICROSOFT WINDOWS SERVER 2016 STANDARD":
                vendor = "MICROSOFT";
                break;
            case "VMWARE ESXI":
                vendor = "VMWARE";
                break;
            default:
                vendor = "UNKNOWN";
        }
        return vendor;
    }
}
