/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.core.flavor.model.SignedFlavor;
import com.intel.mtwilson.core.verifier.policy.BaseRule;
import com.intel.mtwilson.core.verifier.policy.RuleResult;
import com.intel.mtwilson.core.verifier.policy.fault.FlavorSignatureMissing;
import com.intel.mtwilson.core.verifier.policy.fault.FlavorSignatureNotTrusted;
import com.intel.mtwilson.core.verifier.policy.fault.FlavorSignatureVerificationFailed;
import com.intel.mtwilson.core.verifier.policy.utils.FlavorUtils;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class FlavorTrusted extends BaseRule {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(FlavorTrusted.class);
    private SignedFlavor signedFlavor;
    private String flavorSigningCertPath;
    private String flavorCaCertPath;

    protected FlavorTrusted(){}

    public FlavorTrusted(SignedFlavor signedFlavor, String flavorSigningCertPath, String flavorCaCertPath) {
        this.signedFlavor = signedFlavor;
        this.flavorSigningCertPath = flavorSigningCertPath;
        this.flavorCaCertPath = flavorCaCertPath;
    }

    @Override
    public RuleResult apply(HostManifest hostManifest) {
        RuleResult report = new RuleResult(this);
        try {
            if (signedFlavor.getSignature() == null || signedFlavor.getSignature().isEmpty()) {
                report.fault(new FlavorSignatureMissing(signedFlavor.getFlavor()));
            } else if (!FlavorUtils.verifyFlavorTrust(Flavor.serialize(signedFlavor.getFlavor()), signedFlavor.getSignature(), flavorSigningCertPath, flavorCaCertPath)) {
                report.fault(new FlavorSignatureNotTrusted(signedFlavor.getFlavor()));
            }
        } catch (JsonProcessingException exc) {
            report.fault(exc.getMessage(), new FlavorSignatureVerificationFailed(signedFlavor.getFlavor()));
        }
        report.setFlavorId(signedFlavor.getFlavor().getMeta().getId());
        return report;
    }

    @Override
    public String toString() {
        return "Flavor is signed by trusted authority";
    }

}
