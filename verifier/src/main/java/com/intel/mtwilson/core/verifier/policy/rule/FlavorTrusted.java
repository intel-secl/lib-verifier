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
import com.intel.mtwilson.core.verifier.policy.utils.FlavorUtils;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class FlavorTrusted extends BaseRule {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AikCertificateTrusted.class);
    private SignedFlavor flavorAndSignature;

    protected FlavorTrusted(){}

    public FlavorTrusted(SignedFlavor flavorAndSignature) {
        this.flavorAndSignature = flavorAndSignature;
    }

    @Override
    public RuleResult apply(HostManifest hostManifest) {
        RuleResult report = new RuleResult(this);
        try {
            if (flavorAndSignature.getSignature() == null || flavorAndSignature.getSignature().isEmpty()) {
                report.fault(new FlavorSignatureMissing(flavorAndSignature.getFlavor()));
                report.setFlavorId(flavorAndSignature.getFlavor().getMeta().getId());
            } else if (!FlavorUtils.verifyFlavorSignature(Flavor.serialize(flavorAndSignature.getFlavor()), flavorAndSignature.getSignature())) {
                report.fault(new FlavorSignatureNotTrusted(flavorAndSignature.getFlavor()));
                report.setFlavorId(flavorAndSignature.getFlavor().getMeta().getId());
            }
        } catch (JsonProcessingException exc) {
            report.fault(new FlavorSignatureNotTrusted(flavorAndSignature.getFlavor()));
            report.setFlavorId(flavorAndSignature.getFlavor().getMeta().getId());
        }
        return report;
    }
}