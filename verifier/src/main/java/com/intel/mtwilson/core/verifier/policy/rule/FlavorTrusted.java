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

    protected FlavorTrusted(){}

    public FlavorTrusted(SignedFlavor signedFlavor, String flavorSigningCertPath) {
        this.signedFlavor = signedFlavor;
        this.flavorSigningCertPath = flavorSigningCertPath;
    }

    @Override
    public RuleResult apply(HostManifest hostManifest) {
        RuleResult report = new RuleResult(this);
        try {
            if (signedFlavor.getSignature() == null || signedFlavor.getSignature().isEmpty()) {
                report.fault(new FlavorSignatureMissing(signedFlavor.getFlavor()));
                report.setFlavorId(signedFlavor.getFlavor().getMeta().getId());
            } else if (!FlavorUtils.verifyFlavorSignature(Flavor.serialize(signedFlavor.getFlavor()), signedFlavor.getSignature(), flavorSigningCertPath)) {
                report.fault(new FlavorSignatureNotTrusted(signedFlavor.getFlavor()));
                report.setFlavorId(signedFlavor.getFlavor().getMeta().getId());
            }
        } catch (JsonProcessingException exc) {
            report.fault(exc.getMessage(), new FlavorSignatureVerificationFailed(signedFlavor.getFlavor()));
            report.setFlavorId(signedFlavor.getFlavor().getMeta().getId());
        }
        return report;
    }
}
