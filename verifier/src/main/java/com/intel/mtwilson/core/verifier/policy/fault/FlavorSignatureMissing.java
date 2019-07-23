package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.core.verifier.policy.Fault;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class FlavorSignatureMissing extends Fault {

    public FlavorSignatureMissing() { } // for desearializing jackson

    public FlavorSignatureMissing(Flavor flavor) {super("Signature is missing for flavor with id %s", flavor.getMeta().getId());}
}
