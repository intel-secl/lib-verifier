/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.core.verifier.policy.Fault;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class FlavorSignatureNotTrusted extends Fault{

    public FlavorSignatureNotTrusted() { } // for deserializing jackson

    public FlavorSignatureNotTrusted(Flavor flavor) {super("Signature is not trusted for flavor with id %s", flavor.getMeta().getId());}
}
