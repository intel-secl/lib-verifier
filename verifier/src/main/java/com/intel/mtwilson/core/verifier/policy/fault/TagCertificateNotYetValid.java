/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.mtwilson.core.verifier.policy.Fault;
import java.util.Date;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class TagCertificateNotYetValid extends Fault {
    public TagCertificateNotYetValid() { } // for desearializing jackson
    
    public TagCertificateNotYetValid(Date notBefore) {
        super("Tag certificate not valid before %s", notBefore.toString());
    }
}
