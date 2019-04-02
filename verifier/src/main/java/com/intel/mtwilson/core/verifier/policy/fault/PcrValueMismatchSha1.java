/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import com.intel.dcsg.cpg.crypto.Sha1Digest;

import com.intel.mtwilson.core.common.model.PcrIndex;

public class PcrValueMismatchSha1 extends PcrValueMismatch<Sha1Digest> {

    public PcrValueMismatchSha1(PcrIndex pcrIndex, Sha1Digest expectedValue, Sha1Digest actualValue) {
        super(pcrIndex, expectedValue, actualValue);
    }

    @JsonCreator
    public PcrValueMismatchSha1(@JsonProperty("pcr_index") PcrIndex pcrIndex, @JsonProperty("expected_value") String expectedValue, @JsonProperty("actual_value") String actualValue) {
        super(pcrIndex, new Sha1Digest(expectedValue), new Sha1Digest(actualValue));
    }
}
