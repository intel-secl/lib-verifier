/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.intel.dcsg.cpg.crypto.Sha384Digest;

/**
 *  *
 *   * @author ddhawale
 *    */
public class XmlMeasurementValueMismatchSha384 extends XmlMeasurementValueMismatch<Sha384Digest> {
    public XmlMeasurementValueMismatchSha384() {
    }

    public XmlMeasurementValueMismatchSha384(Sha384Digest expectedValue, Sha384Digest actualValue) {
        super(expectedValue, actualValue);
    }
    
    @JsonCreator
    public XmlMeasurementValueMismatchSha384(@JsonProperty("expected_value") String expectedValue, @JsonProperty("actual_value") String actualValue) {
        super(new Sha384Digest(expectedValue), new Sha384Digest(actualValue));
    }
}

