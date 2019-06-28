/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.intel.dcsg.cpg.crypto.AbstractDigest;
import com.intel.dcsg.cpg.crypto.DigestAlgorithm;
import com.intel.dcsg.cpg.crypto.Sha384Digest;
import com.intel.mtwilson.core.verifier.policy.Fault;

/**
 *
 * @author ddhawale
 * @param <T>
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS,
              include = JsonTypeInfo.As.PROPERTY,
              property = "digest_type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = XmlMeasurementValueMismatchSha384.class)
})
public abstract class XmlMeasurementValueMismatch<T extends AbstractDigest> extends Fault {
    private T expectedValue;
    private T actualValue;
    
    public XmlMeasurementValueMismatch() { }
    
    protected XmlMeasurementValueMismatch(T expectedValue, T actualValue) {
        super("Host XML measurement log final hash with value %s does not match expected value %s", actualValue.toString(), expectedValue.toString());
        this.expectedValue = expectedValue;
        this.actualValue = actualValue;
    }

    public static XmlMeasurementValueMismatch newInstance(DigestAlgorithm bank, AbstractDigest expectedValue, AbstractDigest actualValue) {
        switch(bank) {
            case SHA384:
                return new XmlMeasurementValueMismatchSha384((Sha384Digest)expectedValue, (Sha384Digest)actualValue);
            default:
                throw new UnsupportedOperationException("Not supported yet");
        }
    }

    public T getExpectedValue() { return expectedValue; }
    public T getActualValue() { return actualValue; }
}
