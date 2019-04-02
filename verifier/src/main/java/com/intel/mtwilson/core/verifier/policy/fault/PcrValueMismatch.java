/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import com.intel.dcsg.cpg.crypto.AbstractDigest;
import com.intel.dcsg.cpg.crypto.DigestAlgorithm;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.crypto.Sha256Digest;

import com.intel.mtwilson.core.verifier.policy.Fault;

import com.intel.mtwilson.core.common.model.PcrIndex;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class PcrValueMismatch<T extends AbstractDigest> extends Fault {

    protected PcrIndex pcrIndex;
    protected T expectedValue;
    protected T actualValue;

    protected PcrValueMismatch(PcrIndex pcrIndex, T expectedValue, T actualValue) {
        super("Host PCR %d with value %s does not match expected value %s", pcrIndex.toInteger(), actualValue.toString(), expectedValue.toString());
        this.pcrIndex = pcrIndex;
        this.expectedValue = expectedValue;
        this.actualValue = actualValue;
    }

    public static PcrValueMismatch newInstance(DigestAlgorithm bank, PcrIndex pcrIndex, AbstractDigest expectedValue, AbstractDigest actualValue) {
        switch (bank) {
            case SHA1:
                return new PcrValueMismatchSha1(pcrIndex, (Sha1Digest) expectedValue, (Sha1Digest) actualValue);
            case SHA256:
                return new PcrValueMismatchSha256(pcrIndex, (Sha256Digest) expectedValue, (Sha256Digest) actualValue);
            default:
                throw new UnsupportedOperationException("Not supported yet");
        }
    }

    public PcrIndex getPcrIndex() {
        return pcrIndex;
    }

    public T getExpectedValue() {
        return expectedValue;
    }

    public T getActualValue() {
        return actualValue;
    }
}
