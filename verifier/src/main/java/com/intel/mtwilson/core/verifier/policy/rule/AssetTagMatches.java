/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import com.intel.mtwilson.core.verifier.policy.BaseRule;
import com.intel.mtwilson.core.verifier.policy.RuleResult;

import com.intel.mtwilson.core.common.model.HostManifest;

import java.util.Arrays;
import java.util.Map;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The PcrMatchesConstant policy enforces that a specific PCR contains a
 * specific pre-determined constant value. This is typical for values that are
 * known in advance such as PLATFORM or trusted module measurements.
 *
 * For example, "PCR {index} must equal {hex-value}"
 *
 * @author dtiwari
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class AssetTagMatches extends BaseRule {

    private Logger log = LoggerFactory.getLogger(getClass());
    private final byte[] expected;
    private final Map<String, String> tags;

    @JsonCreator
    public AssetTagMatches(@JsonProperty("expected_tag") byte[] expected, @JsonProperty("expected_tag_kv") Map<String, String> tags) {
        this.expected = expected;
        this.tags = tags;
    }

    public byte[] getExpectedTag() {
        return expected;
    }

    public Map<String, String> getTags(){
        return tags;
    }
    
    @Override
    public RuleResult apply(HostManifest hostManifest) {
        RuleResult report = new RuleResult(this);
        if (hostManifest.getAssetTagDigest() == null) {
            log.debug("HostManifest getAssetTagDigest is null");
            report.fault("AssetTag Reported is null");
        } else if (expected == null) {
            log.debug("Expected Assettag is null");
            report.fault("AssetTag is not in provisionded by the management");
        } else {
            log.debug("assetTagReported is {}, expected is {}", Hex.encodeHexString(hostManifest.getAssetTagDigest()), Hex.encodeHexString(expected));
            if (!Arrays.equals(expected, hostManifest.getAssetTagDigest())) {
                log.debug("assetTagReported: {}, NOT equal to expected: {}", Hex.encodeHexString(hostManifest.getAssetTagDigest()), Hex.encodeHexString(expected));
                report.fault("Asset tag provisioned does not match asset tag reported");
            }
        }
        return report;
    }

    @Override
    public String toString() {
        return String.format("Expected tag is: %s", expected.toString());
    }


    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AssetTagMatches other = (AssetTagMatches) obj;
        if (!Arrays.equals(this.expected, other.expected)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(expected);
    }
}
