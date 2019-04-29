/*
 * Copyright (C) 2018 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.mtwilson.core.verifier.policy.Fault;

/**
 *
 * @author ddhawale
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class XmlMeasurementsDigestValueMismatch extends Fault {
    private String flavorId;
    private String flavorDigestAlg;
    private String measurementId;
    private String measurementDigestAlg;

    public XmlMeasurementsDigestValueMismatch() {
    }

    public XmlMeasurementsDigestValueMismatch(String flavorId, String flavorDigestAlg, String measurementId, String measurementDigestAlg) {
        super("XML measurement log for flavor %s has %s algorithm does not match with measurement %s - %s algorithm.",
                flavorId, flavorDigestAlg, measurementId, measurementDigestAlg);
        this.flavorId = flavorId;
        this.flavorDigestAlg = flavorDigestAlg;
        this.measurementId = measurementId;
        this.measurementDigestAlg = measurementDigestAlg;
    }

    public String getFlavorId() {
        return flavorId;
    }

    public String getFlavorDigestAlg() {
        return flavorDigestAlg;
    }

    public String getMeasurementId() {
        return measurementId;
    }

    public String getMeasurementDigestAlg() {
        return measurementDigestAlg;
    }
}
