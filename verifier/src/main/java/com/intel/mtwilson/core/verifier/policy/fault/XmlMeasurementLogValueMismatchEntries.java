/*
 * Copyright (C) 2018 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.mtwilson.core.verifier.policy.Fault;
import com.intel.wml.measurement.xml.MeasurementType;

import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author ddhawale
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class XmlMeasurementLogValueMismatchEntries extends Fault {
    private String flavorId;
    private Set<MeasurementType> mismatchEntries;
    
    public XmlMeasurementLogValueMismatchEntries() {
        mismatchEntries = new HashSet<>();
    } 
    
    public XmlMeasurementLogValueMismatchEntries(String flavorId, Set<MeasurementType> mismatchEntries) {
        super("XML measurement log for flavor %s contains %d entries for which the values are modified.", flavorId, mismatchEntries.size());
        this.flavorId = flavorId;
        this.mismatchEntries = mismatchEntries;
    }

    public String getFlavorId() {
        return flavorId;
    }

    public Set<MeasurementType> getMismatchEntries() { return mismatchEntries; }
}
