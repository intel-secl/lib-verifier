/*
 * Copyright (C) 2018 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.core.verifier.policy.fault;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.mtwilson.core.verifier.policy.Fault;
import com.intel.wml.measurement.xml.MeasurementType;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author ddhawale
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class XmlMeasurementLogContainsUnexpectedEntries extends Fault {
    private String flavorId;
    private List<MeasurementType> unexpectedEntries;

    public XmlMeasurementLogContainsUnexpectedEntries() {
        unexpectedEntries = new ArrayList<MeasurementType>() {};
    }
    
    public XmlMeasurementLogContainsUnexpectedEntries(String flavorId, List<MeasurementType> unexpectedEntries) {
        super("XML measurement log of flavor %s contains %d unexpected entries", flavorId, unexpectedEntries.size());
        this.flavorId = flavorId;
        this.unexpectedEntries = unexpectedEntries;
    }

    public String getFlavorId() {
        return flavorId;
    }

    public List<MeasurementType> getUnexpectedEntries() { return unexpectedEntries; }
}
