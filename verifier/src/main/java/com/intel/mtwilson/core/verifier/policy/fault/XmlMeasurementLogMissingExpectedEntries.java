/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
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
public class XmlMeasurementLogMissingExpectedEntries extends Fault {
    private String flavorId;
    private Set<MeasurementType> missingEntries;

    public XmlMeasurementLogMissingExpectedEntries() {
        missingEntries = new HashSet<>();
    } // for desearializing jackson
    
    public XmlMeasurementLogMissingExpectedEntries(String flavorId, Set<MeasurementType> missingEntries) {
        super("XML measurement log for flavor %s missing %d expected entries", flavorId, missingEntries.size());
        this.flavorId = flavorId;
        this.missingEntries = missingEntries;
    }

    public String getFlavorId() {
        return flavorId;
    }

    public Set<MeasurementType> getMissingEntries() {
        return missingEntries;
    }
}
