/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Very similar to "ObjectModel" but purposefully does NOT implement Model
 * because the faults recorded here are not problems with THIS instance, they
 * are simply records of policy evaluations on some other instance. This class
 * is similar to com.intel.mtwilson.validation.Report but instead of reporting
 * faults on another model, faults are directly recorded here.
 *
 * So if someone turns on automatic Model checking (via aspectj) we do not want
 * the application to throw an exception when a report is passed to some method
 * just because the host represented in the report didn't meet the policy. The
 * report itself IS valid.
 *
 * For that reason, also renamed "isValid" to "isTrusted", to make it clear it's
 * not a "Model" implementation.
 *
 * @author dtiwari
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class RuleResult {

    private final transient Logger log = LoggerFactory.getLogger(getClass().getName());
    private final Rule rule;
    private final ArrayList<Fault> faults = new ArrayList<Fault>();
    private String flavorId;

    public String getFlavorId() {
        return flavorId;
    }

    public void setFlavorId(String flavorId) {
        this.flavorId = flavorId;
    }

    private RuleResult() {
        this.rule = null;
    } // for json deserialization support only

    public RuleResult(Rule rule) {
        this.rule = rule;
    }
    
    @JsonIgnore
    public final String getRuleName() {
        return rule.getClass().getName();
    }

    public final Rule getRule() {
        return rule;
    }

    public final void fault(Fault fault) {
        faults.add(fault);
    }

    public final void fault(String description) {
        faults.add(new Fault(description));
    }

    public final void fault(String format, Object... args) {
        faults.add(new Fault(format, args));
    }

    public final void fault(Throwable e, String description) {
        faults.add(new Fault(e, description));
    }

    public final void fault(Throwable e, String format, Object... args) {
        faults.add(new Fault(e, format, args));
    }

    /**
     *
     * @return a list of faults
     */
    public final List<Fault> getFaults() {
        return faults;
    }

    /**
     * @return true if the host meets the policy (host is trusted) or false if
     * there are faults - which you can access with getFaults()
     */
    public final boolean isTrusted() {
        return faults.isEmpty();
    }

}
