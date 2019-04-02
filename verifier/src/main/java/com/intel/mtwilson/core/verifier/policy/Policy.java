/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * A policy is a collection of rules; all must be met in order to comply with the policy.
 * 
 * Each host typically has ONE policy (whitelist) associated with it, that contains rules
 * for trusted platform, trusted vmm, and trusted location, and possibly other customer-defined
 * rules.
 * 
 * It's also possible to define one or more additional policies (whitelists) for a given host
 * so that it is trusted if it meets any one of the policies. This is typically used during
 * an upgrade procedure, where hosts are scheduled for platform/vmm upgrades and the new version
 * they are being upgraded to is added as an authorized policy to each host, so that there is
 * no trust-related downtime surrounding an upgrade... host is immediately trusted after it
 * reboots with the new software.  Administrators then go back and remove the old trusted 
 * policy after upgrading the hosts.
 * 
 * The Policy object doesn't need any logic - all the rules are conjuncted (AND) together by
 * definition. The PolicyEngine applies the host report to each rule and collects the results.
 * 
 * The Rule instances themselves contain the results. 
 * 
 * @author dtiwari
 * @since  IAT 1.0
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class Policy {
    private final String name;
    private final Set<Rule> rules;
    
    public Policy(String name, Rule... ruleArray) {
        this.name = name;
        this.rules = new HashSet<>(Arrays.asList(ruleArray));
    }
    
    public Policy(String name, Set<Rule> ruleset) {
        this.name = name;
        this.rules = new HashSet<>(ruleset);
    }
    
    public String getName() { return name; }
    public Set<Rule> getRules() { return rules; }
}
