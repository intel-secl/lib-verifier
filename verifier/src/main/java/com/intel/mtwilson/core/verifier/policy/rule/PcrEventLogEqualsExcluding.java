/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import com.intel.mtwilson.core.common.model.Measurement;
import com.intel.mtwilson.core.common.model.PcrEventLog;
import com.intel.mtwilson.core.common.model.PcrEventLogFactory;
import com.intel.mtwilson.core.common.model.PcrIndex;
import com.intel.mtwilson.core.common.model.HostManifest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author dtiwari
 * @since IAT 1.0
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PcrEventLogEqualsExcluding extends PcrEventLogEquals {

    private Logger log = LoggerFactory.getLogger(getClass());

    private static final List<String> hostSpecificModules = Arrays.asList(new String[]{"commandLine.", "LCP_CONTROL_HASH","initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"});

    private boolean excludeHostSpecificModules = true;

    protected PcrEventLogEqualsExcluding() {
    } // for desearializing jackson

    public PcrEventLogEqualsExcluding(PcrEventLog expected) {
        super(expected);
    }

    public void setExcludeHostSpecificModules(boolean enabled) {
        excludeHostSpecificModules = enabled;
    }

    @Override
    protected PcrEventLog getPcrEventLog(HostManifest hostManifest) {
        PcrEventLog eventLog = hostManifest.getPcrManifest().getPcrEventLog(getPcrModuleManifest().getPcrBank(), getPcrModuleManifest().getPcrIndex());
        List<Measurement> modules;
        if(eventLog != null) {
             modules = eventLog.getEventLog();
        } else {
            modules = new ArrayList<>();
        }
        ArrayList<Measurement> modulesExcluding = new ArrayList<>();
        Iterator<Measurement> it = modules.iterator();
        while (it.hasNext()) {
            Measurement measurement = it.next();
            Map<String, String> mInfo = measurement.getInfo();
            log.debug(measurement.getLabel() + " :: " + measurement.getValue().toString() + " :: " + mInfo.values().toString()
                    + " :: " + mInfo.keySet().toString());
            // examin m.getInfo()  to decide if it's dynamic,   and also if excludeHostSpecificModules is true then exclude host specific modules
            if (excludeHostSpecificModules && hostSpecificModules.contains(mInfo.get("ComponentName"))) {
                log.debug("PcrEventLogEqualsExcluding - Skipping the host specific module - {}", mInfo.get("ComponentName"));
                continue;
            }
            // let us skip even the dynamic modules
            if (mInfo.get("PackageName") != null && mInfo.get("PackageName").equalsIgnoreCase("")
                    && mInfo.get("PackageVendor") != null && mInfo.get("PackageVendor").equalsIgnoreCase("")) {
                log.debug("PcrEventLogEqualsExcluding - Skipping the dynamic module - {}", mInfo.get("ComponentName"));
                continue;
            }
            // Add the module to be verified.
            modulesExcluding.add(measurement);
        }
        PcrEventLog updatedPcrEventLog = PcrEventLogFactory.newInstance(getPcrModuleManifest().getPcrBank(), getPcrModuleManifest().getPcrIndex(), modulesExcluding);
        return updatedPcrEventLog; // the new instance 
    }
}
