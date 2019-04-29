/*
 * Copyright (C) 2018 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.core.verifier.policy.BaseRule;
import com.intel.mtwilson.core.verifier.policy.RuleResult;
import com.intel.mtwilson.core.verifier.policy.fault.*;
import com.intel.mtwilson.core.verifier.policy.utils.HostManifestUtils;
import com.intel.wml.measurement.xml.MeasurementType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;


/**
 * The functionality of this policy is to verify the whitelist measurement log against what is provided by the host during host attestation.
 * Need to ensure that there are no additional modules or any modules missing. Also the digest value of all the modules are matching.
 * <p>
 *
 * @author ddhawale
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class XmlMeasurementLogEquals extends BaseRule {
    private Logger log = LoggerFactory.getLogger(getClass());
    private String flavorId;
    private String flavorName;
    private List<MeasurementType> expectedMeasurements;

    protected XmlMeasurementLogEquals() {
    }

    public XmlMeasurementLogEquals(Flavor expected) {
        this.flavorId = expected.getMeta().getId();
        this.flavorName = expected.getMeta().getDescription().getLabel();
        this.expectedMeasurements = new ArrayList<>(expected.getSoftware().getMeasurements().values());
    }

    public List<MeasurementType> getExpectedMeasurements() {
        return expectedMeasurements;
    }

    public String getFlavorId() {
        return flavorId;
    }

    public String getFlavorName() {
        return flavorName;
    }

    @Override
    public RuleResult apply(HostManifest hostManifest) {
        log.debug("XmlMeasurementLogEquals: About to apply the XmlMeasurementLogEquals policy");
        RuleResult report = new RuleResult(this);
        if (HostManifestUtils.isMeasurementMissing(hostManifest)) {
            report.fault(new XmlMeasurementLogMissing(flavorId));
        } else {
            com.intel.wml.measurement.xml.Measurement measurement = null;
            try {
                measurement = HostManifestUtils.getMeasurementAssociatedWithFlavor(flavorId, flavorName, hostManifest);
            } catch (JAXBException | IOException | XMLStreamException e) {
                report.fault(new XmlMeasurementLogInvalid());
            }
            if (measurement == null) {
                report.fault(new XmlMeasurementLogMissing(flavorId));
            } else {
                List<MeasurementType> actualModules = measurement.getMeasurements();
                log.debug("XmlMeasurementLogEquals: About to apply the XmlMeasurementLogEquals policy for {} entries.", actualModules.size());

                if (actualModules.isEmpty()) {
                    report.fault(new XmlMeasurementLogMissing(flavorId));
                } else {
                    ArrayList<MeasurementType> hostActualUnexpected = new ArrayList<>(actualModules);
                    hostActualUnexpected = removeAll(hostActualUnexpected, expectedMeasurements);

                    ArrayList<MeasurementType> hostActualMissing = new ArrayList<>(expectedMeasurements);
                    log.debug("XmlMeasurementLogEquals: About to check host entries {} against the whitelist which has {} entries.",
                            actualModules.size(), hostActualMissing.size());
                    hostActualMissing = removeAll(hostActualMissing, actualModules);

                    raiseFaultForModifiedEntries(hostActualUnexpected, hostActualMissing, report);

                    if (!hostActualUnexpected.isEmpty()) {
                        log.debug("XmlMeasurementLogEquals : Host is having #{} additional modules compared to the white list.", hostActualUnexpected.size());
                        report.fault(new XmlMeasurementLogContainsUnexpectedEntries(flavorId, hostActualUnexpected));
                    } else {
                        log.debug("XmlMeasurementLogEquals: Host is not having any additional modules compared to the white list");
                    }

                    if (!hostActualMissing.isEmpty()) {
                        log.debug("XmlMeasurementLogEquals : Host is missing #{} modules compared to the white list.", hostActualMissing.size());
                        report.fault(new XmlMeasurementLogMissingExpectedEntries(flavorId, new HashSet<>(hostActualMissing)));
                    } else {
                        log.debug("XmlMeasurementLogEquals: Host is not missing any modules compared to the white list");
                    }
                }
            }
        }
        report.setFlavorId(flavorId);
        return report;
    }

    private void raiseFaultForModifiedEntries(ArrayList<MeasurementType> hostActualUnexpected, ArrayList<MeasurementType> hostActualMissing, RuleResult report) {
        ArrayList<MeasurementType> hostModifiedModules = new ArrayList<>();
        ArrayList<MeasurementType> tempHostActualUnexpected = new ArrayList<>(hostActualUnexpected);
        ArrayList<MeasurementType> tempHostActualMissing = new ArrayList<>(hostActualMissing);

        try {
            for (MeasurementType tempUnexpected : tempHostActualUnexpected) {
                for (MeasurementType tempMissing : tempHostActualMissing) {
                    log.debug("RaiseFaultForModifiedEntries: Comparing module {} with hash {} to module {} with hash {}.", tempUnexpected.getPath(),
                            tempUnexpected.getValue(), tempMissing.getPath(), tempMissing.getValue());
                    if (tempUnexpected.getPath().equalsIgnoreCase(tempMissing.getPath())) {
                        log.debug("Adding the entry to the list of modified modules and deleting from the other 2 lists.");
                        hostModifiedModules.add(tempMissing);
                        hostActualUnexpected.remove(tempUnexpected);
                        hostActualMissing.remove(tempMissing);
                    }
                }
            }

            if (!hostModifiedModules.isEmpty()) {
                log.debug("XmlMeasurementLogEquals : Host has updated #{} modules compared to the white list.", hostModifiedModules.size());
                report.fault(new XmlMeasurementLogValueMismatchEntries(flavorId, new HashSet<>(hostModifiedModules)));
            } else {
                log.debug("RaiseFaultForModifiedEntries: No updated modules found.");
            }
        } catch (Exception ex) {
            log.error("RaiseFaultForModifiedEntries: Error during verification of changed modules.", ex);
        }
    }

    private ArrayList<MeasurementType> removeAll(List<MeasurementType> firstList, List<MeasurementType> secondList) {
        ArrayList<MeasurementType> result = new ArrayList<>();
        for(MeasurementType f :firstList) {
            boolean present = false;
            for(MeasurementType s:secondList) {
                if(equalMeasurementTypes(f,s)) {
                    present = true;
                    break;
                }
            }
            if(!present) {
                result.add(f);
            }
        }
        return result;
    }

    private boolean equalMeasurementTypes(MeasurementType first, MeasurementType second) {
        return first.getValue().equals(second.getValue());
    }
}