/*
 * Copyright (C) 2018 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import com.intel.dcsg.cpg.crypto.DigestAlgorithm;
import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.core.verifier.policy.BaseRule;
import com.intel.mtwilson.core.verifier.policy.RuleResult;

import com.intel.mtwilson.core.common.model.HostManifest;

import com.intel.mtwilson.core.verifier.policy.fault.*;
import com.intel.mtwilson.core.verifier.policy.utils.HostManifestUtils;
import com.intel.mtwilson.core.common.utils.MeasurementUtils;
import com.intel.wml.measurement.xml.Measurement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.util.Objects;

/**
 * The XmlMeasurementsDigestEquals policy enforces that a Digest Algorithm specified in
 * flavor is consistent with Digest Algorithm of all measurements retrieved from Host.
 *
 * For example, "Flavor {DigestAlgorithm} must equal to {DigestAlgorithm} of all measurements"
 *
 * @author ddhawale
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class XmlMeasurementsDigestEquals extends BaseRule {
    private Logger log = LoggerFactory.getLogger(getClass());
    private Flavor expected;

    @JsonCreator
    protected XmlMeasurementsDigestEquals() {
    }

    public XmlMeasurementsDigestEquals(Flavor expected) {
        this.expected = expected;
    }

    @Override
    public RuleResult apply(HostManifest hostManifest) {
        RuleResult report = new RuleResult(this);
        if (HostManifestUtils.isMeasurementMissing(hostManifest)) {
            log.debug("HostManifest.PcrManifest XML measurements are not present");
            report.fault(new XmlMeasurementLogMissing(expected.getMeta().getId()));
        } else {
            try {
                DigestAlgorithm pcrDigestAlg = expected.getMeta().getDescription().getDigestAlgorithm();
                String digestAlgorithm = pcrDigestAlg.name();
                boolean faultsFound = false;
                for(String measurementXml : hostManifest.getPcrManifest().getMeasurementXmls()) {
                    Measurement measurement = MeasurementUtils.parseMeasurementXML(measurementXml);
                    if(!digestAlgorithm.equals(measurement.getDigestAlg())) {
                        faultsFound = true;
                        log.debug("XML measurement log for flavor's algorithm does not match with measurement's algorithm");
                        report.fault(new XmlMeasurementsDigestValueMismatch(expected.getMeta().getId(), digestAlgorithm, measurement.getUuid(), measurement.getDigestAlg()));
                    }
                }
                if(!faultsFound) {
                    log.debug("Verified the digest algorithms of the XML measurements successfully.");
                }
            } catch (IOException | JAXBException | XMLStreamException e) {
                log.debug("Unable to parse one of the measurement present in HostManifest");
                report.fault(new XmlMeasurementLogInvalid());
            }
        }
        report.setFlavorId(expected.getMeta().getId());
        return report;
    }

    @Override
    public String toString() {
        return "Expected XML measurements digest algorithms should match with flavor";
    }
}