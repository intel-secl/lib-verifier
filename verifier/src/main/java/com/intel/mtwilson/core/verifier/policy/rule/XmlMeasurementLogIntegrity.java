/*
 * Copyright (C) 2018 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.intel.dcsg.cpg.crypto.AbstractDigest;
import com.intel.dcsg.cpg.crypto.DigestAlgorithm;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.dcsg.cpg.crypto.Sha384Digest;
import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.mtwilson.core.common.model.Measurement;
import com.intel.mtwilson.core.common.model.PcrEventLog;
import com.intel.mtwilson.core.common.model.PcrIndex;
import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.core.verifier.policy.BaseRule;
import com.intel.mtwilson.core.verifier.policy.RuleResult;

import com.intel.mtwilson.core.verifier.policy.fault.PcrEventLogMissing;
import com.intel.mtwilson.core.verifier.policy.fault.XmlMeasurementLogInvalid;
import com.intel.mtwilson.core.verifier.policy.fault.XmlMeasurementLogMissing;
import com.intel.mtwilson.core.verifier.policy.fault.XmlMeasurementValueMismatch;
import com.intel.mtwilson.core.verifier.policy.utils.HostManifestUtils;
import com.intel.wml.measurement.xml.MeasurementType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.intel.mtwilson.core.common.model.SoftwareFlavorPrefix;


/**
 * This policy verifies the integrity of the measurement log provided by the host. It does
 * this integrity verification by calculating the expected final hash value by extending
 * all the modules measured in the exact same order and comparing it with the static
 * tbootxm module in the whitelist.
 *
 * @author ddhawale
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class XmlMeasurementLogIntegrity extends BaseRule {
    private Logger log = LoggerFactory.getLogger(getClass());
    public static final String SWAGGER_BASE_UUID_REGEX = "\\p{XDigit}{8}-\\p{XDigit}{4}-\\p{XDigit}{4}-\\p{XDigit}{4}-\\p{XDigit}{12}";
    private String flavorId;
    private String flavorName;
    private String expectedValue;

    protected XmlMeasurementLogIntegrity() {
    }

    public XmlMeasurementLogIntegrity(Flavor expected) {
        this.flavorId = expected.getMeta().getId();
        this.flavorName = expected.getMeta().getDescription().getLabel();
        this.expectedValue = expected.getSoftware().getCumulativeHash();
    }

    public String getFlavorId() {
        return flavorId;
    }

    public String getFlavorName() {
        return flavorName;
    }

    public String getExpectedValue() {
        return expectedValue;
    }

    @Override
    public RuleResult apply(HostManifest hostManifest) {
        log.debug("XmlMeasurementLogIntegrity: About to apply the XmlMeasurementLogIntegrity policy");
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
                List<MeasurementType> measurements = measurement.getMeasurements();
                log.debug("XmlMeasurementLogIntegrity: Retrieved #{} of measurements from the log.", measurements.size());
                if (measurements.size() > 0) {
                    DigestAlgorithm finalDigestAlgorithm = DigestAlgorithm.SHA384;
                    AbstractDigest expectedValueDigest = Sha384Digest.valueOfHex(expectedValue);
                    AbstractDigest actualDigestInMeasurement = Sha384Digest.valueOfHex(measurement.getCumulativeHash().getValue());
                    AbstractDigest actualValue = computeHistory(measurements);

                    try {
                        if (!expectedDigestMatchesWithDigestInEventLog(expectedValueDigest, hostManifest)) {
                            log.info("XmlMeasurementLogIntegrity: Mismatch in the expected cumulative hash value present in flavor and the value present in the PCR Event log.");
                            report.fault(XmlMeasurementValueMismatch.newInstance(finalDigestAlgorithm, expectedValueDigest, actualDigestInMeasurement));
                            return report;
                        }
                    } catch (RuntimeException re) {
                        if (re.getMessage().equals("PcrEventLog missing")) {
                            report.fault(new PcrEventLogMissing(PcrIndex.PCR15));
                            return report;
                        }
                    }
                    if (!expectedValueDigest.equals(actualDigestInMeasurement)) {
                        log.info("XmlMeasurementLogIntegrity: Mismatch in the expected cumulative hash value present in flavor and the cumulative value present in the XML Measurement log.");
                        report.fault(XmlMeasurementValueMismatch.newInstance(finalDigestAlgorithm, expectedValueDigest, actualDigestInMeasurement));
                        return report;
                    }
                    if (!expectedValueDigest.equals(actualValue)) {
                        log.info("XmlMeasurementLogIntegrity: Mismatch in the expected cumulative hash value present in flavor and final evaluated cumulative hash value from the XML Measurement log.");
                        report.fault(XmlMeasurementValueMismatch.newInstance(finalDigestAlgorithm, expectedValueDigest, actualValue));
                        return report;
                    }
                    log.debug("Verified the integrity of the XML measurement log successfully.");
                }
            }
        }
        report.setFlavorId(flavorId);
        return report;
    }

    private boolean expectedDigestMatchesWithDigestInEventLog(AbstractDigest expectedValueDigest, HostManifest hostManifest) {
        AbstractDigest actualDigestInEventLog = getMeasurementFromEventlog(flavorId, flavorName, hostManifest);
        if(actualDigestInEventLog == null) {
            return false;
        }

        String tpmVersion = hostManifest.getHostInfo().getTpmVersion();
        if (tpmVersion != null && tpmVersion.equals("1.2")) {
            expectedValueDigest = Sha1Digest.digestOf(expectedValueDigest.toByteArray());
        }
        return expectedValueDigest.equals(actualDigestInEventLog);
    }

    private Sha384Digest computeHistory(List<MeasurementType> list) {
        Sha384Digest result = Sha384Digest.ZERO;
        for (MeasurementType m : list) {
            if (m.getValue() != null) {
                log.debug("XmlMeasurementLogIntegrity-computeHistory: Extending value [{}] to current value [{}]", m.getValue(), result.toString());
                result = result.extend(Sha384Digest.valueOfHex(m.getValue()));
            }
        }
        return result;
    }

    private AbstractDigest getMeasurementFromEventlog(String flavorId, String flavorLabel, HostManifest hostManifest) {
        DigestAlgorithm digestAlgorithm = getDigestAlgorithmFromTpmVersion(hostManifest.getHostInfo().getTpmVersion());
        PcrEventLog pcrEventLog = hostManifest.getPcrManifest().getPcrEventLog(digestAlgorithm, PcrIndex.PCR15);
        if (pcrEventLog == null) {
            throw new RuntimeException("PcrEventLog missing");
        }
        for (Object m : pcrEventLog.getEventLog()) {
            com.intel.mtwilson.core.common.model.Measurement measurement = (com.intel.mtwilson.core.common.model.Measurement) m;
            if(flavorIdExistsInEventName(flavorId, measurement)) {
                return measurement.getValue();
            }
            if((flavorLabel.contains(SoftwareFlavorPrefix.DEFAULT_APPLICATION_FLAVOR_PREFIX.getValue()) 
                    || flavorLabel.contains(SoftwareFlavorPrefix.DEFAULT_WORKLOAD_FLAVOR_PREFIX.getValue()))
                    && flavorLabelExistsInEventName(flavorLabel, measurement)) {
                return measurement.getValue();
            }
        }
        return null;
    }

    private boolean flavorIdExistsInEventName(String flavorId, Measurement measurement) {
        Pattern pairRegex = Pattern.compile(SWAGGER_BASE_UUID_REGEX);
        Matcher matcher = pairRegex.matcher(measurement.getLabel());
        while (matcher.find()) {
            String a = matcher.group(0);
            if(flavorId.equals(a)) {
                return true;
            }
        }
        return false;
    }

    private boolean flavorLabelExistsInEventName(String flavorLabel, Measurement measurement) {
        return measurement.getLabel().startsWith(flavorLabel);
    }

    private DigestAlgorithm getDigestAlgorithmFromTpmVersion(String tpmVersion) {
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA1;
        if (tpmVersion != null && tpmVersion.equals("2.0")) {
            digestAlgorithm = DigestAlgorithm.SHA384;
        }
        return digestAlgorithm;
    }
}
