package com.intel.mtwilson.core.verifier.policy.utils;

import com.intel.mtwilson.core.common.model.HardwareFeature;
import com.intel.mtwilson.core.common.model.HostInfo;
import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.mtwilson.core.common.utils.MeasurementUtils;
import com.intel.wml.measurement.xml.Measurement;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;

import static com.intel.mtwilson.core.flavor.SoftwareFlavor.DEFAULT_FLAVOR_PREFIX;

public class HostManifestUtils {
    public static boolean isMeasurementMissing(HostManifest hostManifest) {
        return (hostManifest.getPcrManifest() == null || hostManifest.getPcrManifest().getMeasurementXmls() == null
                || hostManifest.getPcrManifest().getMeasurementXmls().size() == 0);
    }

    public static Measurement getMeasurementAssociatedWithFlavor(String flavorId, String flavorLabel, HostManifest hostManifest) throws JAXBException, IOException, XMLStreamException {
        for(String measurementXml : hostManifest.getPcrManifest().getMeasurementXmls()) {
            Measurement measurement = MeasurementUtils.parseMeasurementXML(measurementXml);
            if(measurement.getUuid().equals(flavorId)) {
                return measurement;
            }
            if(flavorLabel.startsWith(DEFAULT_FLAVOR_PREFIX) && measurement.getLabel().equals(flavorLabel)) {
                return measurement;
            }
        }
        return null;
    }
}
