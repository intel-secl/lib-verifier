package com.intel.mtwilson.core.verifier.policy.utils;

import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.mtwilson.core.common.utils.MeasurementUtils;
import com.intel.wml.measurement.xml.Measurement;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import com.intel.mtwilson.core.common.model.SoftwareFlavorPrefix;

public class HostManifestUtils {
    public static boolean isMeasurementMissing(HostManifest hostManifest) {
        return (hostManifest.getPcrManifest() == null || hostManifest.getPcrManifest().getMeasurementXmls() == null
                || hostManifest.getPcrManifest().getMeasurementXmls().isEmpty());
    }

    public static Measurement getMeasurementAssociatedWithFlavor(String flavorId, String flavorLabel, HostManifest hostManifest) throws JAXBException, IOException, XMLStreamException {
        for(String measurementXml : hostManifest.getPcrManifest().getMeasurementXmls()) {
            Measurement measurement = MeasurementUtils.parseMeasurementXML(measurementXml);
            if(measurement.getUuid().equals(flavorId)) {
                return measurement;
            }
            if((flavorLabel.contains(SoftwareFlavorPrefix.DEFAULT_APPLICATION_FLAVOR_PREFIX.getValue())
                    || flavorLabel.contains(SoftwareFlavorPrefix.DEFAULT_WORKLOAD_FLAVOR_PREFIX.getValue()))
                    && measurement.getLabel().equals(flavorLabel)) {
                return measurement;
            }
        }
        return null;
    }
}
