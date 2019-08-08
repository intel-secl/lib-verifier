/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.utils;

import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.util.ResourceFinder;
import org.apache.commons.io.IOUtils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

public class FlavorUtils {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(FlavorUtils.class);

    public static boolean isTbootInstalled(Flavor flavor) {
        return flavor.getMeta().getDescription().getTbootInstalled() == null || Boolean.valueOf(flavor.getMeta().getDescription().getTbootInstalled());
    }

    public static boolean verifyFlavorSignature(String flavor, String signatureString, String flavorSigningCertPath) {
        boolean isVerified;
        try (InputStream privacyCaIn = new FileInputStream(ResourceFinder.getFile(flavorSigningCertPath))) {
            List<X509Certificate> flavorSigningCertificates = X509Util.decodePemCertificates(IOUtils.toString(privacyCaIn));
            Signature signature = Signature.getInstance("SHA384withRSA");
            signature.initVerify(flavorSigningCertificates.get(0));
            signature.update(flavor.getBytes());
            isVerified = signature.verify(Base64.getDecoder().decode(signatureString));
        }
        catch (IOException exc) {
            log.error("Error reading certificate chain from flavor-signer certificate file: ", exc.fillInStackTrace());
            return false;
        }
        catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException exc) {
            log.error("Error verifying signature: ", exc.fillInStackTrace());
            return false;
        }

        return isVerified;
    }
}
