/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.utils;

import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.util.ResourceFinder;
import org.apache.commons.io.IOUtils;

import com.intel.mtwilson.shiro.ShiroUtil;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class FlavorUtils {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(FlavorUtils.class);

    public static boolean isTbootInstalled(Flavor flavor) {
        return flavor.getMeta().getDescription().getTbootInstalled() == null || Boolean.valueOf(flavor.getMeta().getDescription().getTbootInstalled());
    }

    public static boolean verifyFlavorTrust(String flavor, String signatureString, String flavorSigningCertPath, String flavorCaCertPath) {
        X509Certificate flavorSigningCertificate;
        ArrayList<Certificate> intermediateCas;
        ArrayList<Certificate> rootCas;

        try {
            flavorSigningCertificate = getFlavorSigningCertificate(flavorSigningCertPath);
            intermediateCas = getIntermediateCas(flavorSigningCertPath);
            rootCas = getRootCas(flavorCaCertPath);
            ShiroUtil.verifyCertificateChain(flavorSigningCertificate, rootCas, intermediateCas);
            log.debug("Successfully verified certificate chain");
        } catch (IOException exc) {
            log.error("Error reading certificate chain from flavor-signer certificate file: ", exc.fillInStackTrace());
            return false;
        } catch (GeneralSecurityException exc) {
            log.error("Error verifying signature: ", exc.fillInStackTrace());
            return false;
        }

        return verifyFlavorTrust(flavor, signatureString, flavorSigningCertificate);
    }

    private static boolean verifyFlavorTrust(String flavor, String signatureString, X509Certificate flavorSigningCertificate) {
        try {
            Signature signature = Signature.getInstance("SHA384withRSA");
            signature.initVerify(flavorSigningCertificate);
            signature.update(flavor.getBytes());
            return signature.verify(Base64.getDecoder().decode(signatureString));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException exc) {
            log.error("Error verifying signature: ", exc.fillInStackTrace());
            return false;
        }
    }

    private static X509Certificate getFlavorSigningCertificate(String flavorSigningCertPath) throws IOException, CertificateException {
        InputStream signingCert = new FileInputStream(ResourceFinder.getFile(flavorSigningCertPath));
        List<X509Certificate> flavorSigningCertificates = X509Util.decodePemCertificates(IOUtils.toString(signingCert));
        return flavorSigningCertificates.get(0);
    }

    private static ArrayList<Certificate> getIntermediateCas(String flavorSigningCertPath) throws IOException, CertificateException {
        ArrayList<Certificate> intermediateCas = new ArrayList<>();
        InputStream signingCert = new FileInputStream(ResourceFinder.getFile(flavorSigningCertPath));
        List<X509Certificate> flavorSigningCertificates = X509Util.decodePemCertificates(IOUtils.toString(signingCert));
        intermediateCas.add(flavorSigningCertificates.get(1));
        return intermediateCas;
    }

    private static ArrayList<Certificate> getRootCas(String rootCaPath) throws IOException, CertificateException {
        ArrayList <Certificate> intermediateCas = new ArrayList<>();
        InputStream rootCert = new FileInputStream(ResourceFinder.getFile(rootCaPath));
        List<X509Certificate> flavorSigningCertificates = X509Util.decodePemCertificates(IOUtils.toString(rootCert));
        intermediateCas.add(flavorSigningCertificates.get(0));
        return intermediateCas;
    }
}
