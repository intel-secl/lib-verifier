/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import com.intel.mtwilson.core.common.model.HostManifest;

import com.intel.mtwilson.core.verifier.policy.BaseRule;
import com.intel.mtwilson.core.verifier.policy.RuleResult;
import com.intel.mtwilson.core.verifier.policy.fault.AikCertificateExpired;
import com.intel.mtwilson.core.verifier.policy.fault.AikCertificateMissing;
import com.intel.mtwilson.core.verifier.policy.fault.AikCertificateNotTrusted;
import com.intel.mtwilson.core.verifier.policy.fault.AikCertificateNotYetValid;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
/**
 * 
 * @author dtiwari
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class AikCertificateTrusted extends BaseRule {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AikCertificateTrusted.class);
    private X509Certificate[] trustedAuthorityCerts;

    protected AikCertificateTrusted() {
    } // for desearializing jackson

    public AikCertificateTrusted(X509Certificate[] trustedAuthorityCerts) {
        this.trustedAuthorityCerts = trustedAuthorityCerts;
    }

    @Override
    public RuleResult apply(HostManifest hostReport) {
        RuleResult report = new RuleResult(this);
        if (hostReport.getAikCertificate() == null) {
            report.fault(new AikCertificateMissing());
        } else {
            X509Certificate hostAikCert = hostReport.getAikCertificate();
            try {
                hostAikCert.checkValidity(); // AIK certificate must be valid today
            } catch (CertificateExpiredException e) {
                report.fault(new AikCertificateExpired(hostAikCert.getNotAfter()));
            } catch (CertificateNotYetValidException e) {
                report.fault(new AikCertificateNotYetValid(hostAikCert.getNotBefore()));
            }
            boolean validCaSignature = false;
            for (int i = 0; i < trustedAuthorityCerts.length && !validCaSignature; i++) {
                X509Certificate pca = trustedAuthorityCerts[i];
                try {
                    if (Arrays.equals(pca.getSubjectX500Principal().getEncoded(), hostAikCert.getIssuerX500Principal().getEncoded())) {
                        log.debug("Found matching CA: {}", pca.getSubjectX500Principal().getName());
                        pca.checkValidity(hostAikCert.getNotBefore()); // Privacy CA certificate must have been valid when it signed the AIK certificate - if it's not valid an exception is thrown and is caught and suppressed below
                        hostAikCert.verify(pca.getPublicKey()); // verify the trusted privacy ca signed this aik cert.  throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException
                        validCaSignature = true;
                        log.debug("Verified CA signature: {}", pca.getSubjectX500Principal().getName());
                        break;
                    }
                } catch (Exception e) {
                    log.debug("Failed to verify AIK signature with CA: {}", e.getMessage()); // suppressing because maybe another cert in the list is a valid signer
                }
            }
            if (!validCaSignature) {
                report.fault(new AikCertificateNotTrusted());
            }
        }
        return report;
    }

    @Override
    public String toString() {
        return "AIK certificate is signed by trusted authority";
    }

}
