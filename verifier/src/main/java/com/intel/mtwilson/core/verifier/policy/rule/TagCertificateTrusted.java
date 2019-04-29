/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.rule;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import com.intel.mtwilson.core.verifier.policy.BaseRule;
import com.intel.mtwilson.core.verifier.policy.RuleResult;
import com.intel.mtwilson.core.verifier.policy.fault.TagCertificateExpired;
import com.intel.mtwilson.core.verifier.policy.fault.TagCertificateMissing;
import com.intel.mtwilson.core.verifier.policy.fault.TagCertificateNotTrusted;
import com.intel.mtwilson.core.verifier.policy.fault.TagCertificateNotYetValid;

import com.intel.mtwilson.core.common.model.HostManifest;
import com.intel.mtwilson.core.common.tag.model.X509AttributeCertificate;

import java.security.cert.X509Certificate;
import java.util.Date;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class TagCertificateTrusted extends BaseRule {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TagCertificateTrusted.class);
    private X509Certificate[] trustedAuthorityCerts;
    private X509AttributeCertificate x509AttributeCertificate;

    protected TagCertificateTrusted() {
    } // for desearializing jackson

    public TagCertificateTrusted(X509Certificate[] trustedAuthorityCerts, X509AttributeCertificate x509AttributeCertificate) {
        this.trustedAuthorityCerts = trustedAuthorityCerts;
        this.x509AttributeCertificate = x509AttributeCertificate;
    }

    @Override
    public RuleResult apply(HostManifest hostManifest) {
        RuleResult report = new RuleResult(this);
        if (x509AttributeCertificate == null) {
            log.debug("Tag certificate is NULL");
            report.fault(new TagCertificateMissing());
        } else {
            Date today = new Date();
            boolean validCaSignature = false;
            for (int i = 0; i < trustedAuthorityCerts.length && !validCaSignature; i++) {
                X509Certificate ca = trustedAuthorityCerts[i];
                try {
                    if (x509AttributeCertificate.getIssuer().equalsIgnoreCase(ca.getIssuerX500Principal().getName())) {
                        if (x509AttributeCertificate.isValid(ca)) {
                            // NOTE:  CA certificate must be valid for the start date and end date of the tag certificate's validity - we don't let a CA generate certs for a period when the CA itself is expired.
                            //        if this rule is too strict in practice we can remove it
                            log.debug("Verifying CA start date : {} with tag certificate start date : {}", ca.getNotBefore(), x509AttributeCertificate.getNotBefore());
                            ca.checkValidity(x509AttributeCertificate.getNotBefore());
                            log.debug("Verifying CA end date : {} with tag certificate end date : {}", ca.getNotAfter(), x509AttributeCertificate.getNotAfter());
                            ca.checkValidity(x509AttributeCertificate.getNotAfter());
                            validCaSignature = true;
                        } else {
                            log.debug("TagCertificate is not valid");
                        }
                    } else {
                        log.debug("Issuer name mismatch : {} vs {}", x509AttributeCertificate.getIssuer(), ca.getIssuerX500Principal().getName());
                    }
                } catch (Exception e) { //CertificateExpiredException | CertificateNotYetValidException e) {
                    log.debug("Failed to verify tag signature with CA: {}", e.getMessage()); // suppressing because maybe another cert in the list is a valid signer
                }
            }
            if (!validCaSignature) {
                log.debug("Adding fault for invalid tagcertificate");
                report.fault(new TagCertificateNotTrusted());
            } else {
                // we found a trusted ca and validated the tag certificate; now check the validity period of the tag certificate
                if (today.before(x509AttributeCertificate.getNotBefore())) {
                    log.debug("Adding fault for tagCertificate not yet valid");
                    report.fault(new TagCertificateNotYetValid(x509AttributeCertificate.getNotBefore()));

                }
                if (today.after(x509AttributeCertificate.getNotAfter())) {
                    log.debug("Adding fault for tagCertificate already expired");
                    report.fault(new TagCertificateExpired(x509AttributeCertificate.getNotAfter()));
                }
            }
        }
        return report;
    }

    @Override
    public String toString() {
        return "AIK certificate is signed by trusted authority";
    }
}
