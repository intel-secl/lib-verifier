/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.vendor;

import com.intel.dcsg.cpg.crypto.DigestAlgorithm;
import com.intel.dcsg.cpg.crypto.Sha384Digest;
import com.intel.dcsg.cpg.x509.X509Util;

import com.intel.mtwilson.core.flavor.model.Flavor;
import com.intel.mtwilson.core.flavor.model.PcrEx;

import com.intel.mtwilson.core.verifier.policy.BaseRule;
import com.intel.mtwilson.core.verifier.policy.Rule;
import com.intel.mtwilson.core.verifier.policy.TrustMarker;
import com.intel.mtwilson.core.verifier.policy.rule.*;

import com.intel.mtwilson.core.common.model.Measurement;
import com.intel.mtwilson.core.common.model.PcrEventLogFactory;
import com.intel.mtwilson.core.common.model.PcrFactory;
import com.intel.mtwilson.core.common.model.PcrIndex;
import com.intel.mtwilson.core.common.model.x509.UTF8NameValueMicroformat;
import com.intel.mtwilson.core.common.model.x509.UTF8NameValueSequence;

import com.intel.mtwilson.util.ResourceFinder;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.IOUtils;

/**
 * Factory to create Trust rules
 *
 * @author dtiwari
 */
public class VendorTrustPolicyRules {
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(VendorTrustPolicyRules.class);
    private static final String DUMMY_PCR256_DIGEST = "057367afa72d572655ab6fa21ac7ce7922fb364557f5225de70308c65d4e85d3";
    /**
     * Check AIK Certificate is signed by trusted Privacy CA
     *
     * @param privacyCaCertificatepath  File path of Asset Tag CA Certificate
     * @return  List of Privacy CA certificates
     */
    private static X509Certificate[] loadTrustedAikCertificateAuthorities(String privacyCaCertificatepath) {
        HashSet<X509Certificate> pcaList = new HashSet<>();
        try (InputStream privacyCaIn = new FileInputStream(ResourceFinder.getFile(privacyCaCertificatepath))) {
            List<X509Certificate> privacyCaCerts = X509Util.decodePemCertificates(IOUtils.toString(privacyCaIn));
            pcaList.addAll(privacyCaCerts);
            //IOUtils.closeQuietly(privacyCaIn);
            log.debug("Added {} certificates from PrivacyCA.list.pem", privacyCaCerts.size());
        } catch (Exception ex) {
            log.error("Cannot load PrivacyCA.list.pem", ex);
        }

        try (InputStream privacyCaIn = new FileInputStream(ResourceFinder.getFile(privacyCaCertificatepath))) {
            X509Certificate privacyCaCert = X509Util.decodeDerCertificate(IOUtils.toByteArray(privacyCaIn));
            pcaList.add(privacyCaCert);
            //IOUtils.closeQuietly(privacyCaIn);
            log.debug("Added certificate from PrivacyCA.pem");
        } catch (Exception ex) {
            log.error("Cannot load PrivacyCA.pem", ex);
        }
        X509Certificate[] cas = pcaList.toArray(new X509Certificate[0]);
        return cas;
    }

    /**
     * Create AikCertificateTrusted Trust rule
     *
     * @param flavorPart  Type of Flavor(PLATFORM, OS, HOST_UNIQUE etc.)
     * @param privacyCaCertificatepath  File path of Asset Tag CA Certificate
     * @return  Set of AikCertificateTrusted Rules
     */
    public static Set<Rule> createAikCertificateTrustedRules(String flavorPart, String privacyCaCertificatepath) {
        HashSet<Rule> rules = new HashSet<>();
        X509Certificate[]  cacerts = loadTrustedAikCertificateAuthorities(privacyCaCertificatepath);
        AikCertificateTrusted aikcert = new AikCertificateTrusted(cacerts);
        aikcert.setMarkers(TrustMarker.valueOf(flavorPart).name());
        rules.add(aikcert);
        return rules;
    }
    
    
    /**
     * Create TagCertificateTrusted Trust rules for Flavor Type
     *
     * @param flavor  Flavor
     * @param assetTagCaCertificatepath  File path of Asset Tag CA Certificate
     * @return  Set of TagCertificateTrusted rules
     */
    public static Set<Rule> createTagCertificateTrustedRules(Flavor flavor, String assetTagCaCertificatepath) {
        HashSet<Rule> rules = new HashSet<>();

        // load the tag cacerts and create the tag trust rule  
        try (FileInputStream in = new FileInputStream(assetTagCaCertificatepath)) {
            String text = IOUtils.toString(in);
            List<X509Certificate> tagAuthorities = X509Util.decodePemCertificates(text);                        
            TagCertificateTrusted tagTrustedRule; 
            //fix bug#1294. need to check if getExternal is null 
            if (flavor.getExternal() != null && flavor.getExternal().getAssetTag() != null)
                tagTrustedRule = new TagCertificateTrusted(tagAuthorities.toArray(new X509Certificate[0]), flavor.getExternal().getAssetTag().getTagCertificate());
            else
                tagTrustedRule = new TagCertificateTrusted(tagAuthorities.toArray(new X509Certificate[0]), null);
            tagTrustedRule.setMarkers(TrustMarker.ASSET_TAG.name());
            rules.add(tagTrustedRule);
        } catch (Exception e) {
            throw new RuntimeException("Cannot load tag certificate authorities file: " + e.getMessage());
        }
        return rules;
    }
    
    /**
     * Create AssetTagMatches Trust rules for Flavor Type
     * 
     * @param flavor  Flavor 
     * @return   Set of AssetTagMatches Trust rules
     */
    public static Set<Rule> createAssetTagMacthesRules(Flavor flavor){
        log.debug("Creating PcrEventLogIncludes");
        HashSet<Rule> rules = new HashSet<>();
        //log.debug("Adding the asset tag rule for host {} with asset tag ID {}", tblHosts.getName(), atagCert.getId()); 
        byte[] atagCert = flavor.getExternal().getAssetTag().getTagCertificate().getEncoded();
        //DigestAlgorithm digest = DigestAlgorithm.valueOf(flavor.getHostUniqueAssetTag().getDigestAlgorithm());
        Map<String, String> tags = new HashMap();
        for(UTF8NameValueMicroformat atr : flavor.getExternal().getAssetTag().getTagCertificate().getAttributes(UTF8NameValueMicroformat.class)){
            tags.put(atr.getName(), atr.getValue());
        }
        for(UTF8NameValueSequence atr : flavor.getExternal().getAssetTag().getTagCertificate().getAttributes(UTF8NameValueSequence.class)){
            tags.put(atr.getName(), atr.getValues().get(0));
        }
        AssetTagMatches tagRule = new AssetTagMatches(Sha384Digest.digestOf(atagCert).toByteArray(), tags);
        tagRule.setMarkers(TrustMarker.ASSET_TAG.name());
        rules.add(tagRule);
        return rules;
    }
    
    /**
     * Create PcrEventLogIncludes Trust rules
     * 
     * @param pcrList  List of PCRs along with their the Digest Bank(Algorithm), value and events
     * @param pcrIndexList  List of PCR index required for rules creation
     * @param markers  List of Trust Markers
     * @return  Set of PcrEventLogIncludes Trust rules
     */
    public static Set<Rule> createPcrEventLogIncludesRules(Map<DigestAlgorithm, Map<PcrIndex, PcrEx>> pcrList, List<Integer> pcrIndexList, String... markers){
        log.debug("Creating PcrEventLogIncludes");
        return createRulesFromPcrList("PcrEventLogIncludes", pcrList, pcrIndexList, markers);
    }
    
    /**
     * Create PcrEventLogEquals Trust rules
     * 
     * @param pcrList  List of PCRs along with their the Digest Bank(Algorithm), value and events
     * @param pcrIndexList  List of PCR index required for rules creation
     * @param markers  List of Trust Markers
     * @return  Set of PcrEventLogIncludes Trust rules
     */
    public static Set<Rule> createPcrEventLogEqualsRules(Map<DigestAlgorithm, Map<PcrIndex, PcrEx>> pcrList, List<Integer> pcrIndexList, String... markers){
        log.debug("Creating PcrEventLogEquals");
        return createRulesFromPcrList("PcrEventLogEquals", pcrList, pcrIndexList, markers);
    }

    /**
     * Create PcrEventLogIntegrity Trust rules
     * 
     * @param pcrList  List of PCRs along with their the Digest Bank(Algorithm), value and events
     * @param pcrIndexList  List of PCR index required for rules creation
     * @param markers  List of Trust Markers 
     * @return  Set of PcrEventLogIntegrity Trust rules
     */
    public static Set<Rule> createPcrEventLogIntegrityRules(Map<DigestAlgorithm, Map<PcrIndex, PcrEx>> pcrList, List<Integer> pcrIndexList, String... markers){
        log.debug("Creating PcrEventLogIntegrity");
        return createRulesFromPcrList("PcrEventLogIntegrity", pcrList, pcrIndexList, markers);
    }
    
    
    /**
     * Create PcrEventLogEqualsExcluding Trust rules
     * 
     * @param pcrList  List of PCRs along with their the Digest Bank(Algorithm), value and events
     * @param pcrIndexList  List of PCR index required for rules creation
     * @param markers  List of Trust Markers 
     * @return  Set of PcrEventLogEqualsExcluding Trust rules
     */
    public static Set<Rule> createPcrEventLogEqualsExcludingRules(Map<DigestAlgorithm, Map<PcrIndex, PcrEx>> pcrList, List<Integer> pcrIndexList, String... markers){
        log.debug("Creating PcrEventLogEqualsExcluding");
        return createRulesFromPcrList("PcrEventLogEqualsExcluding", pcrList, pcrIndexList, markers);
    }
    
    /**
     * Create createSoftwareRules Trust rules
     *
     * @return  Set of createSoftwareRules Trust rules
     * @param flavor
     */
    public static Set<Rule> createSoftwareRules(Flavor flavor){
        log.debug("Creating PcrMatchesConstant");
        HashSet<Rule> rules = new HashSet<>();
        XmlMeasurementsDigestEquals xmlMeasurementsDigestEquals = new XmlMeasurementsDigestEquals(flavor);
        xmlMeasurementsDigestEquals.setMarkers(TrustMarker.SOFTWARE.name());
        rules.add(xmlMeasurementsDigestEquals);

        // PCR value not getting validated hence sending dummy value
        PcrEventLogIntegrity pcrEventLogIntegrity = new Pcr15EventLogIntegrity(flavor);
        pcrEventLogIntegrity.setMarkers(TrustMarker.SOFTWARE.name());
        rules.add(pcrEventLogIntegrity);

        XmlMeasurementLogIntegrity xmlMeasurementLogIntegrity = new XmlMeasurementLogIntegrity(flavor);
        xmlMeasurementLogIntegrity.setMarkers(TrustMarker.SOFTWARE.name());
        rules.add(xmlMeasurementLogIntegrity);

        XmlMeasurementLogEquals xmlMeasurementLogEquals = new XmlMeasurementLogEquals(flavor);
        xmlMeasurementLogEquals.setMarkers(TrustMarker.SOFTWARE.name());
        rules.add(xmlMeasurementLogEquals);
        return rules;
    }

    /**
     * Create PcrMatchesConstant Trust rules
     *
     * @param pcrList  List of PCRs along with their the Digest Bank(Algorithm), value and events
     * @param pcrIndexList  List of PCR index required for rules creation
     * @param markers  List of Trust Markers
     * @return  Set of PcrMatchesConstant Trust rules
     */
    public static Set<Rule> createPcrMatchesConstantRules(Map<DigestAlgorithm, Map<PcrIndex, PcrEx>> pcrList, List<Integer> pcrIndexList, String... markers){
        log.debug("Creating PcrMatchesConstant");
        return createRulesFromPcrList("PcrMatchesConstant", pcrList, pcrIndexList, markers);
    }
    
    /**
     * Create a particular Trust rules
     * 
     * @param ruleType  Type of Trust Rule
     * @param pcrList  List of PCRs along with their the Digest Bank(Algorithm), value and events
     * @param pcrIndexList  List of PCR index required for rules creation
     * @param markers  List of Trust Markers
     * @return  Set of Trust rules
     */
    private static Set<Rule> createRulesFromPcrList(String ruleType, Map<DigestAlgorithm, Map<PcrIndex, PcrEx>> pcrList, List<Integer> pcrIndexList, String... markers) {
        Set<Rule> rules = new HashSet();
        BaseRule rule = null;
        List<DigestAlgorithm> pcrDigests = new ArrayList(pcrList.keySet());
        for (DigestAlgorithm pcrDigest : pcrDigests) {
            Map<PcrIndex, PcrEx> pcrs = pcrList.get(pcrDigest);
            if (pcrs.isEmpty()){
                continue;
            }
            for (Integer index : pcrIndexList) {
                PcrIndex pcrIndex = PcrIndex.valueOf(index);
                PcrEx ex = pcrs.get(pcrIndex);
                
                // retrieve PCR value
                String exValue = null;
                if (ex != null && ex.getValue() != null && !ex.getValue().isEmpty())
                    exValue = ex.getValue();
                if (exValue == null) continue;
                
                // retrieve PCR event log
                List<Measurement> exEvent = null;
                if (ex != null && ex.getEvent() != null && !ex.getEvent().isEmpty())
                    exEvent = ex.getEvent();
                
                log.debug("Creating trust rule of type {} for bank {} PCR {}", ruleType, pcrDigest, pcrIndex);
                switch(ruleType) {
                    case "PcrEventLogIncludes":
                        if (exEvent == null) continue;
                        rule = new PcrEventLogIncludes(pcrDigest, pcrIndex, new HashSet(exEvent));
                        rule.setMarkers(markers);
                        break;
                    case "PcrEventLogEquals":
                        if (exEvent == null) continue;
                        rule = new PcrEventLogEquals(PcrEventLogFactory.newInstance(pcrDigest, pcrIndex, exEvent));
                        rule.setMarkers(markers);
                        break;
                    case "PcrEventLogIntegrity":
                        rule = new PcrEventLogIntegrity(PcrFactory.newInstance(pcrDigest, pcrIndex, exValue));
                        rule.setMarkers(markers);
                        break;
                    case "PcrEventLogEqualsExcluding":
                        if (exEvent == null) continue;
                        rule = new PcrEventLogEqualsExcluding(PcrEventLogFactory.newInstance(pcrDigest, pcrIndex, exEvent));
                        rule.setMarkers(markers);
                        break;
                    case "PcrMatchesConstant":
                        rule = new PcrMatchesConstant(PcrFactory.newInstance(pcrDigest, pcrIndex, exValue));
                        rule.setMarkers(markers);
                        break;
                    default:
                        break;
                }
                if (rule != null) {
                    log.debug("Added trust rule of type {}", ruleType);
                    rules.add((Rule)rule);
                }
            }
        }
        return rules;
    }
}
