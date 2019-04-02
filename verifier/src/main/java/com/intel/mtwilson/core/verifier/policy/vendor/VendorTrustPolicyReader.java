/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.verifier.policy.vendor;

import com.intel.mtwilson.core.verifier.policy.Policy;

/**
 *
 * @author dtiwari
 */
public interface VendorTrustPolicyReader {
    Policy loadTrustRules();
}
