/*******************************************************************************
 * Copyright (C) 2016 Black Duck Software, Inc.
 * http://www.blackducksoftware.com/
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *******************************************************************************/
package com.blackducksoftware.integration.hub.report.api;

@Deprecated
public class LicenseDefinition extends com.blackducksoftware.integration.hub.api.report.LicenseDefinition {
    // Need this package and the objects for backwards compatability
    public LicenseDefinition(final String licenseId, final String discoveredAs, final String name, final String spdxId,
            final String ownership, final String codeSharing, final String licenseDisplay) {
        super(licenseId, discoveredAs, name, spdxId, ownership, codeSharing, licenseDisplay);
    }
}
