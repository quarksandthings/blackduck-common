/**
 * hub-common
 *
 * Copyright (C) 2018 Black Duck Software, Inc.
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
 */
package com.blackducksoftware.integration.hub.service;

import java.util.Map;

import org.apache.commons.lang3.builder.RecursiveToStringStyle;
import org.apache.commons.lang3.builder.ReflectionToStringBuilder;

import com.blackducksoftware.integration.exception.IntegrationException;
import com.blackducksoftware.integration.hub.cli.CLIDownloadUtility;
import com.blackducksoftware.integration.hub.cli.SimpleScanUtility;
import com.blackducksoftware.integration.hub.configuration.HubScanConfig;
import com.blackducksoftware.integration.hub.configuration.HubServerConfig;
import com.blackducksoftware.integration.hub.notification.PolicyNotificationFilter;
import com.blackducksoftware.integration.hub.rest.RestConnection;
import com.blackducksoftware.integration.phonehome.PhoneHomeClient;
import com.blackducksoftware.integration.util.CIEnvironmentVariables;
import com.blackducksoftware.integration.util.IntegrationEscapeUtil;

public class HubServicesFactory {
    private final CIEnvironmentVariables ciEnvironmentVariables;
    private final RestConnection restConnection;

    public HubServicesFactory(final RestConnection restConnection) {
        this.ciEnvironmentVariables = new CIEnvironmentVariables();
        ciEnvironmentVariables.putAll(System.getenv());

        this.restConnection = restConnection;
    }

    public void addEnvironmentVariable(final String key, final String value) {
        ciEnvironmentVariables.put(key, value);
    }

    public void addEnvironmentVariables(final Map<String, String> environmentVariables) {
        ciEnvironmentVariables.putAll(environmentVariables);
    }

    public SignatureScannerService createCLIDataService() {
        return createCLIDataService(120000l);
    }

    public SignatureScannerService createCLIDataService(final long timeoutInMilliseconds) {
        return new SignatureScannerService(restConnection, ciEnvironmentVariables, createCliDownloadUtility(), createPhoneHomeDataService(), createProjectDataService(),
                createCodeLocationDataService(), createScanStatusDataService(timeoutInMilliseconds));
    }

    public PhoneHomeService createPhoneHomeDataService() {
        return new PhoneHomeService(restConnection, createPhoneHomeClient(), createHubRegistrationService());
    }

    public PhoneHomeClient createPhoneHomeClient() {
        return new PhoneHomeClient(restConnection.logger, restConnection.timeout, restConnection.getProxyInfo(), restConnection.alwaysTrustServerCertificate);
    }

    public ReportService createReportDataService(final long timeoutInMilliseconds) throws IntegrationException {
        return new ReportService(restConnection, createProjectDataService(), createIntegrationEscapeUtil(), timeoutInMilliseconds);
    }

    public PolicyStatusService createPolicyStatusDataService() {
        return new PolicyStatusService(restConnection, createProjectDataService());
    }

    public ScanStatusService createScanStatusDataService(final long timeoutInMilliseconds) {
        return new ScanStatusService(restConnection, createProjectDataService(), createCodeLocationDataService(), timeoutInMilliseconds);
    }

    public NotificationService createNotificationDataService() {
        return new NotificationService(restConnection);
    }

    public NotificationService createNotificationDataService(final PolicyNotificationFilter policyNotificationFilter) {
        return new NotificationService(restConnection, policyNotificationFilter);
    }

    public ExtensionConfigService createExtensionConfigDataService() {
        return new ExtensionConfigService(restConnection.logger, restConnection);
    }

    public LicenseService createLicenseDataService() {
        return new LicenseService(restConnection, createComponentDataService());
    }

    public CodeLocationService createBdioUploadDataService() {
        return new CodeLocationService(restConnection);
    }

    public CodeLocationService createCodeLocationDataService() {
        return new CodeLocationService(restConnection);
    }

    public CLIDownloadUtility createCliDownloadUtility() {
        return new CLIDownloadUtility(restConnection.logger, restConnection);
    }

    public IntegrationEscapeUtil createIntegrationEscapeUtil() {
        return new IntegrationEscapeUtil();
    }

    public SimpleScanUtility createSimpleScanUtility(final RestConnection restConnection, final HubServerConfig hubServerConfig, final HubScanConfig hubScanConfig, final String projectName,
            final String versionName) {
        return new SimpleScanUtility(restConnection.logger, restConnection.gson, hubServerConfig, ciEnvironmentVariables, hubScanConfig, projectName, versionName);
    }

    public HubRegistrationDataService createHubRegistrationService() {
        return new HubRegistrationDataService(restConnection);
    }

    public HubService createHubDataService() {
        return new HubService(restConnection);
    }

    public RestConnection getRestConnection() {
        return restConnection;
    }

    public ComponentService createComponentDataService() {
        return new ComponentService(restConnection);
    }

    public IssueService createIssueDataService() {
        return new IssueService(restConnection);
    }

    public ProjectService createProjectDataService() {
        return new ProjectService(restConnection, createComponentDataService());
    }

    public UserGroupService createUserGroupDataService() {
        return new UserGroupService(restConnection);
    }

    @Override
    public String toString() {
        return ReflectionToStringBuilder.toString(this, RecursiveToStringStyle.JSON_STYLE);
    }

}
