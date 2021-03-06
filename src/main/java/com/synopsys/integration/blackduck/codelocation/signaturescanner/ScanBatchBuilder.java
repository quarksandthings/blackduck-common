/**
 * blackduck-common
 *
 * Copyright (c) 2019 Synopsys, Inc.
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
package com.synopsys.integration.blackduck.codelocation.signaturescanner;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.synopsys.integration.blackduck.codelocation.signaturescanner.command.ScanTarget;
import com.synopsys.integration.blackduck.codelocation.signaturescanner.command.SnippetMatching;
import com.synopsys.integration.blackduck.configuration.BlackDuckServerConfig;
import com.synopsys.integration.builder.BuilderStatus;
import com.synopsys.integration.builder.IntegrationBuilder;
import com.synopsys.integration.rest.proxy.ProxyInfo;

public class ScanBatchBuilder extends IntegrationBuilder<ScanBatch> {
    public static final int DEFAULT_MEMORY_IN_MEGABYTES = 4096;
    public static final int MINIMUM_MEMORY_IN_MEGABYTES = 256;

    private File installDirectory;
    private File outputDirectory;
    private boolean cleanupOutput;

    private int scanMemoryInMegabytes = DEFAULT_MEMORY_IN_MEGABYTES;
    private boolean dryRun;
    private boolean debug;
    private boolean verbose = true;
    private String scanCliOpts;
    private String additionalScanArguments;

    private SnippetMatching snippetMatching;
    private boolean uploadSource;

    private URL blackDuckUrl;
    private String blackDuckUsername;
    private String blackDuckPassword;
    private String blackDuckApiToken;
    private ProxyInfo proxyInfo = ProxyInfo.NO_PROXY_INFO;
    private boolean alwaysTrustServerCertificate;

    private String projectName;
    private String projectVersionName;

    private List<ScanTarget> scanTargets = new ArrayList<>();

    @Override
    protected ScanBatch buildWithoutValidation() {
        return new ScanBatch(installDirectory, outputDirectory, cleanupOutput, scanMemoryInMegabytes, dryRun, debug, verbose, scanCliOpts, additionalScanArguments, snippetMatching, uploadSource, blackDuckUrl, blackDuckUsername,
                blackDuckPassword, blackDuckApiToken, proxyInfo, alwaysTrustServerCertificate, projectName, projectVersionName, scanTargets);
    }

    @Override
    protected void validate(final BuilderStatus builderStatus) {
        if (scanTargets == null || scanTargets.size() < 1) {
            builderStatus.addErrorMessage("At least one target path must be provided.");
        } else {
            for (final ScanTarget scanTarget : scanTargets) {
                try {
                    new File(scanTarget.getPath()).getCanonicalPath();
                } catch (final IOException e) {
                    builderStatus.addErrorMessage(String.format("The target path: %s is not valid since its canonical path could not be determined: %s.", scanTarget.getPath(), e.getMessage()));
                }
                if (scanTarget.getExclusionPatterns() != null && scanTarget.getExclusionPatterns().size() > 0) {
                    for (final String exclusionPattern : scanTarget.getExclusionPatterns()) {
                        if (StringUtils.isNotBlank(exclusionPattern)) {
                            if (!exclusionPattern.startsWith("/") || !exclusionPattern.endsWith("/") || exclusionPattern.contains("**")) {
                                builderStatus.addErrorMessage("The exclusion pattern: " + exclusionPattern + " is not valid. An exclusion pattern must start and end with a forward slash (/) and may not contain double asterisks (**).");
                            }
                        }
                    }
                }
            }
        }

        if (blackDuckUrl != null) {
            if (StringUtils.isBlank(blackDuckApiToken) && (StringUtils.isBlank(blackDuckUsername) || StringUtils.isBlank(blackDuckPassword))) {
                builderStatus.addErrorMessage("Either an api token or a username and password is required.");
            }
        }

        if (scanMemoryInMegabytes < MINIMUM_MEMORY_IN_MEGABYTES) {
            builderStatus.addErrorMessage(String.format("The minimum amount of memory for the scan is %d MB.", MINIMUM_MEMORY_IN_MEGABYTES));
        }

        if (!StringUtils.isAllBlank(projectName, projectVersionName) && (StringUtils.isBlank(projectName) || StringUtils.isBlank(projectVersionName))) {
            builderStatus.addErrorMessage("Both projectName and projectVersionName must be provided or omitted together");
        }

        if (blackDuckUrl != null && proxyInfo == null) {
            builderStatus.addErrorMessage("Must provide proxy info.");
        }
    }

    /**
     * @deprecated Please use validateAndGetBuilderStatus.
     */
    @Deprecated
    public String createErrorMessage() {
        BuilderStatus builderStatus = validateAndGetBuilderStatus();
        return builderStatus.getFullErrorMessage();
    }

    public ScanBatchBuilder fromBlackDuckServerConfig(final BlackDuckServerConfig blackDuckServerConfig) {
        if (null == blackDuckServerConfig) {
            proxyInfo = ProxyInfo.NO_PROXY_INFO;
            blackDuckUrl = null;
            blackDuckUsername = null;
            blackDuckPassword = null;
            blackDuckApiToken = null;
            alwaysTrustServerCertificate = false;
        } else {
            proxyInfo = blackDuckServerConfig.getProxyInfo();
            blackDuckUrl = blackDuckServerConfig.getBlackDuckUrl();
            if (blackDuckServerConfig.usingApiToken()) {
                blackDuckApiToken = blackDuckServerConfig.getApiToken().orElse(null);
            } else if (blackDuckServerConfig.getCredentials().isPresent()) {
                blackDuckUsername = blackDuckServerConfig.getCredentials().get().getUsername().orElse(null);
                blackDuckPassword = blackDuckServerConfig.getCredentials().get().getPassword().orElse(null);
            }
            alwaysTrustServerCertificate = blackDuckServerConfig.isAlwaysTrustServerCertificate();
        }
        return this;
    }

    public ScanBatchBuilder addTarget(final ScanTarget scanTarget) {
        scanTargets.add(scanTarget);
        return this;
    }

    public ScanBatchBuilder addTargets(final List<ScanTarget> scanTargets) {
        this.scanTargets.addAll(scanTargets);
        return this;
    }

    public ScanBatchBuilder projectAndVersionNames(final String projectName, final String projectVersionName) {
        this.projectName = projectName;
        this.projectVersionName = projectVersionName;
        return this;
    }

    public File getInstallDirectory() {
        return installDirectory;
    }

    public ScanBatchBuilder installDirectory(final File installDirectory) {
        this.installDirectory = installDirectory;
        return this;
    }

    public File getOutputDirectory() {
        return outputDirectory;
    }

    public ScanBatchBuilder outputDirectory(final File outputDirectory) {
        this.outputDirectory = outputDirectory;
        return this;
    }

    public boolean isCleanupOutput() {
        return cleanupOutput;
    }

    public ScanBatchBuilder cleanupOutput(final boolean cleanupOutput) {
        this.cleanupOutput = cleanupOutput;
        return this;
    }

    public int getScanMemoryInMegabytes() {
        return scanMemoryInMegabytes;
    }

    public ScanBatchBuilder scanMemoryInMegabytes(final int scanMemoryInMegabytes) {
        this.scanMemoryInMegabytes = scanMemoryInMegabytes;
        return this;
    }

    public boolean isDryRun() {
        return dryRun;
    }

    public ScanBatchBuilder dryRun(final boolean dryRun) {
        this.dryRun = dryRun;
        return this;
    }

    public boolean isDebug() {
        return debug;
    }

    public ScanBatchBuilder debug(final boolean debug) {
        this.debug = debug;
        return this;
    }

    public boolean isVerbose() {
        return verbose;
    }

    public ScanBatchBuilder verbose(final boolean verbose) {
        this.verbose = verbose;
        return this;
    }

    public String getScanCliOpts() {
        return scanCliOpts;
    }

    public ScanBatchBuilder scanCliOpts(final String scanCliOpts) {
        this.scanCliOpts = scanCliOpts;
        return this;
    }

    public String getAdditionalScanArguments() {
        return additionalScanArguments;
    }

    public ScanBatchBuilder additionalScanArguments(final String additionalScanArguments) {
        this.additionalScanArguments = additionalScanArguments;
        return this;
    }

    public SnippetMatching getSnippetMatching() {
        return snippetMatching;
    }

    public ScanBatchBuilder snippetMatching(final SnippetMatching snippetMatching) {
        this.snippetMatching = snippetMatching;
        return this;
    }

    public boolean getUploadSource() {
        return uploadSource;
    }

    public ScanBatchBuilder uploadSource(final SnippetMatching snippetMatching, boolean uploadSource) {
        snippetMatching(snippetMatching);
        this.uploadSource = uploadSource;
        return this;
    }

    public URL getBlackDuckUrl() {
        return blackDuckUrl;
    }

    public ScanBatchBuilder blackDuckUrl(final URL blackDuckUrl) {
        this.blackDuckUrl = blackDuckUrl;
        return this;
    }

    public String getBlackDuckUsername() {
        return blackDuckUsername;
    }

    public ScanBatchBuilder blackDuckUsername(final String blackDuckUsername) {
        this.blackDuckUsername = blackDuckUsername;
        return this;
    }

    public String getBlackDuckPassword() {
        return blackDuckPassword;
    }

    public ScanBatchBuilder blackDuckPassword(final String blackDuckPassword) {
        this.blackDuckPassword = blackDuckPassword;
        return this;
    }

    public String getBlackDuckApiToken() {
        return blackDuckApiToken;
    }

    public ScanBatchBuilder blackDuckApiToken(final String blackDuckApiToken) {
        this.blackDuckApiToken = blackDuckApiToken;
        return this;
    }

    public ProxyInfo getProxyInfo() {
        return proxyInfo;
    }

    public ScanBatchBuilder proxyInfo(final ProxyInfo proxyInfo) {
        this.proxyInfo = proxyInfo;
        return this;
    }

    public boolean isAlwaysTrustServerCertificate() {
        return alwaysTrustServerCertificate;
    }

    public ScanBatchBuilder alwaysTrustServerCertificate(final boolean alwaysTrustServerCertificate) {
        this.alwaysTrustServerCertificate = alwaysTrustServerCertificate;
        return this;
    }

    public String getProjectName() {
        return projectName;
    }

    public String getProjectVersionName() {
        return projectVersionName;
    }

    public List<ScanTarget> getScanTargets() {
        return scanTargets;
    }

    public ScanBatchBuilder simpleScanTargets(final List<ScanTarget> scanTargets) {
        this.scanTargets = scanTargets;
        return this;
    }

}
