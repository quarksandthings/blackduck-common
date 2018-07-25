/**
 * hub-common
 * <p>
 * Copyright (C) 2018 Black Duck Software, Inc.
 * http://www.blackducksoftware.com/
 * <p>
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.blackducksoftware.integration.hub.cli.configuration;

import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.math.NumberUtils;

import com.blackducksoftware.integration.builder.AbstractBuilder;
import com.blackducksoftware.integration.validator.AbstractValidator;

public class HubScanConfigBuilder extends AbstractBuilder<HubScanConfig> {
    private String additionalScanArguments;
    private boolean cleanupLogsOnSuccess;
    private final Map<String, String> targetToCodeLocationName = new HashMap<>();
    private boolean debug;
    private boolean dryRun;
    private boolean disableScanTargetPathExistenceCheck;
    private boolean enableScanTargetPathsWithinWorkingDirectoryCheck;
    private final Map<String, Set<String>> targetToExclusionPatterns = new HashMap<>();
    private String scanMemory;
    private final Set<String> scanTargetPaths = new HashSet<>();
    private boolean snippetModeEnabled;
    private File toolsDir;
    private File workingDirectory;
    private boolean verbose = true;

    @Override
    public HubScanConfig buildObject() {
        CommonScanConfig commonScanConfig = new CommonScanConfig(additionalScanArguments, debug, dryRun, NumberUtils.toInt(scanMemory), snippetModeEnabled, toolsDir, workingDirectory, verbose);
        HubScanConfig config = new HubScanConfig(commonScanConfig, Collections.unmodifiableSet(scanTargetPaths), cleanupLogsOnSuccess, targetToExclusionPatterns, targetToCodeLocationName);

        return config;
    }

    @Override
    public AbstractValidator createValidator() {
        HubScanConfigValidator validator = new HubScanConfigValidator();
        validator.setScanMemory(scanMemory);
        validator.setWorkingDirectory(workingDirectory);
        validator.addAllScanTargetPaths(scanTargetPaths);
        if (disableScanTargetPathExistenceCheck) {
            validator.disableScanTargetPathExistenceCheck();
        }
        if (enableScanTargetPathsWithinWorkingDirectoryCheck) {
            validator.enableScanTargetPathsWithinWorkingDirectoryCheck();
        }
        validator.addAllTargetToExclusionPatterns(targetToExclusionPatterns);
        return validator;
    }

    public void setCleanupLogsOnSuccess(boolean cleanupLogsOnSuccess) {
        this.cleanupLogsOnSuccess = cleanupLogsOnSuccess;
    }

    public void addTargetToCodeLocationName(String scanTargetPath, String codeLocationName) {
        targetToCodeLocationName.put(scanTargetPath, codeLocationName);
    }

    public void addAllTargetToCodeLocationName(Map<String, String> targetToCodeLocationName) {
        this.targetToCodeLocationName.putAll(targetToCodeLocationName);
    }

    public void setToolsDir(File toolsDir) {
        this.toolsDir = toolsDir;
    }

    public void setDisableScanTargetPathExistenceCheck(boolean disableScanTargetPathExistenceCheck) {
        this.disableScanTargetPathExistenceCheck = disableScanTargetPathExistenceCheck;
    }

    public void setEnableScanTargetPathsWithinWorkingDirectoryCheck(boolean enableScanTargetPathsWithinWorkingDirectoryCheck) {
        this.enableScanTargetPathsWithinWorkingDirectoryCheck = enableScanTargetPathsWithinWorkingDirectoryCheck;
    }

    public void setScanMemory(int scanMemory) {
        setScanMemory(String.valueOf(scanMemory));
    }

    public void setScanMemory(String scanMemory) {
        this.scanMemory = scanMemory;
    }

    public void addScanTargetPath(String scanTargetPath) {
        scanTargetPaths.add(scanTargetPath);
    }

    public void addAllScanTargetPaths(List<String> scanTargetPaths) {
        this.scanTargetPaths.addAll(scanTargetPaths);
    }

    public void setDryRun(boolean dryRun) {
        this.dryRun = dryRun;
    }

    public void setWorkingDirectory(File workingDirectory) {
        this.workingDirectory = workingDirectory;
    }

    public void disableScanTargetPathExistenceCheck() {
        disableScanTargetPathExistenceCheck = true;
    }

    public void enableScanTargetPathsWithinWorkingDirectoryCheck() {
        enableScanTargetPathsWithinWorkingDirectoryCheck = true;
    }

    public void addTargetToExclusionPatterns(String scanTargetPath, Set<String> exclusionPatterns) {
        targetToExclusionPatterns.put(scanTargetPath, exclusionPatterns);
    }

    public void addAllTargetToExclusionPatterns(Map<String, Set<String>> targetToExclusionPatterns) {
        this.targetToExclusionPatterns.putAll(targetToExclusionPatterns);
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public void setSnippetModeEnabled(boolean snippetModeEnabled) {
        this.snippetModeEnabled = snippetModeEnabled;
    }

    public void setAdditionalScanArguments(String additionalScanArguments) {
        this.additionalScanArguments = additionalScanArguments;
    }

}
