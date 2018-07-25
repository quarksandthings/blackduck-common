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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import com.blackducksoftware.integration.log.IntLogger;
import com.blackducksoftware.integration.util.Stringable;

public class HubScanConfig extends Stringable {
    private final CommandArguments commandArguments;
    private final boolean cleanupLogsOnSuccess;
    private final Map<String, String> targetToCodeLocationName;
    private final Map<String, Set<String>> targetToExclusionPatterns;
    private final Set<String> scanTargetPaths;

    public HubScanConfig(CommandArguments commandArguments, Set<String> scanTargetPaths, boolean cleanupLogsOnSuccess, Map<String, Set<String>> targetToExclusionPatterns, Map<String, String> targetToCodeLocationName) {
        this.commandArguments = commandArguments;
        this.scanTargetPaths = scanTargetPaths;
        this.cleanupLogsOnSuccess = cleanupLogsOnSuccess;
        this.targetToExclusionPatterns = targetToExclusionPatterns;
        this.targetToCodeLocationName = targetToCodeLocationName;
    }

    public List<TargetArguments> createTargetArguments() {
        List<TargetArguments> targetArguments = new ArrayList<>();
        for (String scanTarget : scanTargetPaths) {
            String[] exclusionPatterns = new String[0];
            Set<String> patterns = targetToExclusionPatterns.get(scanTarget);
            if (null != patterns && !patterns.isEmpty()) {
                exclusionPatterns = patterns.toArray(new String[patterns.size()]);
            }
            TargetArguments singleTargetArguments = new TargetArguments(targetToCodeLocationName.get(scanTarget), exclusionPatterns, scanTarget);
            targetArguments.add(singleTargetArguments);
        }
        return targetArguments;
    }

    public Set<String> getScanTargetPaths() {
        return scanTargetPaths;
    }

    public boolean isCleanupLogsOnSuccess() {
        return cleanupLogsOnSuccess;
    }

    public Map<String, Set<String>> getTargetToExclusionPatterns() {
        return targetToExclusionPatterns;
    }

    public Map<String, String> getTargetToCodeLocationName() {
        return targetToCodeLocationName;
    }

    public void print(IntLogger logger) {
        try {
            logger.alwaysLog("--> Using Working Directory: " + commonScanConfig.getWorkingDirectory().getCanonicalPath());
        } catch (IOException e) {
            logger.alwaysLog("Extremely unlikely exception getting the canonical path: " + e.getMessage());
        }
        logger.alwaysLog("--> Scanning the following targets:");
        if (scanTargetPaths != null) {
            for (String target : scanTargetPaths) {
                String codeLocationName = getTargetToCodeLocationName().get(target);
                logger.alwaysLog(String.format("--> Target: %s", target));
                if (StringUtils.isNotBlank(codeLocationName)) {
                    logger.alwaysLog(String.format("    --> Code Location Name: %s", codeLocationName));
                }
                Set<String> excludePatterns = getTargetToExclusionPatterns().get(target);
                if (excludePatterns != null && !excludePatterns.isEmpty()) {
                    logger.alwaysLog("--> Directory Exclusion Patterns:");
                    for (String exclusionPattern : excludePatterns) {
                        logger.alwaysLog(String.format("--> Exclusion Pattern: %s", exclusionPattern));
                    }
                }
            }
        } else {
            logger.alwaysLog("--> null");
        }

        logger.alwaysLog("--> Scan Memory: " + commonScanConfig.getScanMemory());
        logger.alwaysLog("--> Dry Run: " + commonScanConfig.isDryRun());
        logger.alwaysLog("--> Clean-up logs on success: " + isCleanupLogsOnSuccess());
        logger.alwaysLog("--> Enable Snippet Mode: " + commonScanConfig.isSnippetModeEnabled());
        logger.alwaysLog("--> Additional Scan Arguments: " + commonScanConfig.getAdditionalScanArguments());
    }

}
