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
package com.blackducksoftware.integration.hub.cli;

import static java.lang.ProcessBuilder.Redirect.PIPE;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import com.blackducksoftware.integration.exception.EncryptionException;
import com.blackducksoftware.integration.hub.cli.configuration.CommandArguments;
import com.blackducksoftware.integration.hub.cli.configuration.TargetArguments;
import com.blackducksoftware.integration.hub.configuration.HubServerConfig;
import com.blackducksoftware.integration.hub.exception.HubIntegrationException;
import com.blackducksoftware.integration.hub.exception.ScanFailedException;
import com.blackducksoftware.integration.hub.service.model.ScannerSplitStream;
import com.blackducksoftware.integration.hub.service.model.StreamRedirectThread;
import com.blackducksoftware.integration.log.IntLogger;
import com.blackducksoftware.integration.rest.proxy.ProxyInfo;
import com.blackducksoftware.integration.util.IntEnvironmentVariables;

public class SimpleScanUtility {
    public static final int DEFAULT_MEMORY = 4096;

    private final IntLogger logger;
    private final HubServerConfig hubServerConfig;
    private final IntEnvironmentVariables intEnvironmentVariables;
    private final CommandArguments commandArguments;
    private final TargetArguments targetArguments;

    private final File specificRunOutoutDirectory;
    private final boolean isDryRun;

    public SimpleScanUtility(IntLogger logger, IntEnvironmentVariables intEnvironmentVariables, CommandArguments commandArguments, TargetArguments targetArguments) {
        this(logger, null, intEnvironmentVariables, commandArguments, targetArguments);
    }

    public SimpleScanUtility(IntLogger logger, HubServerConfig hubServerConfig, IntEnvironmentVariables intEnvironmentVariables, CommandArguments commandArguments, TargetArguments targetArguments) throws IOException {
        this.logger = logger;
        this.hubServerConfig = hubServerConfig;
        this.intEnvironmentVariables = intEnvironmentVariables;
        this.commandArguments = commandArguments;
        this.targetArguments = targetArguments;

        if (null == hubServerConfig || commandArguments.isDryRun()) {
            isDryRun = true;
        } else {
            isDryRun = false;
        }

        specificRunOutoutDirectory = createSpecificOutputDirectory();
    }

    public void setupAndExecuteScan() throws IllegalArgumentException, EncryptionException, InterruptedException, HubIntegrationException {
        CLILocation cliLocation = new CLILocation(logger, commandArguments.getInstallDirectory());
        setupAndExecuteScan(cliLocation);
    }

    private List<String> createDefaultCommand(CLILocation cliLocation, String outputDirectoryPath) throws HubIntegrationException, EncryptionException {
        List<String> cmd = new ArrayList<>();

        String pathToJavaExecutable;
        String pathToOneJar;
        String pathToScanExecutable;
        try {
            pathToJavaExecutable = cliLocation.getProvidedJavaExec().getCanonicalPath();
            pathToOneJar = cliLocation.getOneJarFile().getCanonicalPath();
            pathToScanExecutable = cliLocation.getCLI(logger).getCanonicalPath();
        } catch (IOException e) {
            throw new HubIntegrationException(String.format("The provided directory %s did not have a Hub CLI.", commandArguments.getInstallDirectory().getAbsolutePath()), e);
        }
        logger.debug("Using this java installation : " + pathToJavaExecutable);

        cmd.add(pathToJavaExecutable);
        cmd.add("-Done-jar.silent=true");
        cmd.add("-Done-jar.jar.path=" + pathToOneJar);

        if (!isDryRun && hubServerConfig.shouldUseProxyForHub()) {
            ProxyInfo hubProxyInfo = hubServerConfig.getProxyInfo();
            String proxyHost = hubProxyInfo.getHost();
            int proxyPort = hubProxyInfo.getPort();
            String proxyUsername = hubProxyInfo.getUsername();
            String proxyPassword = hubProxyInfo.getDecryptedPassword();
            String proxyNtlmDomain = hubProxyInfo.getNtlmDomain();
            String proxyNtlmWorkstation = hubProxyInfo.getNtlmWorkstation();
            cmd.add("-Dhttp.proxyHost=" + proxyHost);
            cmd.add("-Dhttp.proxyPort=" + Integer.toString(proxyPort));
            if (StringUtils.isNotBlank(proxyUsername) && StringUtils.isNotBlank(proxyPassword)) {
                cmd.add("-Dhttp.proxyUser=" + proxyUsername);
                cmd.add("-Dhttp.proxyPassword=" + proxyPassword);
            } else {
                // CLI will ignore the proxy host and port if there are no credentials
                cmd.add("-Dhttp.proxyUser=user");
                cmd.add("-Dhttp.proxyPassword=password");
            }
            if (StringUtils.isNotBlank(proxyNtlmDomain)) {
                cmd.add("-Dhttp.auth.ntlm.domain=" + proxyNtlmDomain);
            }
            if (StringUtils.isNotBlank(proxyNtlmWorkstation)) {
                cmd.add("-Dblackduck.http.auth.ntlm.workstation=" + proxyNtlmWorkstation);
            }
        }
        String scanCliOpts = intEnvironmentVariables.getValue("SCAN_CLI_OPTS");
        if (StringUtils.isNotBlank(scanCliOpts)) {
            for (String scanOpt : scanCliOpts.split(" ")) {
                if (StringUtils.isNotBlank(scanOpt)) {
                    cmd.add(scanOpt);
                }
            }
        }
        cmd.add("-Xmx" + commandArguments.getScanMemory() + "m");
        cmd.add("-jar");
        cmd.add(pathToScanExecutable);

        cmd.add("--no-prompt");

        if (!isDryRun) {
            cmd.add("--scheme");
            cmd.add(hubServerConfig.getHubUrl().getProtocol());
            cmd.add("--host");
            cmd.add(hubServerConfig.getHubUrl().getHost());
            logger.debug("Using this Hub hostname : '" + hubServerConfig.getHubUrl().getHost() + "'");

            if (StringUtils.isEmpty(hubServerConfig.getApiToken())) {
                cmd.add("--username");
                cmd.add(hubServerConfig.getGlobalCredentials().getUsername());
            }

            int hubPort = hubServerConfig.getHubUrl().getPort();
            if (hubPort > 0) {
                cmd.add("--port");
                cmd.add(Integer.toString(hubPort));
            } else {
                int defaultPort = hubServerConfig.getHubUrl().getDefaultPort();
                if (defaultPort > 0) {
                    cmd.add("--port");
                    cmd.add(Integer.toString(defaultPort));
                } else {
                    logger.warn("Could not find a port to use for the Server.");
                }
            }

            if (hubServerConfig.isAlwaysTrustServerCertificate()) {
                cmd.add("--insecure");
            }
        }

        if (commandArguments.isVerbose()) {
            cmd.add("-v");
        }

        if (commandArguments.isDebug()) {
            cmd.add("--debug");
        }

        cmd.add("--logDir");
        cmd.add(outputDirectoryPath);

        if (isDryRun) {
            // The dryRunWriteDir is the same as the log directory path
            // The CLI will create a subdirectory for the json files
            cmd.add("--dryRunWriteDir");
            cmd.add(outputDirectoryPath);
        }

        // Only add the statusWriteDir option if the Hub supports the statusWriteDir option
        // The scanStatusDirectoryPath is the same as the log directory path
        // The CLI will create a subdirectory for the status files
        cmd.add("--statusWriteDir");
        cmd.add(outputDirectoryPath);

        if (StringUtils.isNotBlank(commandArguments.getProjectName()) && StringUtils.isNotBlank(commandArguments.getProjectVersionName())) {
            cmd.add("--project");
            cmd.add(commandArguments.getProjectName());
            cmd.add("--release");
            cmd.add(commandArguments.getProjectVersionName());
        }

        if (StringUtils.isNotBlank(targetArguments.getCodeLocationAlias())) {
            cmd.add("--name");
            cmd.add(targetArguments.getCodeLocationAlias());
        }

        if (commandArguments.isSnippetModeEnabled()) {
            cmd.add("--snippet-matching");
        }

        if (targetArguments.getExcludePatterns() != null) {
            for (String exclusionPattern : targetArguments.getExcludePatterns()) {
                if (StringUtils.isNotBlank(exclusionPattern)) {
                    cmd.add("--exclude");
                    cmd.add(exclusionPattern);
                }
            }
        }
        String additionalScanArguments = commandArguments.getAdditionalScanArguments();
        if (StringUtils.isNotBlank(additionalScanArguments)) {
            for (String additionalArgument : additionalScanArguments.split(" ")) {
                if (StringUtils.isNotBlank(additionalArgument)) {
                    cmd.add(additionalArgument);
                }
            }
        }

        cmd.add(targetArguments.getScanTarget());

        return cmd;
    }

    /**
     * This will setup the command-line invocation of the Hub scanner. The workingDirectoryPath is the parent folder of the scan logs and other scan artifacts.
     * @throws EncryptionException
     * @throws IllegalArgumentException
     * @throws HubIntegrationException
     * @throws ScanFailedException
     */
    public void setupAndExecuteScan(CLILocation cliLocation) throws IllegalArgumentException, EncryptionException, InterruptedException, HubIntegrationException {
        String outputDirectoryPath;
        try {
            populateLogDirectory();
            logDirectoryPath = logDirectory.getCanonicalPath();
        } catch (IOException e) {
            throw new HubIntegrationException("Exception creating the log directory for the cli scan: " + e.getMessage(), e);
        }

        try {
            executeScan();
        } catch (IOException e) {
            throw new HubIntegrationException("Exception executing the cli scan: " + e.getMessage(), e);
        }
    }

    /**
     * If running in an environment that handles process creation, this method should be overridden to construct a process to execute the scan in the environment-specific way.
     * @throws IOException
     * @throws HubIntegrationException
     */
    private void executeScan() throws IllegalArgumentException, EncryptionException, IOException, InterruptedException, ScanFailedException {
        printCommand();

        File standardOutFile = getStandardOutputFile();
        standardOutFile.createNewFile();
        try (FileOutputStream outputFileStream = new FileOutputStream(standardOutFile)) {
            ScannerSplitStream splitOutputStream = new ScannerSplitStream(logger, outputFileStream);
            ProcessBuilder processBuilder = new ProcessBuilder(cmd).redirectError(PIPE).redirectOutput(PIPE);
            processBuilder.environment().putAll(intEnvironmentVariables.getVariables());

            if (isNotDryRun(hubServerConfig, signatureScanConfig)) {
                if (!StringUtils.isEmpty(hubServerConfig.getApiToken())) {
                    processBuilder.environment().put("BD_HUB_TOKEN", hubServerConfig.getApiToken());
                } else {
                    processBuilder.environment().put("BD_HUB_PASSWORD", hubServerConfig.getGlobalCredentials().getDecryptedPassword());
                }
            }
            processBuilder.environment().put("BD_HUB_NO_PROMPT", "true");

            Process hubCliProcess = processBuilder.start();

            // The cli logs go the error stream for some reason
            StreamRedirectThread redirectThread = new StreamRedirectThread(hubCliProcess.getErrorStream(), splitOutputStream);
            redirectThread.start();

            int returnCode = -1;
            try {
                returnCode = hubCliProcess.waitFor();

                // the join method on the redirect thread will wait until the thread is dead
                // the thread will die when it reaches the end of stream and the run method is finished
                redirectThread.join();
            } finally {
                if (hubCliProcess.isAlive()) {
                    hubCliProcess.destroy();
                }
                if (redirectThread.isAlive()) {
                    redirectThread.interrupt();
                }
            }

            splitOutputStream.flush();

            logger.info(IOUtils.toString(hubCliProcess.getInputStream(), StandardCharsets.UTF_8));

            logger.info("Hub CLI return code : " + returnCode);
            logger.info("You can view the BlackDuck Scan CLI logs at : '" + logDirectory.getCanonicalPath() + "'");

            if (returnCode != 0) {
                throw new ScanFailedException("The scan failed with return code : " + returnCode);
            }
        }
    }

    private File createSpecificOutputDirectory() throws IOException {
        String internalOutputDirectoryName = "HubScanOutput";
        File internalOutputDirectory = new File(commandArguments.getOutputDirectory(), internalOutputDirectoryName);

        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss-SSS").withZone(ZoneOffset.UTC);
        String timeString = Instant.now().atZone(ZoneOffset.UTC).format(dateTimeFormatter);
        String specificRunOutputDirectoryName = timeString + "_" + Thread.currentThread().getId();
        File specificRunOutputDirectory = new File(internalOutputDirectory, specificRunOutputDirectoryName);

        if (!specificRunOutputDirectory.exists() && !specificRunOutputDirectory.mkdirs()) {
            throw new IOException(String.format("Could not create the %s specific run output directory!", specificRunOutputDirectory.getAbsolutePath()));
        }

        File bdIgnoreLogsFile = new File(commandArguments.getOutputDirectory(), ".bdignore");
        if (!bdIgnoreLogsFile.exists()) {
            if (!bdIgnoreLogsFile.createNewFile()) {
                throw new IOException(String.format("Could not create the %s file!", bdIgnoreLogsFile.getAbsolutePath()));
            }
            String exclusionPattern = "/" + internalOutputDirectoryName + "/";
            Files.write(bdIgnoreLogsFile.toPath(), exclusionPattern.getBytes());
        }

        return specificRunOutputDirectory;
    }

    /**
     * Code to mask passwords in the logs
     */
    private void printCommand(List<String> cmd) {
        List<String> cmdToOutput = new ArrayList<>();
        cmdToOutput.addAll(cmd);

        int passwordIndex = cmdToOutput.indexOf("--password");
        if (passwordIndex > -1) {
            // The User's password will be at the next index
            passwordIndex++;
        }

        int proxyPasswordIndex = -1;
        for (int commandIndex = 0; commandIndex < cmdToOutput.size(); commandIndex++) {
            String commandParameter = cmdToOutput.get(commandIndex);
            if (commandParameter.contains("-Dhttp.proxyPassword=")) {
                proxyPasswordIndex = commandIndex;
            }
        }

        maskIndex(cmdToOutput, passwordIndex);
        maskIndex(cmdToOutput, proxyPasswordIndex);

        logger.info("Hub CLI command :");
        for (String current : cmdToOutput) {
            logger.info(current);
        }
    }

    private void maskIndex(List<String> cmd, int indexToMask) {
        if (indexToMask > -1) {
            String cmdToMask = cmd.get(indexToMask);
            String[] maskedArray = new String[cmdToMask.length()];
            Arrays.fill(maskedArray, "*");
            cmd.set(indexToMask, StringUtils.join(maskedArray));
        }
    }

    public IntLogger getLogger() {
        return logger;
    }

    public File getLogDirectory() {
        return logDirectory;
    }

    public File getStatusDirectory() {
        return new File(logDirectory, "status");
    }

    public File getDataDirectory() {
        return new File(logDirectory, "data");
    }

    public File getCLILogDirectory() {
        return new File(logDirectory, "log");
    }

    public File getStandardOutputFile() {
        return new File(logDirectory, "CLI_Output.txt");
    }

    public File getScanSummaryFile() {
        File scanStatusDirectory = getStatusDirectory();
        if (null != scanStatusDirectory) {
            File[] scanSummaryFiles = scanStatusDirectory.listFiles((FilenameFilter) (dir, name) -> FilenameUtils.wildcardMatchOnSystem(name, "*.json"));
            if (null != scanSummaryFiles) {
                if (scanSummaryFiles.length == 0) {
                    logger.error("There were no status files found in " + scanStatusDirectory.getAbsolutePath());
                    return null;
                } else if (scanSummaryFiles.length > 1) {
                    logger.error(String.format("There were should have only been 1 status file in '%s' but there are %s", scanStatusDirectory.getAbsolutePath(), scanSummaryFiles.length));
                }
                return scanSummaryFiles[0];
            }
        }
        return null;
    }

    public File getDryRunFile() {
        File dataDirectory = getDataDirectory();
        if (null != dataDirectory) {
            File[] dryRunFiles = dataDirectory.listFiles((FilenameFilter) (dir, name) -> FilenameUtils.wildcardMatchOnSystem(name, "*.json"));
            if (null != dryRunFiles) {
                if (dryRunFiles.length == 0) {
                    logger.error("There were no dry run files found in " + dataDirectory.getAbsolutePath());
                    return null;
                } else if (dryRunFiles.length > 1) {
                    logger.error(String.format("There were should have only been 1 dry run in '%s' but there are %s", dataDirectory.getAbsolutePath(), dryRunFiles.length));
                }
                return dryRunFiles[0];
            }
        }
        return null;
    }

}
