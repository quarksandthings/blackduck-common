package com.blackducksoftware.integration.hub.cli;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.blackducksoftware.integration.exception.EncryptionException;
import com.blackducksoftware.integration.hub.exception.HubIntegrationException;
import com.blackducksoftware.integration.log.IntLogger;
import com.blackducksoftware.integration.rest.proxy.ProxyInfo;

public class CliCommandBuilder {
    private List<String> createDefaultCommand(IntLogger logger, CliCommandData cliCommandData) throws HubIntegrationException, EncryptionException {
        List<String> cmd = new ArrayList<>();

        String pathToJavaExecutable;
        String pathToOneJar;
        String pathToScanExecutable;
        try {
            pathToJavaExecutable = cliCommandData.getPathToJavaExecutable();
            pathToOneJar = cliCommandData.getPathToOneJar();
            pathToScanExecutable = cliCommandData.getPathToScanExecutable();
        } catch (IOException e) {
            throw new HubIntegrationException(String.format("The provided directory %s did not have a Hub CLI.", cliCommandData.getInstallDirectoryPath()), e);
        }
        logger.debug("Using this java installation : " + pathToJavaExecutable);

        cmd.add(pathToJavaExecutable);
        cmd.add("-Done-jar.silent=true");
        cmd.add("-Done-jar.jar.path=" + pathToOneJar);

        if (!cliCommandData.isDryRun() && cliCommandData.shouldUseProxy()) {
            ProxyInfo hubProxyInfo = cliCommandData.getProxyInfo();
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
        String scanCliOpts = cliCommandData.getScanCliOpts();
        if (StringUtils.isNotBlank(scanCliOpts)) {
            for (String scanOpt : scanCliOpts.split(" ")) {
                if (StringUtils.isNotBlank(scanOpt)) {
                    cmd.add(scanOpt);
                }
            }
        }
        cmd.add("-Xmx" + cliCommandData.getScanMemoryInMegabytes() + "m");
        cmd.add("-jar");
        cmd.add(pathToScanExecutable);

        cmd.add("--no-prompt");

        if (!cliCommandData.isDryRun()) {
            cmd.add("--scheme");
            cmd.add(cliCommandData.getScheme());
            cmd.add("--host");
            cmd.add(cliCommandData.getHost());
            logger.debug("Using this Hub hostname : '" + cliCommandData.getHost() + "'");

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

}
