package com.blackducksoftware.integration.hub.cli;

import java.io.IOException;

import com.blackducksoftware.integration.hub.cli.configuration.CommandArguments;
import com.blackducksoftware.integration.hub.cli.configuration.TargetArguments;
import com.blackducksoftware.integration.hub.configuration.HubServerConfig;
import com.blackducksoftware.integration.log.IntLogger;
import com.blackducksoftware.integration.rest.proxy.ProxyInfo;
import com.blackducksoftware.integration.util.IntEnvironmentVariables;

public class CliCommandData {
    private final IntLogger logger;
    private final CLILocation cliLocation;
    private final HubServerConfig hubServerConfig;
    private final IntEnvironmentVariables intEnvironmentVariables;
    private final CommandArguments commandArguments;
    private final TargetArguments targetArguments;

    public CliCommandData(IntLogger logger, CLILocation cliLocation, HubServerConfig hubServerConfig, IntEnvironmentVariables intEnvironmentVariables, CommandArguments commandArguments, TargetArguments targetArguments) {
        this.logger = logger;
        this.cliLocation = cliLocation;
        this.hubServerConfig = hubServerConfig;
        this.intEnvironmentVariables = intEnvironmentVariables;
        this.commandArguments = commandArguments;
        this.targetArguments = targetArguments;
    }

    public String getPathToJavaExecutable() throws IOException {
        return cliLocation.getProvidedJavaExec().getCanonicalPath();
    }

    public String getPathToOneJar() throws IOException {
        return cliLocation.getOneJarFile().getCanonicalPath();
    }

    public String getPathToScanExecutable() throws IOException {
        return cliLocation.getCLI(logger).getCanonicalPath();
    }

    public String getInstallDirectoryPath() {
        return commandArguments.getInstallDirectory().getAbsolutePath();
    }

    public boolean isDryRun() {
        if (null == hubServerConfig || commandArguments.isDryRun()) {
            return true;
        } else {
            return false;
        }
    }

    public boolean shouldUseProxy() {
        return hubServerConfig.shouldUseProxyForHub();
    }

    public ProxyInfo getProxyInfo() {
        return hubServerConfig.getProxyInfo();
    }

    public String getScanCliOpts() {
        return intEnvironmentVariables.getValue("SCAN_CLI_OPTS");
    }

    public int getScanMemoryInMegabytes() {
        return commandArguments.getScanMemory();
    }

    public String getScheme() {
        return hubServerConfig.getHubUrl().getProtocol();
    }

    public String getHost() {
        return hubServerConfig.getHubUrl().getHost();
    }

}
