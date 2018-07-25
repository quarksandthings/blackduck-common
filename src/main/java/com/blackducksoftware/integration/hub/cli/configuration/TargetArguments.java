package com.blackducksoftware.integration.hub.cli.configuration;

public class TargetArguments {
    private final String codeLocationAlias;
    private final String[] excludePatterns;
    private final String scanTarget;

    public TargetArguments(String codeLocationAlias, String[] excludePatterns, String scanTarget) {
        this.codeLocationAlias = codeLocationAlias;
        this.excludePatterns = excludePatterns;
        this.scanTarget = scanTarget;
    }

    public String getCodeLocationAlias() {
        return codeLocationAlias;
    }

    public String[] getExcludePatterns() {
        return excludePatterns;
    }

    public String getScanTarget() {
        return scanTarget;
    }

}
