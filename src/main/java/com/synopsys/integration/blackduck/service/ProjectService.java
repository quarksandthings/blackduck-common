/**
 * blackduck-common
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
package com.synopsys.integration.blackduck.service;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.lang3.StringUtils;

import com.synopsys.integration.bdio.model.externalid.ExternalId;
import com.synopsys.integration.blackduck.api.generated.component.ProjectRequest;
import com.synopsys.integration.blackduck.api.generated.component.ProjectVersionRequest;
import com.synopsys.integration.blackduck.api.generated.discovery.ApiDiscovery;
import com.synopsys.integration.blackduck.api.generated.response.AssignedUserGroupView;
import com.synopsys.integration.blackduck.api.generated.view.AssignedUserView;
import com.synopsys.integration.blackduck.api.generated.view.ComponentSearchResultView;
import com.synopsys.integration.blackduck.api.generated.view.ComponentVersionView;
import com.synopsys.integration.blackduck.api.generated.view.MatchedFileView;
import com.synopsys.integration.blackduck.api.generated.view.ProjectVersionView;
import com.synopsys.integration.blackduck.api.generated.view.ProjectView;
import com.synopsys.integration.blackduck.api.generated.view.UserGroupView;
import com.synopsys.integration.blackduck.api.generated.view.UserView;
import com.synopsys.integration.blackduck.api.generated.view.VersionBomComponentView;
import com.synopsys.integration.blackduck.api.generated.view.VersionBomPolicyStatusView;
import com.synopsys.integration.blackduck.api.generated.view.VulnerableComponentView;
import com.synopsys.integration.blackduck.exception.BlackDuckIntegrationException;
import com.synopsys.integration.blackduck.service.model.ComponentVersionVulnerabilities;
import com.synopsys.integration.blackduck.service.model.ProjectVersionWrapper;
import com.synopsys.integration.blackduck.service.model.RequestFactory;
import com.synopsys.integration.blackduck.service.model.VersionBomComponentModel;
import com.synopsys.integration.exception.IntegrationException;
import com.synopsys.integration.log.IntLogger;
import com.synopsys.integration.rest.request.Request;
import com.synopsys.integration.rest.request.Response;

public class ProjectService extends DataService {
    private final ProjectGetService projectGetService;
    private final ComponentService componentService;

    public ProjectService(final BlackDuckService blackDuckService, final IntLogger logger, final ProjectGetService projectGetService, final ComponentService componentService) {
        super(blackDuckService, logger);
        this.projectGetService = projectGetService;
        this.componentService = componentService;
    }

    public ProjectVersionWrapper createProject(final ProjectRequest projectRequest) throws IntegrationException {
        final String projectUrl = blackDuckService.post(ApiDiscovery.PROJECTS_LINK, projectRequest);
        final ProjectView projectView = blackDuckService.getResponse(projectUrl, ProjectView.class);
        if (null == projectRequest.getVersionRequest()) {
            return new ProjectVersionWrapper(projectView);
        }

        final Optional<ProjectVersionView> projectVersionView = getProjectVersion(projectView, projectRequest.getVersionRequest().getVersionName());
        return new ProjectVersionWrapper(projectView, projectVersionView.orElse(null));
    }

    public ProjectVersionView createProjectVersion(final ProjectView projectView, final ProjectVersionRequest projectVersionRequest) throws IntegrationException {
        if (!projectView.hasLink(ProjectView.VERSIONS_LINK)) {
            throw new BlackDuckIntegrationException(String.format("The supplied projectView does not have the link (%s) to create a version.", ProjectView.VERSIONS_LINK));
        }
        final String projectVersionUrl = blackDuckService.post(projectView.getFirstLink(ProjectView.VERSIONS_LINK).get(), projectVersionRequest);
        return blackDuckService.getResponse(projectVersionUrl, ProjectVersionView.class);
    }

    public ProjectVersionWrapper syncProjectAndVersion(final ProjectRequest projectRequest) throws IntegrationException {
        return syncProjectAndVersion(projectRequest, false);
    }

    public ProjectVersionWrapper syncProjectAndVersion(final ProjectRequest projectRequest, final boolean performUpdate) throws IntegrationException {
        final String projectName = projectRequest.getName();

        final Optional<ProjectView> optionalProjectView = getProjectByName(projectName);
        if (!optionalProjectView.isPresent()) {
            // nothing exists, so create and return
            return createProject(projectRequest);
        }

        // the project exists, so do updating and then deal with the version
        ProjectView projectView = optionalProjectView.get();
        if (performUpdate) {
            populateViewFromRequest(projectView, projectRequest);
            blackDuckService.put(projectView);
            projectView = blackDuckService.getResponse(projectView.getHref().get(), ProjectView.class);
        }
        ProjectVersionView projectVersionView = null;

        // dealing with the version
        if (null != projectRequest.getVersionRequest() && StringUtils.isNotBlank(projectRequest.getVersionRequest().getVersionName())) {
            final String projectVersionName = projectRequest.getVersionRequest().getVersionName();
            final Optional<ProjectVersionView> optionalProjectVersionView = getProjectVersion(projectView, projectVersionName);
            if (optionalProjectVersionView.isPresent()) {
                // the version already exists, so do updating
                projectVersionView = optionalProjectVersionView.get();
                if (performUpdate) {
                    populateViewFromRequest(projectVersionView, projectRequest.getVersionRequest());
                    blackDuckService.put(projectVersionView);
                    projectVersionView = blackDuckService.getResponse(projectVersionView.getHref().get(), ProjectVersionView.class);
                }
            } else {
                // the version did not exist, so create it
                projectVersionView = createProjectVersion(projectView, projectRequest.getVersionRequest());
            }
        }

        return new ProjectVersionWrapper(projectView, projectVersionView);
    }

    public void populateViewFromRequest(final ProjectView projectView, final ProjectRequest projectRequest) {
        try {
            BeanUtils.copyProperties(projectView, projectRequest);
        } catch (IllegalAccessException | InvocationTargetException e) {
            logger.error("Could not set properties on projectView: " + e.getMessage(), e);
        }
    }

    public void populateViewFromRequest(final ProjectVersionView projectVersionView, final ProjectVersionRequest projectVersionRequest) {
        try {
            BeanUtils.copyProperties(projectVersionView, projectVersionView);
        } catch (IllegalAccessException | InvocationTargetException e) {
            logger.error("Could not set properties on projectVersionView: " + e.getMessage(), e);
        }
    }

    public List<ProjectView> getAllProjectMatches(final String projectName) throws IntegrationException {
        return projectGetService.getAllProjectMatches(projectName);
    }

    public List<ProjectView> getProjectMatches(final String projectName, final int limit) throws IntegrationException {
        return projectGetService.getProjectMatches(projectName, limit);
    }

    public Optional<ProjectView> getProjectByName(final String projectName) throws IntegrationException {
        return projectGetService.getProjectViewByProjectName(projectName);
    }

    public Optional<ProjectVersionView> getProjectVersion(final ProjectView project, final String projectVersionName) throws IntegrationException {
        return projectGetService.getProjectVersionViewByProjectVersionName(project, projectVersionName);
    }

    public Optional<ProjectVersionWrapper> getProjectVersion(final String projectName, final String projectVersionName) throws IntegrationException {
        final Optional<ProjectView> projectView = getProjectByName(projectName);
        if (projectView.isPresent()) {
            final Optional<ProjectVersionView> projectVersionView = getProjectVersion(projectView.get(), projectVersionName);

            if (projectVersionView.isPresent()) {
                return Optional.of(new ProjectVersionWrapper(projectView.get(), projectVersionView.get()));
            }
        }

        return Optional.empty();
    }

    public List<AssignedUserView> getAssignedUsersToProject(final ProjectView project) throws IntegrationException {
        final List<AssignedUserView> assignedUsers = blackDuckService.getAllResponses(project, ProjectView.USERS_LINK_RESPONSE);
        return assignedUsers;
    }

    public List<UserView> getUsersForProject(final ProjectView project) throws IntegrationException {
        logger.debug("Attempting to get the assigned users for Project: " + project.getName());
        final List<AssignedUserView> assignedUsers = getAssignedUsersToProject(project);

        final List<UserView> resolvedUserViews = new ArrayList<>();
        for (final AssignedUserView assigned : assignedUsers) {
            final UserView userView = blackDuckService.getResponse(assigned.getUser(), UserView.class);
            if (userView != null) {
                resolvedUserViews.add(userView);
            }
        }
        return resolvedUserViews;
    }

    public List<AssignedUserGroupView> getAssignedGroupsToProject(final ProjectView project) throws IntegrationException {
        final List<AssignedUserGroupView> assignedGroups = blackDuckService.getAllResponses(project, ProjectView.USERGROUPS_LINK_RESPONSE);
        return assignedGroups;
    }

    public List<UserGroupView> getGroupsForProject(final ProjectView project) throws IntegrationException {
        logger.debug("Attempting to get the assigned users for Project: " + project.getName());
        final List<AssignedUserGroupView> assignedGroups = getAssignedGroupsToProject(project);

        final List<UserGroupView> resolvedGroupViews = new ArrayList<>();
        for (final AssignedUserGroupView assigned : assignedGroups) {
            final UserGroupView groupView = blackDuckService.getResponse(assigned.getGroup(), UserGroupView.class);
            if (groupView != null) {
                resolvedGroupViews.add(groupView);
            }
        }
        return resolvedGroupViews;
    }

    /**
     * This will get all explicitly assigned users for a project, as well as all users who are assigned to groups that are explicitly assigned to a project.
     */
    public Set<UserView> getAllActiveUsersForProject(final ProjectView projectView) throws IntegrationException {
        final Set<UserView> users = new HashSet<>();

        final List<AssignedUserGroupView> assignedGroups = getAssignedGroupsToProject(projectView);
        for (final AssignedUserGroupView assignedUserGroupView : assignedGroups) {
            if (assignedUserGroupView.getActive()) {
                final UserGroupView userGroupView = blackDuckService.getResponse(assignedUserGroupView.getGroup(), UserGroupView.class);
                if (userGroupView.getActive()) {
                    final List<UserView> groupUsers = blackDuckService.getAllResponses(userGroupView, UserGroupView.USERS_LINK_RESPONSE);
                    users.addAll(groupUsers);
                }
            }
        }

        final List<AssignedUserView> assignedUsers = getAssignedUsersToProject(projectView);
        for (final AssignedUserView assignedUser : assignedUsers) {
            final UserView userView = blackDuckService.getResponse(assignedUser.getUser(), UserView.class);
            users.add(userView);
        }

        return users
                       .stream()
                       .filter(userView -> userView.getActive())
                       .collect(Collectors.toSet());
    }

    public List<VersionBomComponentView> getComponentsForProjectVersion(final ProjectVersionView projectVersionView) throws IntegrationException {
        final List<VersionBomComponentView> versionBomComponentViews = blackDuckService.getAllResponses(projectVersionView, ProjectVersionView.COMPONENTS_LINK_RESPONSE);
        return versionBomComponentViews;
    }

    public List<VulnerableComponentView> getVulnerableComponentsForProjectVersion(final ProjectVersionView projectVersionView) throws IntegrationException {
        final List<VulnerableComponentView> vulnerableBomComponentViews = blackDuckService.getAllResponses(projectVersionView, ProjectVersionView.VULNERABLE_COMPONENTS_LINK_RESPONSE);
        return vulnerableBomComponentViews;
    }

    public List<ComponentVersionVulnerabilities> getComponentVersionVulnerabilities(final ProjectVersionView projectVersionView) throws IntegrationException {
        final List<VersionBomComponentView> versionBomComponentViews = getComponentsForProjectVersion(projectVersionView);
        final List<ComponentVersionView> componentVersionViews = new ArrayList<>();
        for (final VersionBomComponentView versionBomComponentView : versionBomComponentViews) {
            if (StringUtils.isNotBlank(versionBomComponentView.getComponentVersion())) {
                final ComponentVersionView componentVersionView = blackDuckService.getResponse(versionBomComponentView.getComponentVersion(), ComponentVersionView.class);
                componentVersionViews.add(componentVersionView);
            }
        }

        final List<ComponentVersionVulnerabilities> componentVersionVulnerabilitiesList = new ArrayList<>();
        for (final ComponentVersionView componentVersionView : componentVersionViews) {
            final ComponentVersionVulnerabilities componentVersionVulnerabilities = componentService.getComponentVersionVulnerabilities(componentVersionView);
            componentVersionVulnerabilitiesList.add(componentVersionVulnerabilities);
        }
        return componentVersionVulnerabilitiesList;
    }

    public List<VersionBomComponentModel> getComponentsWithMatchedFilesForProjectVersion(final ProjectVersionView version) throws IntegrationException {
        final List<VersionBomComponentView> bomComponents = blackDuckService.getAllResponses(version, ProjectVersionView.COMPONENTS_LINK_RESPONSE);
        final List<VersionBomComponentModel> modelBomComponents = new ArrayList<>(bomComponents.size());
        for (final VersionBomComponentView component : bomComponents) {
            modelBomComponents.add(new VersionBomComponentModel(component, getMatchedFiles(component)));
        }
        return modelBomComponents;
    }

    public Optional<VersionBomPolicyStatusView> getPolicyStatusForVersion(final ProjectVersionView version) throws IntegrationException {
        return blackDuckService.getResponse(version, ProjectVersionView.POLICY_STATUS_LINK_RESPONSE);
    }

    public Optional<String> addComponentToProjectVersion(final ExternalId componentExternalId, final ProjectVersionView projectVersionView) throws IntegrationException {
        final String projectVersionComponentsUrl = projectVersionView.getFirstLink(ProjectVersionView.COMPONENTS_LINK).orElse(null);
        final Optional<ComponentSearchResultView> componentSearchResultView = componentService.getExactComponentMatch(componentExternalId);
        String componentVersionUrl = null;
        if (componentSearchResultView.isPresent()) {
            if (StringUtils.isNotBlank(componentSearchResultView.get().getVariant())) {
                componentVersionUrl = componentSearchResultView.get().getVariant();
            } else {
                componentVersionUrl = componentSearchResultView.get().getVersion();
            }
            addComponentToProjectVersion("application/json", projectVersionComponentsUrl, componentVersionUrl);
        }

        return Optional.ofNullable(componentVersionUrl);
    }

    public void addComponentToProjectVersion(final String mediaType, final String projectVersionComponentsUri, final String componentVersionUrl) throws IntegrationException {
        final Request request = RequestFactory.createCommonPostRequestBuilder("{\"component\": \"" + componentVersionUrl + "\"}").uri(projectVersionComponentsUri).mimeType(mediaType).build();
        try (Response response = blackDuckService.execute(request)) {
        } catch (final IOException e) {
            throw new IntegrationException(e.getMessage(), e);
        }
    }

    private List<MatchedFileView> getMatchedFiles(final VersionBomComponentView component) throws IntegrationException {
        List<MatchedFileView> matchedFiles = new ArrayList<>(0);
        final List<MatchedFileView> tempMatchedFiles = blackDuckService.getAllResponses(component, VersionBomComponentView.MATCHED_FILES_LINK_RESPONSE);
        if (tempMatchedFiles != null && !tempMatchedFiles.isEmpty()) {
            matchedFiles = tempMatchedFiles;
        }
        return matchedFiles;
    }

}
