/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { EUserPermissions, EUserPermissionsLevel, USER_ALLOWED_PERMISSIONS } from "@plane/constants";
// hooks
import { useUserPermissions } from "./user-permissions";

/**
 * Returns a set of boolean permission flags for a project, derived from the
 * current user's project role (viewer / contributor / admin).
 *
 * Role hierarchy:
 *   GUEST  (5)  = Viewer      – read-only
 *   MEMBER (15) = Contributor – can create/edit issues, cycles, and modules
 *   ADMIN  (20) = Admin       – full control (settings, members, delete)
 *
 * @param workspaceSlug - Optional workspace slug; falls back to the router value when omitted.
 * @param projectId     - Optional project id; falls back to the router value when omitted.
 */
export const useProjectPermissions = (workspaceSlug?: string, projectId?: string) => {
  const { allowPermissions } = useUserPermissions();

  const allow = (roles: EUserPermissions[]) =>
    allowPermissions(roles, EUserPermissionsLevel.PROJECT, workspaceSlug, projectId);

  const { issue, cycle, module: mod, member, settings } = USER_ALLOWED_PERMISSIONS.project;

  return {
    // ── Issue permissions ──────────────────────────────────────────────
    canReadIssue: allow(issue.read ?? []),
    canCreateIssue: allow(issue.create ?? []),
    canEditIssue: allow(issue.update ?? []),
    canDeleteIssue: allow(issue.delete ?? []),

    // ── Cycle permissions ──────────────────────────────────────────────
    canReadCycle: allow(cycle.read ?? []),
    canCreateCycle: allow(cycle.create ?? []),
    canEditCycle: allow(cycle.update ?? []),
    canDeleteCycle: allow(cycle.delete ?? []),

    // ── Module permissions ─────────────────────────────────────────────
    canReadModule: allow(mod.read ?? []),
    canCreateModule: allow(mod.create ?? []),
    canEditModule: allow(mod.update ?? []),
    canDeleteModule: allow(mod.delete ?? []),

    // ── Member management ──────────────────────────────────────────────
    canReadMember: allow(member.read ?? []),
    canInviteMember: allow(member.create ?? []),
    canUpdateMemberRole: allow(member.update ?? []),
    canRemoveMember: allow(member.delete ?? []),

    // ── Project settings ───────────────────────────────────────────────
    canReadSettings: allow(settings.read ?? []),
    canUpdateSettings: allow(settings.update ?? []),

    // ── Convenience role checks ────────────────────────────────────────
    /** True when the user has at least viewer (read-only) access. */
    isViewerOrAbove: allow([EUserPermissions.ADMIN, EUserPermissions.MEMBER, EUserPermissions.GUEST]),
    /** True when the user has at least contributor access (can mutate content). */
    isContributorOrAbove: allow([EUserPermissions.ADMIN, EUserPermissions.MEMBER]),
    /** True when the user is a project admin. */
    isAdmin: allow([EUserPermissions.ADMIN]),
  };
};
