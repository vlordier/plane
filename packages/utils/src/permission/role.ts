/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

// plane imports
import { EUserPermissions, PROJECT_ROLE_LABELS } from "@plane/constants";
import type { EUserProjectRoles, EUserWorkspaceRoles } from "@plane/types";

export const getUserRole = (role: EUserPermissions | EUserWorkspaceRoles | EUserProjectRoles) => {
  switch (role) {
    case EUserPermissions.GUEST:
      return "GUEST";
    case EUserPermissions.MEMBER:
      return "MEMBER";
    case EUserPermissions.ADMIN:
      return "ADMIN";
  }
};

/**
 * Returns the human-readable project role label for a given permission level.
 * Maps numeric roles to RBAC display names: Viewer / Contributor / Admin.
 * @param role - The numeric permission level
 * @returns The display label, or undefined if the role is unrecognized
 */
export const getProjectRoleLabel = (
  role: EUserPermissions | EUserProjectRoles | EUserWorkspaceRoles | undefined
): string | undefined => {
  if (role === undefined) return undefined;
  return PROJECT_ROLE_LABELS[role as EUserPermissions];
};

type TSupportedRole = EUserPermissions | EUserProjectRoles | EUserWorkspaceRoles;

/**
 * @description Returns the highest role from an array of supported roles
 * @param { TSupportedRole[] } roles
 * @returns { TSupportedRole | undefined }
 */
export const getHighestRole = <T extends TSupportedRole>(roles: T[]): T | undefined => {
  if (!roles || roles.length === 0) return undefined;
  return roles.reduce((highest, current) => (current > highest ? current : highest));
};
