/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

export enum EAuthenticationPageType {
  STATIC = "STATIC",
  NOT_AUTHENTICATED = "NOT_AUTHENTICATED",
  AUTHENTICATED = "AUTHENTICATED",
}

export enum EInstancePageType {
  PRE_SETUP = "PRE_SETUP",
  POST_SETUP = "POST_SETUP",
}

export enum EUserStatus {
  ERROR = "ERROR",
  AUTHENTICATION_NOT_DONE = "AUTHENTICATION_NOT_DONE",
  NOT_YET_READY = "NOT_YET_READY",
}

export type TUserStatus = {
  status: EUserStatus | undefined;
  message?: string;
};

export enum EUserPermissionsLevel {
  WORKSPACE = "WORKSPACE",
  PROJECT = "PROJECT",
}

export type TUserPermissionsLevel = EUserPermissionsLevel;

export enum EUserPermissions {
  ADMIN = 20,
  MEMBER = 15,
  GUEST = 5,
}
export type TUserPermissions = EUserPermissions;

export type TUserAllowedPermissionsObject = {
  create: TUserPermissions[];
  update: TUserPermissions[];
  delete: TUserPermissions[];
  read: TUserPermissions[];
};
export type TUserAllowedPermissions = {
  workspace: {
    [key: string]: Partial<TUserAllowedPermissionsObject>;
  };
  project: {
    [key: string]: Partial<TUserAllowedPermissionsObject>;
  };
};

export const USER_ALLOWED_PERMISSIONS: TUserAllowedPermissions = {
  workspace: {
    dashboard: {
      read: [EUserPermissions.ADMIN, EUserPermissions.MEMBER, EUserPermissions.GUEST],
    },
  },
  project: {
    issue: {
      read: [EUserPermissions.ADMIN, EUserPermissions.MEMBER, EUserPermissions.GUEST],
      create: [EUserPermissions.ADMIN, EUserPermissions.MEMBER],
      update: [EUserPermissions.ADMIN, EUserPermissions.MEMBER],
      delete: [EUserPermissions.ADMIN, EUserPermissions.MEMBER],
    },
    cycle: {
      read: [EUserPermissions.ADMIN, EUserPermissions.MEMBER, EUserPermissions.GUEST],
      create: [EUserPermissions.ADMIN, EUserPermissions.MEMBER],
      update: [EUserPermissions.ADMIN, EUserPermissions.MEMBER],
      delete: [EUserPermissions.ADMIN],
    },
    module: {
      read: [EUserPermissions.ADMIN, EUserPermissions.MEMBER, EUserPermissions.GUEST],
      create: [EUserPermissions.ADMIN, EUserPermissions.MEMBER],
      update: [EUserPermissions.ADMIN, EUserPermissions.MEMBER],
      delete: [EUserPermissions.ADMIN],
    },
    member: {
      read: [EUserPermissions.ADMIN, EUserPermissions.MEMBER, EUserPermissions.GUEST],
      create: [EUserPermissions.ADMIN],
      update: [EUserPermissions.ADMIN],
      delete: [EUserPermissions.ADMIN],
    },
    settings: {
      read: [EUserPermissions.ADMIN, EUserPermissions.MEMBER, EUserPermissions.GUEST],
      create: [EUserPermissions.ADMIN],
      update: [EUserPermissions.ADMIN],
      delete: [EUserPermissions.ADMIN],
    },
  },
};

/**
 * Human-readable labels for project roles.
 * Maps the numeric permission levels to the RBAC role names:
 *   GUEST  (5)  → Viewer      (read-only access)
 *   MEMBER (15) → Contributor (can create/edit issues, cycles, modules)
 *   ADMIN  (20) → Admin       (full control including settings and members)
 */
export const PROJECT_ROLE_LABELS: Record<EUserPermissions, string> = {
  [EUserPermissions.GUEST]: "Viewer",
  [EUserPermissions.MEMBER]: "Contributor",
  [EUserPermissions.ADMIN]: "Admin",
};
