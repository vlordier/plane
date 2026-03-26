/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import type { ReactNode } from "react";
import { observer } from "mobx-react";
// plane imports
import type { TUserPermissions, TUserPermissionsLevel } from "@plane/constants";
import { EUserPermissionsLevel } from "@plane/constants";
// hooks
import { useUserPermissions } from "@/hooks/store/user";

type Props = {
  /** The permission levels that are allowed to see the children. */
  allowedRoles: TUserPermissions[];
  /** Whether to check workspace-level or project-level permissions. Defaults to PROJECT. */
  level?: TUserPermissionsLevel;
  /** Optional workspace slug override; uses the current route value when omitted. */
  workspaceSlug?: string;
  /** Optional project id override; uses the current route value when omitted. */
  projectId?: string;
  /** Content rendered when the user has the required permission. */
  children: ReactNode;
  /** Content rendered when the user does not have the required permission. Defaults to null. */
  fallback?: ReactNode;
};

/**
 * Conditionally renders `children` when the current user's role is included in
 * `allowedRoles`, or renders `fallback` (default: nothing) otherwise.
 *
 * Example – show "Create Issue" button only to contributors and admins:
 * ```tsx
 * <PermissionGate allowedRoles={[EUserPermissions.ADMIN, EUserPermissions.MEMBER]}>
 *   <Button onClick={openModal}>Create Issue</Button>
 * </PermissionGate>
 * ```
 */
export const PermissionGate = observer(function PermissionGate({
  allowedRoles,
  level = EUserPermissionsLevel.PROJECT,
  workspaceSlug,
  projectId,
  children,
  fallback = null,
}: Props) {
  const { allowPermissions } = useUserPermissions();

  if (!allowPermissions(allowedRoles, level, workspaceSlug, projectId)) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
});
