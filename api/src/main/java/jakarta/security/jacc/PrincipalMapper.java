/*
 * Copyright (c) 2023, 2024 Contributors to Eclipse Foundation. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */
package jakarta.security.jacc;

import java.security.Principal;
import java.util.Set;
import javax.security.auth.Subject;

/**
 * A PrincipalMapper is an object that maps from a collection of generic Principals
 * or a Subject to well known entities in Jakarta EE.
 *
 * <p>
 * The following target entities are supported:
 *
 * <ul>
 *  <li> The caller principal -  a {@code java.security.Principal} containing the
 *       name of the current authenticated user.
 *  <li> The role - a {@code java.lang.String} representing the logical application role
 *       associated with the caller principal.
 * </ul>
 *
 * <p>
 * A PrincipalMapper is intended to be used by a {@link Policy}, but should work
 * outside a {@link Policy} (for instance, during request processing in a Servlet container).
 *
 * @author Arjan Tijms
 */
public interface PrincipalMapper {

    /**
     * Pick from the principals within the passed-in Subject the platform-specific <code>java.security.Principal</code>
     * that represents the name of authenticated caller, or null if the current caller is not authenticated.
     *
     * @param subject the subject from which the caller principal is to be retrieved.
     * @return Principal representing the name of the current authenticated user, or null if not authenticated.
     */
    Principal getCallerPrincipal(Subject subject);

    /**
     * Pick from the principals within the passed-in Subject all application roles that are associated with
     * the caller principal.
     *
     * <p>
     * The roles returned here are the logical application roles. If the principals in the passed-in Subject
     * represent non-application roles (called "groups"), the implementation must perform the group-to-role mapping.
     * For instance, if a Principal representing the group "adm" is present in the Subject, and the group "adm" is
     * mapped (in a implementation specific way) to "administrator", then "administrator" must be returned here.
     *
     * @param subject the subject from which the roles are to be retrieved.
     * @return a set of logical application roles associated with the caller principal.
     */
    Set<String> getMappedRoles(Subject subject);

    /**
     * Pick from the principals within the passed-in set of principals the platform-specific
     * <code>java.security.Principal</code> that represents the name of the authenticated caller, or null if the
     * current caller is not authenticated.
     *
     * @param principals the set of principals from which the caller principal is to be retrieved.
     * @return Principal representing the name of the current authenticated user, or null if not authenticated.
     */
    default Principal getCallerPrincipal(Set<Principal> principals) {
        Subject subject = new Subject();
        subject.getPrincipals().addAll(principals);

        return getCallerPrincipal(subject);
    }

    /**
     * Pick from the principals within the passed-in set of principals all application roles that are associated with
     * the caller principal.
     *
     * <p>
     * The roles returned here are the logical application roles. If the principals in the passed-in Subject
     * represent non-application roles (called "groups"), the implementation must perform the group-to-role mapping.
     * For instance, if a Principal representing the group "adm" is present in the Subject, and the group "adm" is
     * mapped (in a implementation specific way) to "administrator", then "administrator" must be returned here.
     *
     * @param principals the set of principals from which the roles are to be retrieved.
     * @return a set of logical application roles associated with the caller principal.
     */
    default Set<String> getMappedRoles(Set<Principal> principals) {
        Subject subject = new Subject();
        subject.getPrincipals().addAll(principals);

        return getMappedRoles(subject);
    }

    /**
     * Jakarta Security defines the "any authenticated caller role" as "**" and allows an application specific mapping for
     * this role to be established. E.g. "**" could be mapped to the logical application role "admin".
     *
     * <p>
     * This method is used to discover if such a mapping has indeed been done. If it has been done, "**" is a regular role name
     * and we can no longer check for "any authenticated caller" using "**".
     *
     * @return true if the special "**" role has been mapped to something else, false otherwise.
     */
    default boolean isAnyAuthenticatedUserRoleMapped() {
        return false;
    }

}
