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

import static java.util.Collections.emptySet;

import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Principal;
import java.util.Set;
import javax.security.auth.Subject;

/**
 * A Policy object is responsible for determining whether a caller principal (including the unauthenticated one) has permission
 * to perform a security-sensitive operation.
 *
 * <p>
 * A Policy uses the {@link Subject} as a holder for the caller principal. A Subject, being a "bag of principals" does not
 * specify which of the potentially many principals represents the caller principal. As a low level artifact (aimed at
 * Jakarta EE runtime interaction with the security system) this allows for an amount of runtime specific behaviour and optimisations.
 *
 * <p>
 * Policies typically, but not necessarily, make use of the Permission instances hold by the {@link PolicyConfiguration} instance for
 * a given policy context. In a Jakarta EE Servlet environment these contain the transformed security constraints as expressed by XML
 * in web.xml, via annotations, or which are programmatically set using the Jakarta Servlet APIs.
 *
 * @author Arjan Tijms
 */
public interface Policy {

    /**
     * This method checks whether the permission represented by the @{permissionToBeChecked} parameter is granted to
     * the caller principal within the @{subject} parameter.
     *
     * @param permissionToBeChecked the permission this policy is going to check
     * @param subject holder of the (obscured) caller principal
     * @return true if the caller principal has the requested permission, false otherwise
     */
    default boolean implies(Permission permissionToBeChecked, Subject subject) {
        if (isExcluded(permissionToBeChecked)) {
            return false;
        }

        if (isUnchecked(permissionToBeChecked)) {
            return true;
        }

        return impliesByRole(permissionToBeChecked, subject);
    }

    /**
     * This method checks whether the permission represented by the @{permissionToBeChecked} parameter is
     * excluded by this policy. Excluded means the permission is not granted to any caller.
     *
     * @param permissionToBeChecked the permission this policy is going to check
     * @return true if the requested permission is excluded, false otherwise
     */
    default boolean isExcluded(Permission permissionToBeChecked) {
        throw new UnsupportedOperationException();
    }

    /**
     * This method checks whether the permission represented by the @{permissionToBeChecked} parameter is
     * unchecked by this policy. Unchecked means the permission is granted to any caller, either authenticated
     * or not.
     *
     * @param permissionToBeChecked the permission this policy is going to check
     * @return true if the requested permission is unchecked, false otherwise
     */
    default boolean isUnchecked(Permission permissionToBeChecked) {
        throw new UnsupportedOperationException();
    }

    /**
     * This method checks whether the permission represented by the @{permissionToBeChecked} parameter is granted to
     * the caller principal within the @{subject} parameter based on one or more roles associated with that
     * caller principal.
     *
     * @param permissionToBeChecked the permission this policy is going to check
     * @param subject holder of the (obscured) caller principal
     * @return true if the caller principal has the requested permission, false otherwise
     */
    default boolean impliesByRole(Permission permissionToBeChecked, Subject subject) {
        throw new UnsupportedOperationException();
    }

    /**
     * Returns a collection of at least all declared permissions associated with the caller principal
     * contained in the @{subject} parameter.
     *
     * <p>
     * Policies can represent remote authorization systems which may not be able to provide all permissions, and
     * there for this method cannot guarantee all permissions are indeed returned. The policy should however
     * return at least all permissions which are declared or set within a Jakarta EE application. Examples of such permissions
     * are the permissions transformed from the Jakarta Servlet security constraints expression in @{web.xml}, via annotations
     * or programmatically using the Jakarta Servlet API.
     *
     * @param subject holder of the (obscured) caller principal
     * @return a collection of permissions associated with the caller principal
     */
    PermissionCollection getPermissionCollection(Subject subject);

    /**
     * This method checks whether the permission represented by the @{permissionToBeChecked} parameter is granted to
     * the anonymous (unauthenticated) caller principal.
     *
     * @param permissionToBeChecked the permission this policy is going to check
     * @return true if the anonymous caller principal has the requested permission, false otherwise
     */
    default boolean implies(Permission permissionToBeChecked) {
        return implies(permissionToBeChecked, emptySet());
    }

    /**
     * Returns a collection of at least all declared permissions associated with the caller principal
     * contained in the set of principals being passed in.
     *
     * <p>
     * Policies can represent remote authorization systems which may not be able to provide all permissions, and
     * there for this method cannot guarantee all permissions are indeed returned. The policy should however
     * return at least all permissions which are declared or set within a Jakarta EE application. Examples of such permissions
     * are the permissions transformed from the Jakarta Servlet security constraints expression in @{web.xml}, via annotations
     * or programmatically using the Jakarta Servlet API.
     *
     * @param permissionToBeChecked the permission this policy is going to check
     * @param principals collection containing the (obscured) caller principal
     * @return a collection of permissions associated with the caller principal
     */
    default boolean implies(Permission permissionToBeChecked, Set<Principal> principals) {
        Subject subject = new Subject();
        subject.getPrincipals().addAll(principals);

        return implies(permissionToBeChecked, subject);
    }

    /**
     * Optional method; TODO: needed?
     */
    default void refresh() { }

}
