/*
 * Copyright (c) 2021, 2022 Contributors to Eclipse Foundation. All rights reserved.
 * Copyright (c) 1997, 2020 Oracle and/or its affiliates. All rights reserved.
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

import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Map;

/**
 * The methods of this interface are used by containers to create policy statements in a Policy provider. An object that
 * implements the PolicyConfiguration interface provides the policy statement configuration interface for a
 * corresponding policy context within the corresponding Policy provider.
 *
 * <p>
 * The life cycle of a policy context is defined by three states; "open", "inService", and "deleted". A policy context
 * is in one of these three states.
 *
 * <p>
 * A policy context in the "open" state is in the process of being configured, and may be operated on by any of the
 * methods of the PolicyConfiguration interface. A policy context in the "open" state must not be assimilated at
 * <code>Policy.refresh</code> into the policy statements used by the Policy provider in performing its access
 * decisions. In order for the policy statements of a policy context to be assimilated by the associated provider, the
 * policy context must be in the "inService" state. A policy context in the "open" state is transitioned to the
 * "inService" state by calling the commit method.
 *
 * <p>
 * A policy context in the "inService" state is available for assimilation into the policy statements being used to
 * perform access decisions by the associated Policy provider. Providers assimilate policy contexts containing policy
 * statements when the refresh method of the provider is called. When a provider's refresh method is called, it must
 * assimilate only those policy contexts whose state is "inService" and it must ensure that the policy statements put
 * into service for each policy context are only those defined in the context at the time of the call to refresh. A
 * policy context in the "inService" state is not available for additional configuration and may be returned to the
 * "open" state by calling the getPolicyConfiguration method of the PolicyConfigurationFactory.
 *
 * <p>
 * A policy context in the "deleted" state is neither available for configuration, nor is it available for assimilation
 * into the Provider. A policy context whose state is "deleted" may be reclaimed for subsequent processing by calling
 * the getPolicyConfiguration method of the associated PolicyConfigurationFactory. A "deleted" policy context is
 * transitioned to the "open" state when it it returned as a result of a call to getPolicyConfiguration.
 *
 * <p>
 * The following table captures the correspondence between the policy context life cycle and the methods of the
 * PolicyConfiguration interface. The rightmost 3 columns of the table correspond to the PolicyConfiguration state
 * identified at the head of the column. The values in the cells of these columns indicate the next state resulting from
 * a call to the method identified in the leftmost column of the corresponding row, or that calling the method is
 * unsupported in the state represented by the column (in which case the state will remain unchanged).
 *
 * <br>
 * <br>
 * <table border="1">
 * <caption>PolicyConfiguration State Table</caption>
 * <tr>
 * <th valign="middle" rowspan="2" colspan="1" >Method</th>
 * <th valign="top" rowspan="1" colspan="3" >Current State to Next State</th>
 * </tr>
 * <tr>
 * <th>deleted</th>
 * <th>open</th>
 * <th>inService</th>
 * </tr>
 * <tr>
 * <td>addToExcludedPolicy</td>
 * <td>Unsupported Operation</td>
 * <td>open</td>
 * <td>Unsupported Operation</td>
 * </tr>
 * <tr>
 * <td>addToRole</td>
 * <td>Unsupported Operation</td>
 * <td>open</td>
 * <td>Unsupported Operation</td>
 * </tr>
 * <tr>
 * <td>addToUncheckedPolicy</td>
 * <td>Unsupported Operation</td>
 * <td>open</td>
 * <td>Unsupported Operation</td>
 * </tr>
 * <tr>
 * <td>commit</td>
 * <td>Unsupported Operation</td>
 * <td>inService</td>
 * <td>inService</td>
 * </tr>
 * <tr>
 * <td>delete</td>
 * <td>deleted</td>
 * <td>deleted</td>
 * <td>deleted</td>
 * </tr>
 * <tr>
 * <td>getContextID</td>
 * <td>deleted</td>
 * <td>open</td>
 * <td>inService</td>
 * </tr>
 * <tr>
 * <td>inService</td>
 * <td>deleted</td>
 * <td>open</td>
 * <td>inService</td>
 * </tr>
 * <tr>
 * <td>linkConfiguration</td>
 * <td>Unsupported Operation</td>
 * <td>open</td>
 * <td>Unsupported Operation</td>
 * </tr>
 * <tr>
 * <td>removeExcludedPolicy</td>
 * <td>Unsupported Operation</td>
 * <td> open</td>
 * <td>Unsupported Operation</td>
 * </tr>
 * <tr>
 * <td>removeRole</td>
 * <td>Unsupported Operation</td>
 * <td>open</td>
 * <td>Unsupported Operation</td>
 * </tr>
 * <tr>
 * <td>removeUncheckedPolicy</td>
 * <td>Unsupported Operation</td>
 * <td>open</td>
 * <td>Unsupported Operation</td>
 * </tr>
 * </table>
 * <br>
 *
 * <p>
 * For a provider implementation to be compatible with multi-threaded environments, it may be necessary to synchronize
 * the refresh method of the provider with the methods of its PolicyConfiguration interface and with the
 * getPolicyConfiguration and inService methods of its PolicyConfigurationFactory.
 *
 * @see java.security.Permission
 * @see java.security.PermissionCollection
 * @see PolicyContextException
 * @see jakarta.security.jacc.PolicyConfigurationFactory
 *
 * @author Ron Monzillo
 * @author Gary Ellison
 */
public interface PolicyConfiguration {

    /**
     * This method returns this object's policy context identifier.
     *
     * @return this object's policy context identifier.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the getContextID method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    String getContextID() throws PolicyContextException;

    /**
     * Used to add permissions to a named role in this PolicyConfiguration. If the named role does not exist in the
     * PolicyConfiguration, it is created as a result of the call to this function.
     *
     * <p>
     * It is the job of the Policy provider to ensure that all the permissions added to a role are granted to principals
     * "mapped to the role".
     *
     * @param roleName the name of the Role to which the permissions are to be added.
     * @param permissions the collection of permissions to be added to the role. The collection may be either a homogeneous
     * or heterogeneous collection.
     *
     * @throws UnsupportedOperationException if the state of the policy context whose interface is this
     * PolicyConfiguration Object is "deleted" or "inService" when this method is called.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the addToRole method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    void addToRole(String roleName, PermissionCollection permissions) throws PolicyContextException;

    /**
     * Used to add a single permission to a named role in this PolicyConfiguration. If the named role does not exist in the
     * PolicyConfiguration, it is created as a result of the call to this function.
     *
     * <p>
     * It is the job of the Policy provider to ensure that all the permissions added to a role are granted to principals
     * "mapped to the role".
     *
     * @param roleName the name of the Role to which the permission is to be added.
     * @param permission the permission to be added to the role.
     *
     * @throws UnsupportedOperationException if the state of the policy context whose interface is this
     * PolicyConfiguration Object is "deleted" or "inService" when this method is called.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the addToRole method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    void addToRole(String roleName, Permission permission) throws PolicyContextException;

    /**
     * Used to add unchecked policy statements to this PolicyConfiguration.
     *
     * @param permissions the collection of permissions to be added as unchecked policy statements. The collection may be
     * either a homogeneous or heterogeneous collection.
     *
     * @throws UnsupportedOperationException if the state of the policy context whose interface is this
     * PolicyConfiguration Object is "deleted" or "inService" when this method is called.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the addToUncheckedPolicy method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    void addToUncheckedPolicy(PermissionCollection permissions) throws PolicyContextException;

    /**
     * Used to add a single unchecked policy statement to this PolicyConfiguration.
     *
     * @param permission the permission to be added to the unchecked policy statements.
     *
     * @throws UnsupportedOperationException if the state of the policy context whose interface is this
     * PolicyConfiguration Object is "deleted" or "inService" when this method is called.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the addToUncheckedPolicy method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    void addToUncheckedPolicy(Permission permission) throws PolicyContextException;

    /**
     * Used to add excluded policy statements to this PolicyConfiguration.
     *
     * @param permissions the collection of permissions to be added to the excluded policy statements. The collection may be
     * either a homogeneous or heterogeneous collection.
     *
     * @throws UnsupportedOperationException if the state of the policy context whose interface is this
     * PolicyConfiguration Object is "deleted" or "inService" when this method is called.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the addToExcludedPolicy method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    void addToExcludedPolicy(PermissionCollection permissions) throws PolicyContextException;

    /**
     * Used to add a single excluded policy statement to this PolicyConfiguration.
     *
     * @param permission the permission to be added to the excluded policy statements.
     *
     * @throws UnsupportedOperationException if the state of the policy context whose interface is this
     * PolicyConfiguration Object is "deleted" or "inService" when this method is called.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the addToExcludedPolicy method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    void addToExcludedPolicy(Permission permission) throws PolicyContextException;

    /**
     * Used to return all per role policy statements that have been added to this PolicyConfiguration via
     * prior calls to {@link PolicyConfiguration#addToRole(String, Permission)}
     * and {@link PolicyConfiguration#addToRole(String, PermissionCollection)}, indexed by the role names used
     * in those calls.
     *
     * @return map of all per role policy statements that have been added to this PolicyConfiguration.
     */
    Map<String, PermissionCollection> getPerRolePermissions();

    /**
     * Used to return all unchecked policy statements that have been added to this PolicyConfiguration via
     * prior calls to {@link PolicyConfiguration#addToUncheckedPolicy(Permission)}
     * and {@link PolicyConfiguration#addToUncheckedPolicy(PermissionCollection)}.
     *
     * @return the collection of all unchecked policy statements that have been added to this PolicyConfiguration.
     */
    PermissionCollection getUncheckedPermissions();

    /**
     * Used to return all excluded policy statements that have been added to this PolicyConfiguration via
     * prior calls to {@link PolicyConfiguration#addToExcludedPolicy(Permission)}
     * and {@link PolicyConfiguration#addToExcludedPolicy(PermissionCollection)}.
     *
     * @return the collection of all excluded policy statements that have been added to this PolicyConfiguration.
     */
    PermissionCollection getExcludedPermissions();

    /**
     * Used to remove a role and all its permissions from this PolicyConfiguration. This method has no effect on the links
     * between this PolicyConfiguration and others.
     *
     * @param roleName the name of the role to remove from this PolicyConfiguration. If the value of the roleName parameter
     * is "*" and no role with name "*" exists in this PolicyConfiguration, then all roles must be removed from this
     * PolicyConfiguration.
     *
     * @throws UnsupportedOperationException if the state of the policy context whose interface is this
     * PolicyConfiguration Object is "deleted" or "inService" when this method is called.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the removeRole method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    void removeRole(String roleName) throws PolicyContextException;

    /**
     * Used to remove any unchecked policy statements from this PolicyConfiguration. This method has no effect on the links
     * between this PolicyConfiguration and others.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the removeUncheckedPolicy method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    void removeUncheckedPolicy() throws PolicyContextException;

    /**
     * Used to remove any excluded policy statements from this PolicyConfiguration. This method has no effect on the links
     * between this PolicyConfiguration and others.
     *
     * @throws UnsupportedOperationException if the state of the policy context whose interface is this
     * PolicyConfiguration Object is "deleted" or "inService" when this method is called.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the removeExcludedPolicy method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    void removeExcludedPolicy() throws PolicyContextException;

    /**
     * Creates a relationship between this configuration and another such that they share the same principal-to-role
     * mappings. PolicyConfigurations are linked to apply a common principal-to-role mapping to multiple separately
     * manageable PolicyConfigurations, as is required when an application is composed of multiple modules.
     *
     * <p>
     * Note that the policy statements which comprise a role, or comprise the excluded or unchecked policy collections in a
     * PolicyConfiguration are unaffected by the configuration being linked to another.
     *
     * <p>
     * The relationship formed by this method is symmetric, transitive and idempotent. If the argument PolicyConfiguration
     * does not have a different Policy context identifier than this PolicyConfiguration no relationship is formed, and an
     * exception, as described below, is thrown.
     *
     * @param link A reference to a different PolicyConfiguration than this PolicyConfiguration.
     *
     * @throws UnsupportedOperationException if the state of the policy context whose interface is this
     * PolicyConfiguration Object is "deleted" or "inService" when this method is called.
     *
     * @throws IllegalArgumentException if called with an argument PolicyConfiguration whose Policy context is
     * equivalent to that of this PolicyConfiguration.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the linkConfiguration method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    void linkConfiguration(PolicyConfiguration link) throws PolicyContextException;

    /**
     * Causes all policy statements to be deleted from this PolicyConfiguration and sets its internal state such that
     * calling any method, other than delete, getContextID, or inService on the PolicyConfiguration will be rejected and
     * cause an UnsupportedOperationException to be thrown.
     *
     * <p>
     * This operation has no affect on any linked PolicyConfigurations other than removing any links involving the deleted
     * PolicyConfiguration.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the delete method signature. The exception thrown by the implementation class will be encapsulated
     * (during construction) in the thrown PolicyContextException.
     */
    void delete() throws PolicyContextException;

    /**
     * This method is used to set to "inService" the state of the policy context whose interface is this PolicyConfiguration
     * Object. Only those policy contexts whose state is "inService" will be included in the policy contexts processed by
     * the Policy.refresh method. A policy context whose state is "inService" may be returned to the "open" state by calling
     * the getPolicyConfiguration method of the PolicyConfiguration factory with the policy context identifier of the policy
     * context.
     *
     * <p>
     * When the state of a policy context is "inService", calling any method other than commit, delete, getContextID, or
     * inService on its PolicyConfiguration Object will cause an UnsupportedOperationException to be thrown.
     *
     * @throws UnsupportedOperationException if the state of the policy context whose interface is this
     * PolicyConfiguration Object is "deleted" when this method is called.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the commit method signature. The exception thrown by the implementation class will be encapsulated
     * (during construction) in the thrown PolicyContextException.
     */
    void commit() throws PolicyContextException;

    /**
     * This method is used to determine if the policy context whose interface is this PolicyConfiguration Object is in the
     * "inService" state.
     *
     * @return true if the state of the associated policy context is "inService"; false otherwise.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the inService method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    boolean inService() throws PolicyContextException;
}
