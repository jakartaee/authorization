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

import java.security.AccessController;
import java.security.Permission;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.SecurityPermission;

/**
 * Abstract factory and finder class for obtaining the instance of the class that implements the
 * PolicyConfigurationFactory of a provider. The factory will be used to instantiate PolicyConfiguration objects that
 * will be used by the deployment tools of the container to create and manage policy contexts within the Policy
 * Provider.
 *
 * <p>
 * Implementation classes must have a public no argument constructor that may be used to create an operational instance
 * of the factory implementation class.
 *
 * @see Permission
 * @see PolicyConfiguration
 * @see PolicyContextException
 *
 * @author Ron Monzillo
 * @author Gary Ellison
 * @author Harpreet Singh
 */
public abstract class PolicyConfigurationFactory {
    private static String FACTORY_NAME = "jakarta.security.jacc.PolicyConfigurationFactory.provider";

    private static volatile PolicyConfigurationFactory policyConfigurationFactory;

    /**
     * This static method uses a system property to find and instantiate (via a public constructor) a provider specific
     * factory implementation class.
     *
     * <p>
     * The name of the provider specific factory implementation class is obtained from the
     * value of the system property,
     * <pre>{@code
     *     jakarta.security.jacc.PolicyConfigurationFactory.provider.
     * }
     * </pre>
     *
     * @return the singleton instance of the provider specific PolicyConfigurationFactory implementation class.
     *
     * @throws SecurityException when called by an AccessControlContext that has not been granted the "setPolicy"
     * SecurityPermission.
     *
     * @throws ClassNotFoundException when the class named by the system property could not be found including
     * because the value of the system property has not be set.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the getPolicyConfigurationFactory method signature. The exception thrown by the implementation class
     * will be encapsulated (during construction) in the thrown PolicyContextException
     */
    public static PolicyConfigurationFactory getPolicyConfigurationFactory() throws ClassNotFoundException, PolicyContextException {

        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkPermission(new SecurityPermission("setPolicy"));
        }

        if (policyConfigurationFactory != null) {
            return policyConfigurationFactory;
        }

        synchronized(PolicyConfigurationFactory.class) {

            if (policyConfigurationFactory != null) {
                return policyConfigurationFactory;
            }

            final String className[] = { null };

            try {

                Class<?> clazz = null;

                if (securityManager != null) {
                    try {
                        clazz = AccessController.doPrivileged(new PrivilegedExceptionAction<Class<?>>() {
                            @Override
                            public Class<?> run() throws Exception {

                                className[0] = System.getProperty(FACTORY_NAME);

                                if (className[0] == null) {
                                    throw new ClassNotFoundException("Jakarta Authorization:Error PolicyConfigurationFactory : property not set : " + FACTORY_NAME);
                                }

                                return Class.forName(className[0], true, Thread.currentThread().getContextClassLoader());
                            }
                        });
                    } catch (PrivilegedActionException ex) {
                        Exception e = ex.getException();

                        if (e instanceof ClassNotFoundException) {
                            throw (ClassNotFoundException) e;
                        } else if (e instanceof InstantiationException) {
                            throw (InstantiationException) e;
                        } else if (e instanceof IllegalAccessException) {
                            throw (IllegalAccessException) e;
                        }
                    }
                } else {
                    className[0] = System.getProperty(FACTORY_NAME);

                    if (className[0] == null) {
                        throw new ClassNotFoundException("Jakarta Authorization:Error PolicyConfigurationFactory : property not set : " + FACTORY_NAME);
                    }

                    clazz = Class.forName(className[0], true, Thread.currentThread().getContextClassLoader());
                }

                if (clazz != null) {
                    Object factory = clazz.newInstance();

                    if (factory instanceof PolicyConfigurationFactory) {
                        policyConfigurationFactory = (PolicyConfigurationFactory) factory;
                    } else {
                        throw new ClassCastException("Jakarta Authorization:Error PolicyConfigurationFactory : class not PolicyConfigurationFactory : " + className[0]);
                    }
                }

            } catch (ClassNotFoundException cnfe) {
                throw new ClassNotFoundException("Jakarta Authorization:Error PolicyConfigurationFactory : cannot find class : " + className[0], cnfe);
            } catch (IllegalAccessException iae) {
                throw new PolicyContextException("Jakarta Authorization:Error PolicyConfigurationFactory : cannot access class : " + className[0], iae);
            } catch (InstantiationException ie) {
                throw new PolicyContextException("Jakarta Authorization:Error PolicyConfigurationFactory : cannot instantiate : " + className[0], ie);
            }
        }

        return policyConfigurationFactory;

    }

    /**
     * This method is used to obtain an instance of the provider specific class that implements the PolicyConfiguration
     * interface that corresponds to the identified policy context within the provider. The methods of the
     * PolicyConfiguration interface are used to define the policy statements of the identified policy context.
     *
     * <p>
     * If at the time of the call, the identified policy context does not exist in the provider, then the policy context
     * will be created in the provider and the Object that implements the context's PolicyConfiguration Interface will be
     * returned. If the state of the identified context is "deleted" or "inService" it will be transitioned to the "open"
     * state as a result of the call. The states in the lifecycle of a policy context are defined by the PolicyConfiguration
     * interface.
     *
     * <p>
     * For a given value of policy context identifier, this method must always return the same instance of
     * PolicyConfiguration and there must be at most one actual instance of a PolicyConfiguration with a given policy
     * context identifier (during a process context).
     *
     * <p>
     * To preserve the invariant that there be at most one PolicyConfiguration object for a given policy context, it may be
     * necessary for this method to be thread safe.
     *
     * @param contextID A String identifying the policy context whose PolicyConfiguration interface is to be returned. The
     * value passed to this parameter must not be null.
     * @param remove A boolean value that establishes whether or not the policy statements and linkages of an existing
     * policy context are to be removed before its PolicyConfiguration object is returned. If the value passed to this
     * parameter is true, the policy statements and linkages of an existing policy context will be removed. If the value is
     * false, they will not be removed.
     *
     * @return an Object that implements the PolicyConfiguration Interface matched to the Policy provider and corresponding
     * to the identified policy context.
     *
     * @throws SecurityException when called by an AccessControlContext that has not been granted the "setPolicy"
     * SecurityPermission.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the getPolicyConfiguration method signature. The exception thrown by the implementation class will
     * be encapsulated (during construction) in the thrown PolicyContextException.
     */
    public abstract PolicyConfiguration getPolicyConfiguration(String contextID, boolean remove) throws PolicyContextException;

    /**
     * This method is used to obtain an instance of the provider specific class that implements the PolicyConfiguration
     * interface that corresponds to the identified policy context within the provider. The methods of the
     * PolicyConfiguration interface are used to define the policy statements of the identified policy context.
     *
     * <p>
     * If at the time of the call, the identified policy context does not exist in the provider, then the policy context
     * will <strong>not</strong> be created in the provider and a null will be returned. No state transition of any kind
     * is allowed to occur, the <code>PolicyConfiguration</code> instance is to be returned as-is.
     *
     * <p>
     * For a given value of the policy context identifier, this method must always return the same instance of
     * PolicyConfiguration and there must be at most one actual instance of a PolicyConfiguration with a given policy
     * context identifier (during a process context).
     *
     * @param contextID A String identifying the policy context whose PolicyConfiguration interface is to be returned. The
     * value passed to this parameter must not be null.
     *
     * @return an Object that implements the PolicyConfiguration Interface matched to the Policy provider and corresponding
     * to the identified policy context, or a null if such an Object is not present.
     */
    public abstract PolicyConfiguration getPolicyConfiguration(String contextID);

    /**
     * This method is used to obtain an instance of the provider specific class that implements the PolicyConfiguration
     * interface that corresponds to the identified policy context within the provider. The policy context is identified by
     * the value of the policy context identifier associated with the thread on which the accessor is called. The methods
     * of the PolicyConfiguration interface are used to define the policy statements of the identified policy context.
     *
     * <p>
     * If at the time of the call, the identified policy context does not exist in the provider, then the policy context
     * will <strong>not</strong> be created in the provider and a null will be returned. No state transition of any kind
     * is allowed to occur, the <code>PolicyConfiguration</code> instance is to be returned as-is.
     *
     * <p>
     * For a given determined value of the policy context identifier, this method must always return the same instance of
     * PolicyConfiguration and there must be at most one actual instance of a PolicyConfiguration with a given policy
     * context identifier (during a process context).
     *
     * <p>
     * This method should be logically identical to calling {@link PolicyConfigurationFactory#getPolicyConfiguration(String)}
     * with as input the value returned from {@link PolicyContext#getContextID()}, unless that value is null. In that case
     * a null should be returned.
     *
     *
     * @return an Object that implements the PolicyConfiguration Interface matched to the Policy provider and corresponding
     * to the identified policy context, or a null if such an Object is not present.
     */
    public abstract PolicyConfiguration getPolicyConfiguration();

    /**
     * This method determines if the identified policy context exists with state "inService" in the Policy provider
     * associated with the factory.
     *
     * @param contextID A string identifying a policy context
     *
     * @return true if the identified policy context exists within the provider and its state is "inService", false
     * otherwise.
     *
     * @throws SecurityException when called by an AccessControlContext that has not been granted the "setPolicy"
     * SecurityPermission.
     *
     * @throws PolicyContextException if the implementation throws a checked exception that has not been
     * accounted for by the inService method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    public abstract boolean inService(String contextID) throws PolicyContextException;

}
