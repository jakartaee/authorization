/*
 * Copyright (c) 2023 Contributors to Eclipse Foundation. All rights reserved.
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

/**
 * Abstract factory and finder class for obtaining the instance of the class that implements the
 * PolicyFactory of a provider. The factory will be used to instantiate Policy objects.
 *
 * <p>
 * <b>NOTE: DRAFT API. SUBJECT TO CHANGE</b>
 *
 * @see Policy
 *
 * @author Arjan Tijms
 */
public abstract class PolicyFactory {

    public static final String FACTORY_NAME = "jakarta.security.jacc.PolicyFactory.provider";

    private static volatile PolicyFactory policyFactory;

    /**
     * Get the system-wide PolicyFactory implementation.
     *
     * <p>
     * The name of the factory implementation class is obtained from the
     * value of the system property,
     * <pre>{@code
     *     jakarta.security.jacc.PolicyFactory.provider
     * }
     * </pre>
     *
     * This value can also be retrieved from the field {@code PolicyFactory.FACTORY_NAME}.
     *
     * @return the system-wide singleton instance of the provider specific PolicyFactory implementation class.
     *
     * @exception SecurityException If an exception was thrown during the class loading, or construction of the default
     * PolicyFactory implementation class; in which case the SecurityException will contain the root Exception as its
     * cause.
     */
    public static synchronized PolicyFactory getPolicyFactory() {
        if (policyFactory != null) {
            return policyFactory;
        }

        final String className = System.getProperty(FACTORY_NAME);
        if (className != null) {
            try {
                policyFactory = (PolicyFactory)
                    Class.forName(
                            className,
                            true,
                            Thread.currentThread().getContextClassLoader())
                         .getDeclaredConstructor()
                         .newInstance();
            } catch (ReflectiveOperationException pae) {
                throw new SecurityException(pae);
            }
        }

        return policyFactory;
    }

    /**
     * Set the system-wide PolicyFactory implementation.
     *
     * <p>
     * If an implementation was set previously, it will be replaced.
     *
     * @param policyFactory The PolicyFactory instance, which may be null.
     *
     */
    public static synchronized void setPolicyFactory(PolicyFactory policyFactory) {
        PolicyFactory.policyFactory = policyFactory;
    }

    /**
     * This method is used to obtain an instance of the provider specific class that implements the {@link Policy}
     * interface that corresponds to policy context within the provider. The policy context is identified by
     * the value of the policy context identifier associated with the thread on which the accessor is called.
     *
     * <p>
     * For a given determined value of the policy context identifier, this method must always return the same instance of
     * {@link Policy} and there must be at most one actual instance of a {@link Policy} with a given policy
     * context identifier (during a process context).
     *
     * <p>
     * This method should be logically identical to calling {@link PolicyFactory#getPolicy(String)}
     * with as input the value returned from {@link PolicyContext#getContextID()}.
     *
     * @return an Object that implements the {@link Policy} interface corresponding to the identified policy context,
     * or a null if such an Object is not present.
     */
    public Policy getPolicy() {
        return getPolicy(PolicyContext.getContextID());
    }

    /**
     * Set the context Policy implementation.
     *
     * <p>
     * If an implementation was set previously, it will be replaced.
     *
     * <p>
     * This method should be logically identical to calling {@link PolicyFactory#setPolicy(String, Policy) }
     * with as input for the first parameter the value returned from {@link PolicyContext#getContextID()}.
     *
     * @param policy The policy instance, which may be null.
     *
     */
    public void setPolicy(Policy policy) {
        setPolicy(PolicyContext.getContextID(), policy);
    }

    /**
     * This method is used to obtain an instance of the provider specific class that implements the {@link Policy}
     * interface that corresponds to policy context within the provider. The policy context is identified by
     * the value of the policy context identifier associated with the thread on which the accessor is called.
     *
     * <p>
     * For a given determined value of the policy context identifier, this method must always return the same instance of
     * {@link Policy} and there must be at most one actual instance of a {@link Policy} with a given policy
     * context identifier (during a process context).
     *
     * @param contextId A String identifying the policy context whose {@link Policy} interface is to be returned. The
     * value passed to this parameter can be null, which corresponds to the system-wide default {@link Policy} instance.
     *
     *
     * @return an Object that implements the {@link Policy} interface corresponding to the identified policy context,
     * or a null if such an Object is not present.
     */
    public abstract Policy getPolicy(String contextId);

    /**
     * Set the context Policy implementation.
     *
     * <p>
     * If an implementation was set previously, it will be replaced.
     *
     * @param contextId A String identifying the policy context whose {@link Policy} interface is to be returned. The
     * value passed to this parameter can be null, which corresponds to the system-wide default {@link Policy} instance.
     *
     * @param policy The policy instance, which may be null.
     *
     */
    public abstract void setPolicy(String contextId, Policy policy);

}
