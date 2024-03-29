/*
 * Copyright (c) 2024 Contributors to the Eclipse Foundation.
 * Copyright (c) 2007, 2022 Oracle and/or its affiliates. All rights reserved.
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

/**
 * $Id$
 *
 * @author Raja Perumal
 *         08/01/02
 */

package ee.jakarta.tck.authorization.test;

import static java.util.logging.Level.FINER;
import static java.util.logging.Level.INFO;

import ee.jakarta.tck.authorization.util.logging.server.TSLogger;
import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyContextException;

/**
 * JACC PolicyConfigurationFactory This is a delegating PolicyConfigurationFactory which delegates the policy
 * configurations to vendor implementation of PolicyConfigurationFactory class.
 *
 */
public class TSPolicyConfigurationFactoryImpl extends PolicyConfigurationFactory {

    private static TSLogger logger = TSLogger.getTSLogger();

    private static String FACTORY_NAME = "vendor.jakarta.security.jacc.PolicyConfigurationFactory.provider";


    public TSPolicyConfigurationFactoryImpl(PolicyConfigurationFactory policyConfigurationFactory) {
        super(policyConfigurationFactory);
        logger.log(INFO, "PolicyConfigurationFactory instantiated");
        if (policyConfigurationFactory.getClass().getName().equals(FACTORY_NAME)) {
            logger.log(INFO, "policyConfigurationFactory equals expected vendor PolicyConfigurationFactory");
        }
    }

    /**
     * This method is used to obtain an instance of the provider specific class that implements the PolicyConfiguration
     * interface that corresponds to the identified policy context within the provider. The methods of the
     * PolicyConfiguration interface are used to define the policy statements of the identified policy context.
     * <P>
     * If at the time of the call, the identified policy context does not exist in the provider, then the policy context
     * will be created in the provider and the Object that implements the context's PolicyConfiguration Interface will be
     * returned. If the state of the identified context is "deleted" or "inService" it will be transitioned to the "open"
     * state as a result of the call. The states in the lifecycle of a policy context are defined by the PolicyConfiguration
     * interface.
     * <P>
     * For a given value of policy context identifier, this method must always return the same instance of
     * PolicyConfiguration and there must be at most one actual instance of a PolicyConfiguration with a given policy
     * context identifier (during a process context).
     * <P>
     * To preserve the invariant that there be at most one PolicyConfiguration object for a given policy context, it may be
     * necessary for this method to be thread safe.
     * <P>
     *
     * @param contextId A String identifying the policy context whose PolicyConfiguration interface is to be returned. The
     * value passed to this parameter must not be null.
     * <P>
     * @param remove A boolean value that establishes whether or not the policy statements of an existing policy context are
     * to be removed before its PolicyConfiguration object is returned. If the value passed to this parameter is true, the
     * policy statements of an existing policy context will be removed. If the value is false, they will not be removed.
     *
     * @return an Object that implements the PolicyConfiguration Interface matched to the Policy provider and corresponding
     * to the identified policy context.
     *
     * @throws java.lang.SecurityException when called by an AccessControlContext that has not been granted the "setPolicy"
     * SecurityPermission.
     *
     * @throws jakarta.security.jacc.PolicyContextException if the implementation throws a checked exception that has not
     * been accounted for by the getPolicyConfiguration method signature. The exception thrown by the implementation class
     * will be encapsulated (during construction) in the thrown PolicyContextException.
     */

    public PolicyConfiguration getPolicyConfiguration(String contextId, boolean remove) throws PolicyContextException {
        if (logger.isLoggable(FINER)) {
            logger.entering("PolicyConfigurationFactoryImpl", "getPolicyConfiguration");
        }

        PolicyConfiguration policyConfiguration = new TSPolicyConfigurationImpl(contextId, remove, logger);

        logger.log(INFO, "PolicyConfigurationFactory.getPolicyConfiguration() invoked");
        logger.log(FINER, "Getting PolicyConfiguration object with id = " + contextId);

        return policyConfiguration;
    }

    /**
     * This method determines if the identified policy context exists with state "inService" in the Policy provider
     * associated with the factory.
     * <P>
     *
     * @param contextId A string identifying a policy context
     *
     * @return true if the identified policy context exists within the provider and its state is "inService", false
     * otherwise.
     *
     * @throws java.lang.SecurityException when called by an AccessControlContext that has not been granted the "setPolicy"
     * SecurityPermission.
     *
     * @throws jakarta.security.jacc.PolicyContextException if the implementation throws a checked exception that has not
     * been accounted for by the inService method signature. The exception thrown by the implementation class will be
     * encapsulated (during construction) in the thrown PolicyContextException.
     */
    public boolean inService(String contextId) throws PolicyContextException {
        if (logger.isLoggable(FINER)) {
            logger.entering("PolicyConfigurationFactoryImpl", "inService");
        }
        logger.log(INFO, "PolicyConfigurationFactory.inService() invoked");
        logger.log(FINER, "PolicyConfiguration.inService() invoked for context id = " + contextId);

        return getWrapped().inService(contextId);
    }

    public PolicyConfiguration getPolicyConfiguration(String contextID) {
        if (logger.isLoggable(FINER)) {
            logger.entering("PolicyConfigurationFactoryImpl", "getPolicyConfiguration(String)");
        }

        PolicyConfiguration policyConfiguration = getWrapped().getPolicyConfiguration(contextID);
        logger.log(INFO, "PolicyConfigurationFactory.getPolicyConfiguration(String) invoked");

        return policyConfiguration;
    }

    public PolicyConfiguration getPolicyConfiguration() {
        if (logger.isLoggable(FINER)) {
            logger.entering("PolicyConfigurationFactoryImpl", "getPolicyConfiguration()");
        }

        String contextId = PolicyContext.getContextID();
        PolicyConfiguration policyConfiguration = getWrapped().getPolicyConfiguration(contextId);
        logger.log(INFO, "PolicyConfigurationFactory.getPolicyConfiguration(String) invoked");
        logger.log(FINER, "Getting PolicyConfiguration object with id = " + contextId);

        return policyConfiguration;
    }

}
