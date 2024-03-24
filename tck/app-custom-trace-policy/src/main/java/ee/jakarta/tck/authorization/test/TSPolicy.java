/*
 * Copyright (c) 2024 Contributors to the Eclipse Foundation.
 * Copyright (c) 2007, 2020 Oracle and/or its affiliates. All rights reserved.
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
package ee.jakarta.tck.authorization.test;

import static java.util.logging.Level.FINER;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.SEVERE;

import ee.jakarta.tck.authorization.util.logging.server.TSLogger;
import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.WebResourcePermission;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Permission;
import java.security.PermissionCollection;
import javax.security.auth.Subject;

/**
 * This is a delegating Policy Implementation class which delegates the permission evaluation to vendor's policy
 * implementation.
 *
 * @author Raja Perumal 08/14/02
 *
 */
public final class TSPolicy implements Policy {

    public static TSLogger logger = TSLogger.getTSLogger();

    private Policy policy;

    public TSPolicy(Policy policy) {
        this.policy = policy;
    }

    /**
     * Evaluates the global policy for the permissions granted to the ProtectionDomain and tests whether the permission is
     * granted.
     *
     * @param permission the Permission object to be tested for implication.
     * @param subject the Subject to test
     *
     * @return true if "permission" is a proper subset of a permission granted to this Subject.
     * @since 1.4
     */
    @Override
    public boolean implies(Permission permission, Subject subject) {
        if ((permission instanceof WebResourcePermission) && (permission.getName().equals("/secured.jsp"))) {
            logger.log(INFO, "Calling policyContextSubject()");
            policyContextSubject();

            logger.log(INFO, "Calling policyContextHttpServletRequest()");
            policyContextHttpServletRequest();
        }

        // If there is a PolicyContext.getContextID, verify that getPolicyConfiguration() methods work
        String contextId = PolicyContext.getContextID();
        if (contextId != null) {
            try {
                PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();

                // Should be non-null PolicyConfiguration
                PolicyConfiguration policyConfiguration = policyConfigurationFactory.getPolicyConfiguration();
                if (policyConfiguration != null) {
                    logger.log(INFO, "PolicyConfigurationFactory.getPolicyConfiguration() : PASSED");
                } else {
                    logger.log(INFO, "PolicyConfigurationFactory.getPolicyConfiguration() : FAILED");
                }

                // Should be non-null PolicyConfiguration and match no-arg getPolicyConfiguration()
                PolicyConfiguration policyConfiguration2 = policyConfigurationFactory.getPolicyConfiguration(contextId);
                if (policyConfiguration2 == null || !policyConfiguration.equals(policyConfiguration2)) {
                    logger.log(INFO, "PolicyConfigurationFactory.getPolicyConfiguration(String) : FAILED");
                } else {
                    logger.log(INFO, "PolicyConfigurationFactory.getPolicyConfiguration(String) : PASSED");
                }

            } catch (Exception e) {
                logger.log(INFO, "PolicyConfigurationFactory.getPolicyConfiguration() : FAILED");
            }
        }

        return policy.implies(permission, subject);
    }

    /**
     * Evaluates the global policy and returns a PermissionCollection object specifying the set of permissions allowed given
     * the characteristics of the protection domain.
     *
     * @param subject the Subject associated with the caller.
     *
     * @return the set of permissions allowed for the <i>subject</i> according to the policy. The returned set of permissions
     * must be a new mutable instance and it must support heterogeneous Permission types.
     *
     * @since 1.4
     */
    @Override
    public PermissionCollection getPermissionCollection(Subject subject) {
        if (logger.isLoggable(FINER)) {
            logger.entering("TSPolicy", "getPermissions");
        }

        // Print permission collection as logger info ?
        return policy.getPermissionCollection(subject);
    }

    /**
     * Refreshes/reloads the policy configuration. The behavior of this method depends on the implementation. For example,
     * calling <code>refresh</code> on a file-based policy will cause the file to be re-read.
     *
     */
    @Override
    public void refresh() {
        policy.refresh();
        if (logger != null) {
            logger.log(INFO, "TSPolicy.refresh() invoked");
        }
    }

    /**
     * testName: policyContextHttpServletRequest
     *
     * @assertion_ids: JACC:SPEC:99; JACC:JAVADOC:30
     *
     * @test_Strategy: 1) call PolicyContext.getContext("jakarta.servlet.http.HttpServletRequest") 2) verify the return
     * value is an instance of HttpServletRequest
     *
     */
    private void policyContextHttpServletRequest() {
        try {
            // Get HttpServletRequest object
            HttpServletRequest ctx = PolicyContext.getContext("jakarta.servlet.http.HttpServletRequest");
            logger.log(INFO, "PolicyContext.getContext() " + "test passed for" + "jakarta.servlet.http.HttpServletRequest " + ctx.getContextPath());
            logger.log(INFO, "PolicyContextHttpServletRequest: PASSED");
        } catch (ClassCastException e) {
            logger.log(INFO,"PolicyContext.getContext()" + "returned incorrect value for key " + "jakarta.servlet.http.HttpServletRequest");
            logger.log(SEVERE, "PolicyContextHttpServletRequest: FAILED");
        } catch (Exception e) {
            logger.log(SEVERE, "PolicyContextHttpServletRequest: FAILED");
        }
    }

    /**
     * testName: policyContextSubject
     *
     * @assertion_ids: JACC:SPEC:97; JACC:JAVADOC:30
     *
     * @test_Strategy: 1) call PolicyContext.getContext("javax.security.auth.Subject.container) 2) verify the return value
     * is an instance of javax.security.auth.Subject
     *
     */
    private void policyContextSubject() {
        try {
            // Get Subject
            Subject subject = PolicyContext.getContext("javax.security.auth.Subject.container");
            logger.log(INFO, "PolicyContext.getContext() " + "test passed for" + "javax.security.auth.Subject.container " + subject.toString());
            logger.log(INFO, "PolicyContextSubject: PASSED");
        } catch (ClassCastException e) {
            logger.log(INFO, "PolicyContext.getContext()" + "returned incorrect value for key " + "javax.security.auth.Subject.container");
            logger.log(INFO, "PolicyContextSubject: FAILED");
        } catch (Exception e) {
            logger.log(SEVERE, "PolicyContextSubject: FAILED");
        }
    }

}
