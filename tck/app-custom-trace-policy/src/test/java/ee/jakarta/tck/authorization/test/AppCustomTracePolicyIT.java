/*
 * Copyright (c) 2024, 2026 Contributors to Eclipse Foundation.
 * Copyright (c) 2015, 2020 Oracle and/or its affiliates. All rights reserved.
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

import static ee.jakarta.tck.authorization.util.ShrinkWrap.mavenWar;
import static org.junit.Assert.assertTrue;

import ee.jakarta.tck.authorization.util.ArquillianBase;
import ee.jakarta.tck.authorization.util.logging.client.LogFileProcessor;
import java.util.logging.Logger;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(Arquillian.class)
public class AppCustomTracePolicyIT extends ArquillianBase {

    Logger logger = Logger.getLogger(AppCustomTracePolicyIT.class.getName());

    @Deployment(testable = false)
    public static Archive<?> createDeployment() {
        return mavenWar();
    }

    /**
     * @testName: GetPolicyConfiguration
     *
     * @assertion_ids: JACC:SPEC:26; JACC:JAVADOC:28; JACC:JAVADOC:29
     *
     * @test_Strategy: 1. Register TS provider with the AppServer.
     *
     *                 2. Read the server side log to verify the Policy is called and
     *                 instantiated in the server.
     *
     *                 3. Make sure that from within the Policy, we are able to call
     *                 the different variants of
     *                 PolicyConfigurationFactory.getPolicyConfiguration
     *
     *                 Description The getPolicyConfiguration method of the
     *                 factory must be used to find or instantiate
     *                 PolicyConfiguration objects corresponding to the
     *                 application or modules being deployed.
     *
     */
    @Test
    public void GetPolicyConfiguration() {
      LogFileProcessor logProcessor = new LogFileProcessor("appId", "app-custom-trace-policy");

      // Verify whether the log contains required messages.
      assertTrue(
          "GetPolicyConfiguration failed : " + "getPolicyconfiguration() failed",
          logProcessor.verifyLogContains("PolicyConfigurationFactory.getPolicyConfiguration() : PASSED"));

      assertTrue(
          "GetPolicyConfiguration failed : " + "getPolicyconfiguration(String) failed",
          logProcessor.verifyLogContains("PolicyConfigurationFactory.getPolicyConfiguration(String) : PASSED"));
    }


    /**
     * @testName: PolicyRefresh
     *
     * @assertion_ids: JACC:SPEC:54; JACC:SPEC:5; JACC:SPEC:23
     *
     * @test_Strategy: 1. Register TS provider with the AppServer. (See User guide
     *                 for Registering TS Provider with your AppServer ).
     *
     *                 2. Read the server side log and
     *                 verify that TSPolicy.refresh() method is called
     *
     *                 (Note: This assertion implicitly tests JACC:SPEC:5,
     *                 JACC:SPEC:23 i.e loading provider specified interfaces by
     *                 the containers)
     *
     */
    @Test
    public void PolicyRefresh() {
      LogFileProcessor logProcessor = new LogFileProcessor("appId", "app-custom-trace-policy");

      // verify the log contains TSPolicy.refresh().
      assertTrue(
          "PolicyRefresh() failed",
          logProcessor.verifyLogContains("TSPolicy.refresh() invoked"));
    }

    /**
     * @testName: Policy
     *
     * @assertion_ids: JACC:SPEC:53; JACC:SPEC:56; JACC:SPEC:67; JACC:SPEC:68;
     *                 JACC:SPEC:105; JACC:SPEC:14; JACC:SPEC:22
     *
     * @test_Strategy: 1. Register TS provider with the AppServer. (See User guide
     *                 for Registering TS Provider with your AppServer ).
     *
     *                 2. Read the server side log, and verify the server side log
     *                 contains the following string "TSPolicy.refresh() invoked"
     *
     *                 3. The occurrence of the above string indicates the server
     *                 used used the custom policy
     */
    @Test
    public void Policy() {
        LogFileProcessor logProcessor = new LogFileProcessor("appId", "app-custom-trace-policy");

        // verify the log contains TSPolicy.refresh().
        assertTrue(
            "TestName: Policy failed : " + "Policy replacement API not used",
            logProcessor.verifyLogContains("TSPolicy.refresh() invoked"));
    }

    /**
     * testName: policyContextHttpServletRequest
     *
     * @assertion_ids: JACC:SPEC:99; JACC:JAVADOC:30
     *
     * @test_Strategy:
     *           1) From within a Policy, call PolicyContext.getContext("jakarta.servlet.http.HttpServletRequest")
     *           2) verify the return value is an instance of HttpServletRequest
     *           3) This makes sure a Policy has access to the HttpServletRequest
     *
     */
    @Test
    public void PolicyContextHttpServletRequest() {
        assertTrue(
            readFromServerWithCredentials("/secured.jsp", "javajoe", "javajoe").contains("javajoe"));

        LogFileProcessor logProcessor = new LogFileProcessor("appId", "app-custom-trace-policy");

        assertTrue(
            "TestName: Policy failed : " + "HttpServletRequest not available",
            logProcessor.verifyLogContains("PolicyContextHttpServletRequest: PASSED"));
    }


    /**
     * testName: policyContextSubject
     *
     * @assertion_ids: JACC:SPEC:97; JACC:JAVADOC:30
     *
     * @test_Strategy:
     *          1) From within a Policy, call PolicyContext.getContext("javax.security.auth.Subject.container)
     *          2) verify the return value is an instance of javax.security.auth.Subject
     *          3) This makes sure a Policy has access to the Subject
     *
     */
    @Test
    public void PolicyContextSubject() {
        assertTrue(
            readFromServerWithCredentials("/secured.jsp", "javajoe", "javajoe").contains("javajoe"));

        LogFileProcessor logProcessor = new LogFileProcessor("appId", "app-custom-trace-policy");

        assertTrue(
            "TestName: Policy failed : " + "Subject not available",
            logProcessor.verifyLogContains("PolicyContextSubject: PASSED"));

    }


}
