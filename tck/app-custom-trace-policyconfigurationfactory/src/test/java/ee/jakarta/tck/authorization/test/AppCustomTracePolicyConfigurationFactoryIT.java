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
public class AppCustomTracePolicyConfigurationFactoryIT extends ArquillianBase {

    Logger logger = Logger.getLogger(AppCustomTracePolicyConfigurationFactoryIT.class.getName());

    @Deployment(testable = false)
    public static Archive<?> createDeployment() {
        return mavenWar();
    }

    /**
     * @testName: PolicyConfigurationFactory
     *
     * @assertion_ids: JACC:SPEC:25; JACC:SPEC:15; JACC:SPEC:63
     *
     * @test_Strategy: 1. Register TS provider with the AppServer. (See User guide
     *                 for Registering TS Provider with your AppServer ).
     *
     *                 2. Read the server side log to
     *                 verify PolicyConfigurationFactory is called and
     *                 instantiated in the server.
     *
     *                 Description The getPolicyConfigurationFactory method must
     *                 be used in the containers to which the application or
     *                 module are being deployed to find or instantiate
     *                 PolicyConfigurationFactory objects.
     *
     */
    @Test
    public void PolicyConfigurationFactory() {
      LogFileProcessor logProcessor = new LogFileProcessor("appId", "app-custom-trace-policyconfigurationfactory");

      // Verify whether the log contains required messages.
      assertTrue(
          "PolicyConfigurationFactory failed : " + "PolicyconfigurationFactory not instantiated",
          logProcessor.verifyLogContains("PolicyConfigurationFactory instantiated"));
    }

    /**
     * @testName: GetPolicyConfiguration
     *
     * @assertion_ids: JACC:SPEC:26; JACC:JAVADOC:28; JACC:JAVADOC:29
     *
     * @test_Strategy: 1. Register TS provider with the AppServer. (See User guide
     *                 for Registering TS Provider with your AppServer ).
     *
     *                 2. Read the server side log to
     *                 verify PolicyConfigurationFactory is called and
     *                 instantiated in the server.
     *
     *                 Description The getPolicyconfiguration method of the
     *                 factory must be used to find or instantiate
     *                 PolicyConfiguration objects corresponding to the
     *                 application or modules being deployed.
     *
     */
    @Test
    public void GetPolicyConfiguration() {
      LogFileProcessor logProcessor = new LogFileProcessor("appId", "app-custom-trace-policyconfigurationfactory");

      // Verify whether the log contains required messages.
      assertTrue(
          "GetPolicyConfiguration failed : " + "getPolicyconfiguration() was not invoked",
          logProcessor.verifyLogContains("PolicyConfigurationFactory.getPolicyConfiguration() invoked"));
    }

}
