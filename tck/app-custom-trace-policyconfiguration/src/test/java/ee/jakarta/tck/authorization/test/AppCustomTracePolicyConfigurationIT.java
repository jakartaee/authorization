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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import ee.jakarta.tck.authorization.util.ArquillianBase;
import ee.jakarta.tck.authorization.util.logging.client.LogFileProcessor;
import jakarta.security.jacc.WebResourcePermission;
import jakarta.security.jacc.WebRoleRefPermission;
import jakarta.security.jacc.WebUserDataPermission;
import java.security.Permissions;
import java.util.logging.Logger;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(Arquillian.class)
public class AppCustomTracePolicyConfigurationIT extends ArquillianBase {

    Logger logger = Logger.getLogger(AppCustomTracePolicyConfigurationIT.class.getName());

    @Deployment(testable = false)
    public static Archive<?> createDeployment() {
        return mavenWar();
    }

    /**
     * @testName: WebUserDataPermission
     *
     * @assertion_ids: JACC:SPEC:41; JACC:SPEC:42; JACC:JAVADOC:54;
     *                 JACC:JAVADOC:56; JACC:JAVADOC:58; JACC:SPEC:27;
     *                 JACC:SPEC:28; JACC:SPEC:34; JACC:SPEC:52
     *
     * @test_Strategy: 1. Register TS provider with the AppServer. (See User guide
     *                 for Registering TS Provider with your AppServer ).
     *
     *                 2. Deploy the application.
     *
     *                 3. During deployment, appserver generates permissions for
     *                 the J2EE components based on the given deployment
     *                 descriptor
     *
     *                 4. Retrieve server side logs and verify the generated
     *                 unchecked permissions matches the expected permission
     *                 collection
     *
     *
     */
    @Test
    public void WebUserDataPermission() {
        LogFileProcessor logProcessor = new LogFileProcessor("getAppSpecificRecordCollection|appId", "app-custom-trace-policyconfiguration");


        // ----------UNCHECKED----------//
        // 1) retrieve server generated unchecked policy statements
        // 2) construct expected unchecked policy statements
        // 3) verify expected policy statements with generated policy statements

        // Get actual "unchecked" WebUserDataPermissions
        Permissions uncheckedWebUserDataPermissions =
            logProcessor.getSpecificPermissions(
                logProcessor.getAppSpecificUnCheckedPermissions(), "WebUserDataPermission");

        logger.info("Server generated unchecked WebUserDataPermissions");
        logProcessor.printPermissionCollection(uncheckedWebUserDataPermissions);

        // Construct the expected unchecked WebUserDataPermission
        Permissions expectedUnCheckedPermissions = new Permissions();
        expectedUnCheckedPermissions.add(new WebUserDataPermission("/sslprotected.jsp", "GET,POST:CONFIDENTIAL"));
        expectedUnCheckedPermissions.add(new WebUserDataPermission("/excluded.jsp", "!GET,POST"));
        expectedUnCheckedPermissions.add(new WebUserDataPermission("/sslprotected.jsp", "!GET,POST"));
        expectedUnCheckedPermissions.add(new WebUserDataPermission("/secured.jsp", (String) null));
        expectedUnCheckedPermissions.add(new WebUserDataPermission("/anyauthuser.jsp", "!GET,POST"));
        expectedUnCheckedPermissions.add(new WebUserDataPermission("/:/unchecked.jsp:/secured.jsp:/sslprotected.jsp:/excluded.jsp:/anyauthuser.jsp", (String) null));
        expectedUnCheckedPermissions.add(new WebUserDataPermission("/unchecked.jsp", (String) null));

        logger.info("verifying unchecked policy statments:");

        assertTrue(
            "WebUserDataPermission failed: " + "unchecked policy statements verification failed",
            logProcessor.verifyLogImplies(expectedUnCheckedPermissions, uncheckedWebUserDataPermissions));



        // ---------EXCLUDED----------//
        // 1) retrieve server generated excluded policy statements
        // 2) construct expected excluded policy statements
        // 3) verify expected policy statements with generated policy statements

        // Get actual "excluded" WebUserDataPermission
        Permissions excludedWebUserDataPermissions =
            logProcessor.getSpecificPermissions(
                logProcessor.getAppSpecificExcludedPermissions(), "WebUserDataPermission");

        logger.info("Server generated excluded WebUserDataPermission");
        logProcessor.printPermissionCollection(excludedWebUserDataPermissions);

        // Construct the expected excluded WebUserDataPermission
        Permissions expectedExcludedPermissions = new Permissions();
        expectedExcludedPermissions.add(new WebUserDataPermission("/excluded.jsp", "GET,POST"));

        logger.info("verifying excluded policy statments:");

        assertTrue(
             "WebUserDataPermission failed: " + "excluded policy statements verification failed",
            logProcessor.verifyLogImplies(expectedExcludedPermissions, excludedWebUserDataPermissions));
    }



    /**
     * @testName: WebResourcePermission
     *
     * @assertion_ids: JACC:SPEC:36; JACC:SPEC:72; JACC:SPEC:27; JACC:SPEC:28; JACC:SPEC:52; JACC:SPEC:128;
     *
     * @test_Strategy: 1. Register TS provider with the AppServer. (See User guide for Registering TS Provider with your
     * AppServer ).
     *
     * 2. Deploy the application.
     *
     * 3. During deployment, appserver generates permissions for the EE components based on the given deployment
     * descriptor
     *
     * 4. Retrieve server side logs and verify the generated permissions matches the expected permission collection
     *
     */
    @Test
    public void WebResourcePermission() {
        LogFileProcessor logProcessor = new LogFileProcessor("getAppSpecificRecordCollection|appId", "app-custom-trace-policyconfiguration");

        // ----------UNCHECKED----------//
        // 1) retrieve server generated unchecked policy statements
        // 2) construct expected unchecked policy statements
        // 3) verify expected policy statements with generated policy statements

        Permissions expectedUnCheckedPermissions = new Permissions();

        // Get "unchecked" WebResourcePermissions
        Permissions uncheckedWebResourcePermissions =
            logProcessor.getSpecificPermissions(
                logProcessor.getAppSpecificUnCheckedPermissions(), "WebResourcePermission");

        System.out.println("\n\nServer generated unchecked WebResourcePermissions");
        logProcessor.printPermissionCollection(uncheckedWebResourcePermissions);

        // Construct the expected unchecked WebResourcePermission
        expectedUnCheckedPermissions.add(new WebResourcePermission("/unchecked.jsp", (String) null));
        expectedUnCheckedPermissions.add(new WebResourcePermission("/sslprotected.jsp", "!GET,POST"));
        expectedUnCheckedPermissions.add(new WebResourcePermission("/:/secured.jsp:/unchecked.jsp:/excluded.jsp:/sslprotected.jsp:/anyauthuser.jsp", (String) null));
        expectedUnCheckedPermissions.add(new WebResourcePermission("/excluded.jsp", "!GET,POST"));
        expectedUnCheckedPermissions.add(new WebResourcePermission("/secured.jsp", "!GET,POST"));
        expectedUnCheckedPermissions.add(new WebResourcePermission("/anyauthuser.jsp", "!GET,POST"));

        System.out.println("verifying unchecked policy statments:");

        assertTrue(
            "WebResourcePermission failed: " + "unchecked policy statements verification failed",
            logProcessor.verifyLogImplies(expectedUnCheckedPermissions, uncheckedWebResourcePermissions));





        // ---------EXCLUDED----------//
        // 1) Retrieve server generated excluded policy statements
        // 2) Construct expected excluded policy statements
        // 3) Verify expected policy statements with generated policy statements



        // Get actual "excluded" WebResourcePermissions
        Permissions excludedWebResourcePermissions =
            logProcessor.getSpecificPermissions(
                logProcessor.getAppSpecificExcludedPermissions(), "WebResourcePermission");

        System.out.println("\n\nServer generated excluded WebResourcePermissions");
        logProcessor.printPermissionCollection(excludedWebResourcePermissions);

        // Construct the expected excluded WebResourcePermission
        Permissions expectedExcludedPermissions = new Permissions();
        expectedExcludedPermissions.add(new WebResourcePermission("/excluded.jsp", "GET,POST"));

        System.out.println("verifying excluded policy statments:");

        assertTrue(
            "WebResourcePermission failed: " + "excluded policy statements verification failed",
            logProcessor.verifyLogImplies(expectedExcludedPermissions, excludedWebResourcePermissions));





        // ---------ADDTOROLE----------//
        // 1) retrieve server generated addToRole policy statements
        // 2) construct expected addToRole policy statements
        // 3) verify expected policy statements with generated policy statements


        // Get actual "addToRole" WebResourcePermissions
        Permissions addToRoleWebResourcePermissions =
            logProcessor.getSpecificPermissions(
                logProcessor.getAppSpecificAddToRolePermissions(), "WebResourcePermission");

        System.out.println("\n\nServer generated addToRole WebResourcePermissions");
        logProcessor.printPermissionCollection(addToRoleWebResourcePermissions);

        // Construct the expected excluded WebResourcePermission
        Permissions expectedAddToRolePermissions = new Permissions();
        expectedAddToRolePermissions.add(new WebResourcePermission("/secured.jsp", "GET,POST"));
        expectedAddToRolePermissions.add(new WebResourcePermission("/sslprotected.jsp", "GET,POST"));
        expectedAddToRolePermissions.add(new WebResourcePermission("/anyauthuser.jsp", "GET,POST"));

        System.out.println("verifying addToRole policy statments:");

        assertTrue(
            "WebResourcePermission failed: " + "addToRole policy statements verification failed",
            logProcessor.verifyLogImplies(expectedAddToRolePermissions, addToRoleWebResourcePermissions));
    }

    /**
     * @testName: WebResourcePermissionExcludedPolicy
     *
     * @assertion_ids: JACC:SPEC:37; JACC:SPEC:114; JACC:SPEC:111; JACC:SPEC:27;
     *                 JACC:SPEC:28; JACC:SPEC:34; JACC:SPEC:52
     *
     * @test_Strategy: 1. Register TS provider with the AppServer. (See User guide
     *                 for Registering TS Provider with your AppServer ).
     *
     *                 2. Deploy the application.
     *
     *                 3. During deployment, appserver generates permissions for
     *                 the J2EE components based on the given deployment
     *                 descriptor
     *
     *                 4. Retrieve server side logs and verify the generated
     *                 permissions matches the expected permission collection
     *
     */
    @Test
    public void WebResourcePermissionExcludedPolicy() {

      // ---------EXCLUDED----------//
      // 1) retrieve server generated excluded policy statements
      // 2) construct expected excluded policy statements
      // 3) verify expected policy statements with generated policy statements

      LogFileProcessor logProcessor = new LogFileProcessor("getAppSpecificRecordCollection|appId", "app-custom-trace-policyconfiguration");

      // Get "excluded" WebResourcePermissions
      Permissions excludedWebResourcePermissions =
          logProcessor.getSpecificPermissions(
              logProcessor.getAppSpecificExcludedPermissions(), "WebResourcePermission");

      logger.info("Server generated excluded WebResourcePermissions");

      logProcessor.printPermissionCollection(excludedWebResourcePermissions);

      // Construct the expected excluded WebResourcePermission
      Permissions expectedExcludedPermissions = new Permissions();
      expectedExcludedPermissions
          .add(new WebResourcePermission("/excluded.jsp", "GET,POST"));

      logger.info("verifying excluded policy statments:");

      assertTrue(
          "WebResourcePermissionExcludedPolicy failed: " + "excluded policy statements verification failed",
          logProcessor.verifyLogImplies(expectedExcludedPermissions, excludedWebResourcePermissions));
    }

    /**
     * @testName: WebResourcePermissionUnCheckedPolicy
     *
     * @assertion_ids: JACC:SPEC:36; JACC:SPEC:39; JACC:SPEC:27; JACC:SPEC:28;
     *                 JACC:SPEC:52; JACC:JAVADOC:17
     *
     * @test_Strategy: 1. Register TS provider with the AppServer. (See User guide
     *                 for Registering TS Provider with your AppServer ).
     *
     *                 2. Deploy the application.
     *
     *                 3. During deployment, appserver generates permissions for
     *                 the J2EE components based on the given deployment
     *                 descriptor
     *
     *                 4. Retrieve server side logs and verify the generated
     *                 unchecked permissions matches the expected permission
     *                 collection
     */
    @Test
    public void WebResourcePermissionUnCheckedPolicy() {
      LogFileProcessor logProcessor = new LogFileProcessor("getAppSpecificRecordCollection|appId", "app-custom-trace-policyconfiguration");


      // Get "unchecked" WebResourcePermissions
      Permissions uncheckedWebResourcePermissions =
          logProcessor.getSpecificPermissions(
              logProcessor.getAppSpecificUnCheckedPermissions(), "WebResourcePermission");

      logger.info("Server generated unchecked WebResourcePermissions");
      logProcessor.printPermissionCollection(uncheckedWebResourcePermissions);

      // Construct the expected unchecked WebResourcePermission
      Permissions expectedPermissions = new Permissions();
      expectedPermissions.add(new WebResourcePermission("/unchecked.jsp", (String) null));
      expectedPermissions.add(new WebResourcePermission("/sslprotected.jsp", "!GET,POST"));
      expectedPermissions.add(new WebResourcePermission("/:/secured.jsp:/unchecked.jsp:/excluded.jsp:/sslprotected.jsp:/anyauthuser.jsp", (String) null));
      expectedPermissions.add(new WebResourcePermission("/excluded.jsp", "!GET,POST"));
      expectedPermissions.add(new WebResourcePermission("/secured.jsp", "!GET,POST"));
      expectedPermissions.add(new WebResourcePermission("/anyauthuser.jsp", "!GET,POST"));

      assertTrue(
          "WebResourcePermissionUnCheckedPolicy failed",
          logProcessor.verifyLogImplies(expectedPermissions, uncheckedWebResourcePermissions));
    }


    /**
     * @testName: WebRoleRefPermission
     *
     * @assertion_ids: JACC:SPEC:36; JACC:SPEC:112; JACC:SPEC:38; JACC:SPEC:43;
     *                 JACC:SPEC:44; JACC:JAVADOC:50; JACC:SPEC:27; JACC:SPEC:28;
     *                 JACC:SPEC:45; JACC:SPEC:52; JACC:SPEC:75; JACC:SPEC:128;
     *                 JACC:SPEC:131
     *
     * @test_Strategy: 1. Register TS provider with the AppServer. (See User guide
     *                 for Registering TS Provider with your AppServer ). 2.
     *                 Deploy the application.
     *
     *                 3. During deployment, appserver generates permissions for
     *                 the EE components based on the given deployment
     *                 descriptor
     *
     *                 4. Retrieve server side logs and verify the generated
     *                 permissions matches the expected permission collection
     */
    @Test
    public void WebRoleRefPermission() {

        // ---------ADDTOROLE----------//
        // 1) retrieve server generated addToRole policy statements
        // 2) construct expected addToRole policy statements
        // 3) verify expected policy statements with generated policy statements

        LogFileProcessor logProcessor = new LogFileProcessor("getAppSpecificRecordCollection|appId", "app-custom-trace-policyconfiguration");

        // Get actual "addToRole" WebRoleRefPermissions
        Permissions addToRoleWebRoleRefPermissions =
            logProcessor.getSpecificPermissions(
                logProcessor.getAppSpecificAddToRolePermissions(), "WebRoleRefPermission");

        logger.info("Server generated addToRole WebRoleRefPermissions");
        logProcessor.printPermissionCollection(addToRoleWebRoleRefPermissions);

        // Construct the expected excluded WebRoleRefPermission
        Permissions expectedAddToRolePermissions = new Permissions();
        expectedAddToRolePermissions.add(new jakarta.security.jacc.WebRoleRefPermission("secured", "ADM"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("secured", "Administrator"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("secured", "Manager"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("secured", "Employee"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("sslprotected", "MGR"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("sslprotected", "ADM"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("sslprotected", "Administrator"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("sslprotected", "Manager"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("sslprotected", "Employee"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("unchecked", "Manager"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("unchecked", "Administrator"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("unchecked", "Employee"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("excluded", "Manager"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("excluded", "Administrator"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("excluded", "Employee"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("anyauthuser", "Employee"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("anyauthuser", "Manager"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("anyauthuser", "Administrator"));

        // JSR115 Maintenance Review changes
        expectedAddToRolePermissions.add(new WebRoleRefPermission("", "Administrator"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("", "Manager"));
        expectedAddToRolePermissions.add(new WebRoleRefPermission("", "Employee"));

        logger.info("verifying addToRole policy statments:");

        assertTrue(
            "WebRoleRefPermission failed: " + "addToRole policy statements verification failed",
            logProcessor.verifyLogImplies(expectedAddToRolePermissions, addToRoleWebRoleRefPermissions));
    }


    /**
     * @testName: AnyAuthUserWebRoleRef
     *
     * @assertion_ids: JACC:SPEC:130; JACC:SPEC:131;
     *
     * @test_Strategy: This is testing that: If the any authenticated user
     *                 role-name, **, does not appear in a security-role-ref
     *                 within the servlet, a WebRoleRefPermission must also be
     *                 added for it. The name of each such WebRoleRefPermission
     *                 must be the servlet-name of the corresponding servlet
     *                 element. steps: 1. We have any-authenticated-user
     *                 referenced in a security-constraint in our DD (for
     *                 anyauthuser.jsp) We have a total of 5 servlets defined in
     *                 our DD also.
     *
     *                 2. Deploy the application.
     *
     *                 3. During deployment, appserver generates permissions for
     *                 the EE components based on the given deployment
     *                 descriptor
     *
     *                 4. Retrieve server side logs and verify the generated
     *                 permissions matches the expected permission collection
     */
    @Test
    public void AnyAuthUserWebRoleRef() {
      LogFileProcessor logProcessor = new LogFileProcessor("getAppSpecificRecordCollection|appId", "app-custom-trace-policyconfiguration");

      // Retrieve server generated addToRole policy statements
      Permissions addToRoleWebRoleRefPermissions =
          logProcessor.getSpecificPermissions(
              logProcessor.getAppSpecificAddToRolePermissions(), "WebRoleRefPermission");

      // For debug aid, print out server generated addToRole policy statements
      logger.info("Server generated addToRole WebRoleRefPermissions");
      logProcessor.printPermissionCollection(addToRoleWebRoleRefPermissions);

      // According to the Jakarta Authorization 1.5 spec (chapter 3, section 3.1.3.3),
      // it states that:
      //
      // "a WebRoleRefPermission must also be added for it" (meaning **)
      // and that
      // "The name of each such WebRoleRefPermission must be the servlet-name
      // of the corresponding servlet element."
      //
      // This means for each servlet definition in our web.xml, there will need to
      // exist a WebRoleRefPermission with that servlet name for the ** role.
      //
      Permissions expectedAddToRolePerms = new Permissions();
      expectedAddToRolePerms.add(new WebRoleRefPermission("excluded", "**"));
      expectedAddToRolePerms.add(new WebRoleRefPermission("unchecked", "**"));
      expectedAddToRolePerms.add(new WebRoleRefPermission("sslprotected", "**"));
      expectedAddToRolePerms.add(new WebRoleRefPermission("secured", "**"));
      expectedAddToRolePerms.add(new WebRoleRefPermission("anyauthuser", "**"));

      logger.info("verifying addToRole policy statments:");

      assertTrue(
          "AnyAuthUserWebRoleRef failed: " + "addToRole policy statements for any-authenticated-user (**) failed",
          logProcessor.verifyLogImplies(expectedAddToRolePerms, addToRoleWebRoleRefPermissions));
    }

    /**
     * @testName: validateNoInvalidStates
     *
     * @assertion_ids: JACC:SPEC:60;
     *
     * @test_Strategy: 1. Register TS provider with the AppServer. (See User guide
     *                 for Registering TS Provider with your AppServer ).
     *
     *                 2. Read the server side log to verify PolicyConfigurationFactory
     *                 is called and instantiated in the server.
     *
     *                 Description:
     *
     *                 This method looks for occurrences of error
     *                 message within JACCLog.txt where those error messages would
     *                 only appear in JACCLog.txt if there was a
     *                 policyConfiguration lifecycle state that was in the wrong
     *                 state at the wrong time.
     *
     *                 This can ONLY test the state for being in the 'inService'
     *                 state or not. So testing is done
     *                 to make sure the PolicyConfigration state is correct wrt
     *                 policyConfiguration.inService() for each of the methods
     *                 defined in the PolicyConfiguration javadoc table.
     *
     *                 Again,
     *                 this is not a complete validation of all states, but is
     *                 only able to validate if the state is inService or not at
     *                 each of the method calls based on the javadoc table.
     *                 Occurrence of an ERROR message below would be a flag for a
     *                 method being in an incorrect state.
     */
    @Test
    public void validateNoInvalidStates() {
      LogFileProcessor logProcessor = new LogFileProcessor("getAppSpecificRecordCollection|appId", "app-custom-trace-policyconfiguration");

      String errorMessage1 = "ERROR - our policy config should not be in the INSERVICE state.";

      // Verify that the log contains no errors related to the inService state
      assertFalse(
          "validateNoInvalidStates failed : detected error message of: " + errorMessage1,
          logProcessor.verifyLogContains(errorMessage1));


      String errorMessage2 = "ERROR - our policy config should be in the INSERVICE state.";

      assertFalse(
          "validateNoInvalidStates failed : detected error message of: " + errorMessage2,
          logProcessor.verifyLogContains(errorMessage2));
    }


}
