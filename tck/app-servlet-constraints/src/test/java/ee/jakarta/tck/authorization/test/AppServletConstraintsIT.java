/*
 * Copyright (c) 2024 Contributors to Eclipse Foundation.
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import ee.jakarta.tck.authorization.util.ArquillianBase;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;


@RunWith(Arquillian.class)
public class AppServletConstraintsIT extends ArquillianBase {

    @Deployment(testable = false)
    public static Archive<?> createDeployment() {
        return mavenWar();
    }

    /**
     * @testName: IsUserInRole
     *
     * @assertion_ids: JACC:SPEC:65; JACC:SPEC:32; JACC:SPEC:75
     *
     * @test_Strategy:
     *                 1. Deploy a jsp secured.jsp which is accessible by a role
     *                 Administrator.
     *
     *                 2. Assign javajoe to role Administrator and access the jsp
     *
     *                 3. verify the rolename by calling isUserInRole() inside
     *                 secured.jsp
     */
    @Test
    public void IsUserInRole() {
        assertTrue(
            readFromServerWithCredentials("/secured.jsp", "javajoe", "javajoe").contains("javajoe"));
    }

    /**
     * @testName: PermissionsToRole
     *
     * @assertion_ids: JACC:SPEC:65; JACC:SPEC:10; JACC:JAVADOC:19;
     *                 JACC:JAVADOC:25; JACC:JAVADOC:26; JACC:JAVADOC:27;
     *                 JACC:JAVADOC:30; JACC:JAVADOC:31
     *
     * @test_Strategy:
     *                 1. Deploy a jsp secured.jsp which is accessible by a role
     *                 Administrator.
     *
     *                 2. Assign javajoe to role Administrator and access the jsp
     *
     *                 3. If javajoe can access secured.jsp this implies all users
     *                 mapped to Administrator can access secured.jsp
     */
    @Test
    public void PermissionsToRole() {
        IsUserInRole();
    }

    /**
     * @testName: WebResourcePermission
     *
     * @assertion_ids: JACC:SPEC:73; JACC:SPEC:117; JACC:SPEC:76
     *
     * @test_Strategy:
     *                 1. Deploy a jsp called (secured.jsp) configure it to be
     *                 accessible only by Role Administrator
     *
     *                 2. Access secured.jsp with a user(j2ee) who is not in role
     *                 Administrator
     *
     *                 3. expect proper Http error code.
     *
     *                 JSPName URL --------------------------------- secured.jsp
     *                 /secured.jsp
     *
     */
    @Test
    public void WebResourcePermission() {
        assertEquals(403,
            responseFromServerWithCredentials("/secured.jsp", "j2ee", "j2ee").getStatusCode());
    }

    /**
     * @testName: WildCardAuthConstraint
     *
     * @assertion_ids: JACC:SPEC:35; JACC:SPEC:10; JACC:JAVADOC:19;
     *                 JACC:JAVADOC:25; JACC:JAVADOC:26; JACC:JAVADOC:27;
     *                 JACC:JAVADOC:30; JACC:JAVADOC:31; JACC:SPEC:129;
     *
     * @test_Strategy: 1. Register TS provider with the AppServer. (See User guide
     *                 for Registering TS Provider with your AppServer ).
     *
     *                 2. Deploy a jsp AccessToAll.jsp which contains a wildcard
     *                 auth constraint (i.e "*" as shown below) in its security
     *                 constraint. <auth-constraint> <role-name>*</role-name>
     *                 </auth-constraint>
     *
     *                 3. Access the jsp /AccessToAll.jsp from the client.
     *
     *                 4. Make sure the login user javajoe is able to access the
     *                 jsp /AccessToAll.jsp
     *
     *                 4. Make sure the login user is mapped to all roles defined
     *                 in the application (i.e. ADM, EMP and MGR) i.e a)
     *                 isUserInRole("ADM") should return true and b)
     *                 isUserInRole("MGR") should return true and c)
     *                 isUserInRole("EMP") should return true
     *
     *                 5. Make sure the login user is not in the role that is not
     *                 defined in the application. i.e isUserInRole("VP") should
     *                 return false
     */
    @Test
    public void WildCardAuthConstraint() {
        String response = readFromServerWithCredentials("/accesstoall.jsp", "javajoe", "javajoe");

        assertTrue(response.contains("javajoe"));

        assertTrue("not mapped to role ADM", response.contains("USR_IN_ROLE_ADM"));
        assertTrue("not mapped to role MGR", response.contains("USR_IN_ROLE_MGR"));
        assertTrue("not mapped to role EMP", response.contains("USR_IN_ROLE_EMP"));
        assertTrue("mapped to role VP", response.contains("USR_NOT_IN_ROLE_VP"));
    }

    /**
     * @testName: WebUserDataPermission
     *
     * @assertion_ids: JACC:SPEC:71; JACC:SPEC:117; JACC:SPEC:104; JACC:SPEC:113
     *
     * @test_Strategy:
     *                 1. Deploy a jsp called (sslprotected.jsp) with a security
     *                 constraint that has a user-data-constraint
     *                 <transport-guarantee>CONFIDENTIAL</transport-guarantee>
     *
     *                 2. Send https request to sslprotected.jsp, access the
     *                 content of sslprotected.jsp
     *
     *                 JSPName URL ---------------------------------
     *                 sslprotecd.jsp /sslprotected.jsp
     *
     */
    @Test
    public void WebUserDataPermission() {
        setUseBaseSecured(true);
        String response = readFromServerWithCredentials("/sslprotected.jsp", "javajoe", "javajoe");

        assertTrue(response.contains("javajoe"));
    }

}
