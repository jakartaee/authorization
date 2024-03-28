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
import static org.junit.Assert.assertTrue;

import ee.jakarta.tck.authorization.util.ArquillianBase;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(Arquillian.class)
public class AppEJBConstraintsIT extends ArquillianBase {

    @Deployment(testable = false)
    public static Archive<?> createDeployment() {
        return mavenWar();
    }

    /*
     * @testName: ADM_InRole
     *
     * @assertion_ids: EJB:SPEC:61.8; // Add JSR250 assertion for DeclareRoles
     *
     * @test_Strategy:
     *  1. Create a stateless session bean "InterMediateBean" with runas identity set to <Manager>
     *  2. Create another stateless session beans "TargetBean"
     *  3. Invoke InterMediateBean.InRole() with admin_secrole_ref this inturn
     *     invokes TargetBean.IsCaller() with admin_secrole_ref
     *  4. Since InterMediateBean is configured to run as <Manager> the
     *     TargetBean.IsCaller() with admin_secrole_ref must return false.
     */
    @Test
    public void ADM_InRole() {
        assertTrue(
            readFromServerWithCredentials("/protectedServlet?test=ADM_InRole", "j2ee", "j2ee")
                .contains("ADM_InRole test passed"));
    }

    /*
     * @testName: EjbIsAuthz
     *
     * @assertion_ids: EJB:SPEC:827; JACC:SPEC:103; // Add JSR250 Assertion for RolesAllowed
     *
     * @test_Strategy:
     *  1. Create a stateless session bean "InterMediateBean" with runas identity set to <Manager>
     *  2. Create another stateless session bean "TargetBean" with method EjbIsAuthz
     *  3. Protect the method with multiple security roles including <Manager>
     *  4. Call the InterMediateBean.EjbIsAuthz() as principal <username,password>. Which then invokes
     *     the EjbIsAuthz() on the TargetBean.
     *  5. Since then InterMediateBean uses runas identity, <Manager>, which is one of security roles set
     *  on the method permission, so access to the method EjbIsAuthz should be allowed.
     *  6. Verify call returns successfully.
     */
    @Test
    public void EjbIsAuthz() {
        assertTrue(
            readFromServerWithCredentials("/protectedServlet?test=EjbIsAuthz", "j2ee", "j2ee")
                .contains("EjbIsAuthz test passed"));
    }

    /*
     * @testName: EjbNotAuthz
     *
     * @assertion_ids: EJB:SPEC:811 ; JACC:SPEC:103; // Add JSR250 assertion for RolesAllowed
     *
     * @test_Strategy:
     *  1. Create a stateless session bean "InterMediateBean" with runas identity set to <Manager>
     *  2. Create another stateless session bean "TargetBean" with method EjbNotAuthz
     *  3. Protect the method with security role
     * <Administrator>
     *  4. Call the bean InterMediateBean.EjbNotAuthz() as principal <username,password>. Which then invokes
     * the EjbNotAuthz() on the bean TargetBean.
     *  5. Since then InterMediateBean uses runas identity, <Manager>, which does
     * not share any principals with role <Administrator>. so access to the method EjbNotAuthz shouldnot be allowed.
     *  6.Verify jakarta.ejb.EJBAccessException is generated.
     */
    @Test
    public void EjbNotAuthz() {
        assertTrue(
            readFromServerWithCredentials("/protectedServlet?test=EjbNotAuthz", "j2ee", "j2ee")
                .contains("EjbNotAuthz test passed"));
    }

    /*
     * @testName: EjbSecRoleRef
     *
     * @assertion_ids: EJB:SPEC:61.7; EJB:SPEC:81.4; // Add JSR 250 assertion for DeclareRoles
     *
     * @test_Strategy:
     *  1. Create a stateless session bean "InterMediateBean" with runas identity set to <Manager>
     *  2. Create another stateless session bean "TargetBean" with method EjbSecRoleRef.
     *  3. Protect the method with security role <Employee>, Link a security role ref - emp_secrole_ref to role <Employee>.
     *  4. Call InterMediateBean.EjbSecRoleRef() principal <username,password>. Which then invokes EjbSecRoleRef on the bean TargetBean.
     *  5. Since then InterMediateBean uses runas identity, <Manager>, who's principals also in role <Employee> so access to the method of
     * bean TargetBean should be allowed.
     *  6. verify that return value of isCallerInRole(emp_secrole_ref) is true.
     */
    @Test
    public void EjbSecRoleRef() {
        assertTrue(
            readFromServerWithCredentials("/protectedServlet?test=EjbSecRoleRef", "j2ee", "j2ee")
                .contains("EjbSecRoleRef test passed"));
    }

    /*
     * @testName: excludeTest
     *
     * @assertion_ids: EJB:SPEC:808; // Add JSR250 assertion for DenyAll
     *
     * @test_Strategy:
     *  1. Create a stateless session bean with runas identity <Manager>
     *  2. Invoke
     * InterMediateBean.excludeTest(), this in-turn invokes TargetBean.excludeTest().
     *  3. Put the TargetBean's excludeTest()
     * method in the exclude-list or DenyAll
     *  4. Verify that jakarta.ejb.EJBAccessException is generated.
     */
    @Test
    public void excludeTest() {
        assertTrue(
            readFromServerWithCredentials("/protectedServlet?test=excludeTest", "j2ee", "j2ee")
                .contains("excludeTest passed"));
    }

    /*
     * @testName: InterMediateBean_CallerPrincipal
     *
     * @assertion_ids: EJB:SPEC:796; // Add JSR250 assertion for RunAs
     *
     * @test_Strategy:
     *  1. Create a stateless session bean InterMediateBean with runas identity set to <Manager>
     *  2. Verify that InterMediateBean returns the correct getCallerPrincipal() this should not be affected because
     *  it is configured to run as <Manager>
     */
    @Test
    public void InterMediateBean_CallerPrincipal() {
        assertTrue(
            readFromServerWithCredentials("/protectedServlet?test=InterMediateBean_CallerPrincipal", "j2ee", "j2ee")
                .contains("InterMediateBean_CallerPrincipal test passed"));
    }

    /*
     * @testName: MGR_InRole
     *
     * @assertion_ids: EJB:SPEC:827; //Add JSR 250 assertion for DeclareRoles
     *
     * @test_Strategy:
     *  1. Create a stateless session bean "InterMediateBean" with runas identity set to <Manager>
     *  2. Create
     * another stateless session beans "TargetBean"
     *  3. Invoke InterMediateBean.InRole() with mgr_secrole_ref this inturn
     * invokes TargetBean.IsCaller() with mgr_secrole_ref
     *  4. Since InterMediateBean is configured to run as <Manager> the
     * TargetBean.IsCaller() with mgr_secrole_ref must return true.
     */
    @Test
    public void MGR_InRole() {
        assertTrue(
            readFromServerWithCredentials("/protectedServlet?test=MGR_InRole", "j2ee", "j2ee")
                .contains("MGR_InRole test passed"));
    }

    /*
     * @testName: TargetBean_CallerPrincipal
     *
     * @assertion_ids: EJB:SPEC:796; // Add JSR250 assertion for RunAs
     *
     * @test_Strategy:
     *  1. Create a stateless session bean "InterMediateBean" with runas identity set to <Manager>
     *  2. Create another stateless session bean "TargetBean".
     *  3. Verify that TargetBean returns the correct getCallerPrincipal() which
     *     is the principal using runas identity, but not the principal invoked InterMediateBean.
     */
    @Test
    public void TargetBean_CallerPrincipal() {
        assertTrue(
            readFromServerWithCredentials("/protectedServlet?test=TargetBean_CallerPrincipal", "j2ee", "j2ee")
                .contains("CallerPrincipal test passed"));
    }

    /*
     * @testName: uncheckedTest
     *
     * @assertion_ids: EJB:SPEC:827; note: Add JSR250 assertion for PermitAll
     *
     * @test_Strategy:
     *  1. Create a stateless session bean with runas identity <Manager>
     *  2. Invoke InterMediateBean.uncheckedTest() this in-turn invokes TargetBean.uncheckedTest().
     *  3. Protect the TargetBean's uncheckedTest() with method permission "unchecked" or PermitAll
     *  4. Verify that access is allowed.
     */
    @Test
    public void uncheckedTest() {
        assertTrue(
            readFromServerWithCredentials("/protectedServlet?test=uncheckedTest", "j2ee", "j2ee")
                .contains("uncheckedTest passed"));
    }

}
