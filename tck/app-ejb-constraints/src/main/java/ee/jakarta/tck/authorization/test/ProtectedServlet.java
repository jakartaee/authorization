/*
 * Copyright (c) 2024 Contributors to Eclipse Foundation.
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

import jakarta.ejb.EJB;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.HttpConstraint;
import jakarta.servlet.annotation.ServletSecurity;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * This Servlet runs each of the Enterprise Beans tests.
 *
 * <p>
 * Note that this uses plain Servlet and Enterprise Beans code and does not
 * use anything Jakarta Authorization specific. It is the responsibility of the
 * one performing the test to make sure the product under test indeed uses
 * Jakarta Authorization internally.
 *
 * <p>
 * Products that don't support Jakarta Authorization, but do provide a compliant
 * Servlet and specificatlly Jakarta Enterprise Beans implementation should be able
 * to pass these tests as well.
 *
 * <p>
 * All the tests require an initial caller authenticated as "j2ee" with role "Employee".
 *
 */
@WebServlet("/protectedServlet/*")
@ServletSecurity(@HttpConstraint(rolesAllowed = "Employee"))
public class ProtectedServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @EJB(beanName = "InterMediateBean")
    private InterMediate ejbref;

    // Security role references.
    // Note: To test annotation @DeclareRoles, same role names are used as
    // role-links. If there is a need to link different role-names for
    // role-links then old-style deployment descriptor should be used for
    // adding such role references.
    private static final String emp_secrole_ref = "Employee";
    private static final String admin_secrole_ref = "Administrator";
    private static final String mgr_secrole_ref = "Manager";

    // Principal name corresponding to RunAs.  It's server specific how to exactly set this
    // for the RunAs role "Manager". The default here uses identity mapping.
    private String authuser = "Manager";
    private String username = "j2ee";

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        response.getWriter().write("This is a servlet \n");

        switch (request.getParameter("test")) {
            case "ADM_InRole":
                ADM_InRole(response.getWriter());
                break;
            case "EjbIsAuthz":
                EjbIsAuthz(response.getWriter());
                break;
            case "EjbNotAuthz":
                EjbNotAuthz(response.getWriter());
                break;
            case "EjbSecRoleRef":
                EjbSecRoleRef(response.getWriter());
                break;
            case "excludeTest":
                excludeTest(response.getWriter());
                break;
            case "InterMediateBean_CallerPrincipal":
                InterMediateBean_CallerPrincipal(response.getWriter());
                break;
            case "MGR_InRole":
                MGR_InRole(response.getWriter());
                break;
            case "TargetBean_CallerPrincipal":
                TargetBean_CallerPrincipal(response.getWriter());
                break;
            case "uncheckedTest":
                uncheckedTest(response.getWriter());
                break;
        }
    }

    /*
     * @testName: ADM_InRole
     *
     * @assertion_ids: EJB:SPEC:61.8; // Add JSR250 assertion for DeclareRoles
     *
     * @test_Strategy: 1. Create a stateless session bean "InterMediateBean" with runas identity set to <Manager> 2. Create
     * another stateless session beans "TargetBean" 3. Invoke InterMediateBean.InRole() with admin_secrole_ref this inturn
     * invokes TargetBean.IsCaller() with admin_secrole_ref 4. Since InterMediateBean is configured to run as <Manager> the
     * TargetBean.IsCaller() with admin_secrole_ref must return false.
     */
    public void ADM_InRole(PrintWriter writer) {
        writer.write("Starting ADM_InRole test");
        try {
            if (ejbref.InRole(admin_secrole_ref)) {
                throw new IllegalStateException("ADM_InRole test failed");
            }
            writer.write("ADM_InRole test passed");
        } catch (Exception e) {
            throw new IllegalStateException("ADM_InRole test failed:", e);
        }
    }

    /*
     * @testName: EjbIsAuthz
     *
     * @assertion_ids: EJB:SPEC:827; JACC:SPEC:103; // Add JSR250 Assertion for RolesAllowed
     *
     * @test_Strategy: 1. Create a stateless session bean "InterMediateBean" with runas identity set to <Manager> 2. Create
     * another stateless session bean "TargetBean" with method EjbIsAuthz 3. Protect the method with multiple security roles
     * including <Manager> 4. Call the InterMediateBean.EjbIsAuthz() as principal <username,password>. Which then invokes
     * the EjbIsAuthz() on the TargetBean. 5. Since then InterMediateBean uses runas identity, <Manager>, which is one of
     * security roles set on the method permission, so access to the method EjbIsAuthz should be allowed. 6. Verify call
     * returns successfully.
     */
    public void EjbIsAuthz(PrintWriter writer) {
        writer.write("Starting EjbIsAuthz test");
        try {
            if (!ejbref.EjbIsAuthz()) {
                throw new IllegalStateException("EjbIsAuthz test failed");
            }
            writer.write("EjbIsAuthz test passed");
        } catch (Exception e) {
            throw new IllegalStateException("EjbIsAuthz test failed: ", e);
        }
    }

    /*
     * @testName: EjbNotAuthz
     *
     * @assertion_ids: EJB:SPEC:811 ; JACC:SPEC:103; // Add JSR250 assertion for RolesAllowed
     *
     * @test_Strategy: 1. Create a stateless session bean "InterMediateBean" with runas identity set to <Manager> 2. Create
     * another stateless session bean "TargetBean" with method EjbNotAuthz 3. Protect the method with security role
     * <Administrator> 4. Call the bean InterMediateBean.EjbNotAuthz() as principal <username,password>. Which then invokes
     * the EjbNotAuthz() on the bean TargetBean. 5. Since then InterMediateBean uses runas identity, <Manager>, which does
     * not share any principals with role <Administrator>. so access to the method EjbNotAuthz shouldnot be allowed. 6.
     * Verify jakarta.ejb.EJBAccessException is generated.
     */
    public void EjbNotAuthz(PrintWriter writer) {
        writer.write("Starting EjbNotAuthz test");
        try {
            if (!ejbref.EjbNotAuthz()) {
                throw new IllegalStateException("EjbNotAuthz test failed");
            }
            writer.write("EjbNotAuthz test passed");
        } catch (Exception e) {
            throw new IllegalStateException("EjbNotAuthz test failed:", e);
        }
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
    public void EjbSecRoleRef(PrintWriter writer) {
        writer.write("Starting EjbSecRoleRef test");
        try {
            if (!ejbref.EjbSecRoleRef(emp_secrole_ref)) {
                throw new IllegalStateException("EjbSecRoleRef test failed");
            }
            writer.write("EjbSecRoleRef test passed");
        } catch (Exception e) {
            throw new IllegalStateException("EjbSecRoleRef test failed: ", e);
        }
    }

    /*
     * @testName: excludeTest
     *
     * @assertion_ids: EJB:SPEC:808; // Add JSR250 assertion for DenyAll
     *
     * @test_Strategy: 1. Create a stateless session bean with runas identity <Manager> 2. Invoke
     * InterMediateBean.excludeTest(), this in-turn invokes TargetBean.excludeTest(). 3. Put the TargetBean's excludeTest()
     * method in the exclude-list or DenyAll 4. Verify that jakarta.ejb.EJBAccessException is generated.
     */
    public void excludeTest(PrintWriter writer) {
        writer.write("Starting excludeTest ");
        try {
            if (!ejbref.excludeTest()) {
                writer.write("excludeTest returned false");
                throw new IllegalStateException("excludeTest failed");
            }
            writer.write("excludeTest passed");
        } catch (Exception e) {
            throw new IllegalStateException("excludeTest failed:", e);
        }
    }

    /*
     * @testName: InterMediateBean_CallerPrincipal
     *
     * @assertion_ids: EJB:SPEC:796; // Add JSR250 assertion for RunAs
     *
     * @test_Strategy: 1. Create a stateless session bean InterMediateBean with runas identity set to <Manager> 2. Verify
     * that InterMediateBean returns the correct getCallerPrincipal() this should not be affected because it is configured
     * to run as <Manager>
     */
    public void InterMediateBean_CallerPrincipal(PrintWriter writer) {
        writer.write("Starting InterMediateBean_CallerPrincipal test");
        try {
            if (!ejbref.IsCallerB1(username)) {
                throw new IllegalStateException("InterMediateBean_CallerPrincipal test failed");
            }
            writer.write("InterMediateBean_CallerPrincipal test passed");
        } catch (Exception e) {
            throw new IllegalStateException("InterMediateBean_CallerPrincipal test failed:", e);
        }
    }

    /*
     * @testName: MGR_InRole
     *
     * @assertion_ids: EJB:SPEC:827; //Add JSR 250 assertion for DeclareRoles
     *
     * @test_Strategy: 1. Create a stateless session bean "InterMediateBean" with runas identity set to <Manager> 2. Create
     * another stateless session beans "TargetBean" 3. Invoke InterMediateBean.InRole() with mgr_secrole_ref this inturn
     * invokes TargetBean.IsCaller() with mgr_secrole_ref 4. Since InterMediateBean is configured to run as <Manager> the
     * TargetBean.IsCaller() with mgr_secrole_ref must return true.
     */
    public void MGR_InRole(PrintWriter writer) {
        writer.write("Starting MGR_InRole");
        try {
            if (!ejbref.InRole(mgr_secrole_ref)) {
                throw new IllegalStateException("MGR_InRole test failed");
            }
            writer.write("MGR_InRole test passed");
        } catch (Exception e) {
            throw new IllegalStateException("MGR_InRole test failed:", e);
        }
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
    public void TargetBean_CallerPrincipal(PrintWriter writer) {
        writer.write("Starting TargetBean_CallerPrincipal test");
        try {
            if (ejbref.IsCallerB2(username) || !ejbref.IsCallerB2(authuser)) {
                throw new IllegalStateException("TargetBean_CallerPrincipal test failed");
            }

            writer.write("TargetBean_CallerPrincipal test passed");
        } catch (Exception e) {
            throw new IllegalStateException("TargetBean_CallerPrincipal test failed:", e);
        }
    }

    /*
     * @testName: uncheckedTest
     *
     * @assertion_ids: EJB:SPEC:827; note: Add JSR250 assertion for PermitAll
     *
     * @test_Strategy: 1. Create a stateless session bean with runas identity <Manager> 2. Invoke
     * InterMediateBean.uncheckedTest() this in-turn invokes TargetBean.uncheckedTest(). 3. Protect the TargetBean's
     * uncheckedTest() with method permission "unchecked" or PermitAll 4. Verify that access is allowed.
     */

    public void uncheckedTest(PrintWriter writer) {
        writer.write("Starting uncheckedTest ");
        try {
            if (!ejbref.uncheckedTest()) {
                writer.write("uncheckedTest returned false");
                throw new IllegalStateException("uncheckedTest failed");
            }

            writer.write("uncheckedTest passed.");
        } catch (Exception e) {
            throw new IllegalStateException("uncheckedTest failed", e);
        }
    }

}
