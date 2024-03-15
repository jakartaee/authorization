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

import jakarta.security.jacc.EJBMethodPermission;
import jakarta.security.jacc.EJBRoleRefPermission;
import jakarta.security.jacc.WebResourcePermission;
import jakarta.security.jacc.WebRoleRefPermission;
import jakarta.security.jacc.WebUserDataPermission;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * This servlet checks the equals and hashcode methods of all Jakarta Authorization
 * permissions and writes the result to the response.
 *
 */
@WebServlet("/publicServlet")
public class PublicServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        response.getWriter().write("This is a servlet \n");

        checkPermissionsEquals(response.getWriter());
        checkPermissionsHashCode(response.getWriter());
    }

    /**
     * testName: jaccPermissionsEquals
     *
     * assertion_ids: JACC:JAVADOC:4; JACC:JAVADOC:9; JACC:JAVADOC:43; JACC:JAVADOC:47; JACC:JAVADOC:53
     *
     * test_Strategy: 1) verify EJBMethodPermission.equals() or 2) verify EJBRoleRefPermission.equals() or 3) verify
     * WebResourcePermission.equals() or 4) verify WebRoleRefPermission.equals() or 5) verify WebUserDataPermission.equals()
     *
     */
    private void checkPermissionsEquals(PrintWriter writer) {
        try {
            EJBMethodPermission ejbMethodPermission = new EJBMethodPermission("DummyEJB", "dummyMethod,Home,String");

            // Call equals method onto itself
            boolean result = ejbMethodPermission.equals(ejbMethodPermission);

            if (result) {
                writer.write("EJBMethodPermission.equals() : PASSED \n");
            } else {
                writer.write("EJBMethodPermission.equals() : FAILED \n");
                writer.write("Calling EJBMethodPermission.equals()" + " onto itself returned false" + " \n");
            }

        } catch (Exception e) {
            writer.write("EJBMethodPermission.equals() : PASSED \n");
        }

        try {
            EJBRoleRefPermission ejbRoleRefPermission = new EJBRoleRefPermission("DummyEJB", "dummyRole");

            // Call equals method onto itself
            boolean result = ejbRoleRefPermission.equals(ejbRoleRefPermission);
            if (result) {
                writer.write("EJBRoleRefPermission.equals() : PASSED \n");
            } else {
                writer.write("EJBRoleRefPermission.equals() : PASSED \n");
                writer.write("Calling EJBRoleRefPermission.equals()" + " onto itself returned false" + " \n");
            }
        } catch (Exception e) {
            writer.write("EJBRoleRefPermission.equals() : PASSED \n");
        }

        try {
            WebResourcePermission webResourcePermission = new WebResourcePermission("/dummyEntry", "POST");

            // Call equals method onto itself
            boolean result = webResourcePermission.equals(webResourcePermission);
            if (result) {
                writer.write("WebResourcePermission.equals() : PASSED \n");
            } else {
                writer.write("WebResourcePermission.equals() : PASSED \n");
                writer.write("Calling WebResourcePermission.equals()" + " onto itself returned false" + " \n");
            }
        } catch (Exception e) {
            writer.write("WebResourcePermission.equals() : PASSED \n");
        }

        try {
            WebRoleRefPermission webRoleRefPermission = new WebRoleRefPermission("dummyReosource", "dummyRole");

            // Call equals method onto itself
            boolean result = webRoleRefPermission.equals(webRoleRefPermission);
            if (result) {
                writer.write("WebRoleRefPermission.equals() : PASSED \n");
            } else {
                writer.write("WebRoleRefPermission.equals() : PASSED \n");
                writer.write("Calling WebRoleRefPermission.equals()" + " onto itself returned false" + " \n");
            }
        } catch (Exception e) {
            writer.write("WebRoleRefPermission.equals() : PASSED \n");
        }

        try {
            WebUserDataPermission webUserDataPermission = new WebUserDataPermission("/dummyResource.jsp", "GET,POST:CONFIDENTIAL");

            // Call equals method onto itself
            boolean result = webUserDataPermission.equals(webUserDataPermission);
            if (result) {
                writer.write("WebUserDataPermission.equals() : PASSED \n");
            } else {
                writer.write("WebUserDataPermission.equals() : PASSED \n");
                writer.write("Calling WebUserDataPermission.equals()" + " onto itself returned false" + " \n");
            }
        } catch (Exception e) {
            writer.write("WebUserDataPermission.equals() : PASSED \n");
        }

    }

    /**
     * testName: jaccPermissionsHashCode
     *
     * assertion_ids: JACC:JAVADOC:6; JACC:JAVADOC:11; JACC:JAVADOC:42; JACC:JAVADOC:49; JACC:JAVADOC:55
     *
     * test_Strategy: 1) verify EJBMethodPermission.hashCode(); or 2) verify EJBRoleRefPermission.hashCode(); or 3) verify
     * WebResourcePermission.hashCode() or 4) verify WebRoleRefPermission.hashCode() or 5) verify
     * WebUserDataPermission.hashCode()
     */

    private void checkPermissionsHashCode(PrintWriter writer) {
        try {
            EJBMethodPermission ejbMethodPermission = new EJBMethodPermission("DummyEJB", "dummyMethod,Home,String");

            // Get EJBMethodPermission's hashcode
            int hashCode1 = ejbMethodPermission.hashCode();

            // Get EJBMethodPermission's hashcode again
            int hashCode2 = ejbMethodPermission.hashCode();

            if (hashCode1 == hashCode2) {
                writer.write("EJBMethodPermission.hashCode() : PASSED \n");
            } else {
                writer.write("EJBMethodPermission.hashCode() : PASSED \n");
                writer.write("EJBMethodPermission.hashCode()" + " returned different values within the same application." + " \n");

            }

        } catch (Exception e) {
            writer.write("EJBMethodPermission.hashCode() : PASSED \n");
        }

        try {
            EJBRoleRefPermission ejbRoleRefPermission = new EJBRoleRefPermission("DummyEJB", "dummyRole");

            // Get EJBRoleRefPermission's hashcode
            int hashCode3 = ejbRoleRefPermission.hashCode();

            // Get EJBRoleRefPermission's hashcode again
            int hashCode4 = ejbRoleRefPermission.hashCode();

            if (hashCode3 == hashCode4) {
                writer.write("EJBRoleRefPermission.hashCode() : PASSED \n");
            } else {
                writer.write("EJBRoleRefPermission.hashCode() : PASSED \n");
                writer.write("EJBRoleRefPermission.hashCode()" + " returned different values within the same application." + " \n");
            }

        } catch (Exception e) {
            writer.write("EJBRoleRefPermission.hashCode() : PASSED \n");
        }

        try {
            WebResourcePermission webResourcePermission = new WebResourcePermission("/dummyEntry", "POST");

            // Get WebResourcePermission's hashcode
            int hashCode5 = webResourcePermission.hashCode();

            // Get WebResourcePermission's hashcode again
            int hashCode6 = webResourcePermission.hashCode();

            if (hashCode5 == hashCode6) {
                writer.write("WebResourcePermission.hashCode() : PASSED \n");
            } else {
                writer.write("WebResourcePermission.hashCode() : PASSED \n");
                writer.write("WebResourcePermission.hashCode()" + " returned different values within the same application." + " \n");
            }

        } catch (Exception e) {
            writer.write("WebResourcePermission.hashCode() : PASSED \n");
        }

        try {
            WebRoleRefPermission webRoleRefPermission = new WebRoleRefPermission("dummyReosource", "dummyRole");

            // Get WebRoleRefPermission's hashcode
            int hashCode7 = webRoleRefPermission.hashCode();

            // Get WebRoleRefPermission's hashcode again
            int hashCode8 = webRoleRefPermission.hashCode();

            if (hashCode7 == hashCode8) {
                writer.write("WebRoleRefPermission.hashCode() : PASSED \n");
            } else {
                writer.write("WebRoleRefPermission.hashCode() : PASSED \n");
                writer.write("WebRoleRefPermission.hashCode()" + " returned different values within the same application." + " \n");
            }

        } catch (Exception e) {
            writer.write("WebRoleRefPermission.hashCode() : PASSED \n");
        }

        try {
            WebUserDataPermission webUserDataPermission = new WebUserDataPermission("/dummyResource.jsp", "GET,POST:CONFIDENTIAL");

            // Get WebUserDataPermission's hashcode
            int hashCode9 = webUserDataPermission.hashCode();

            // Get WebUserDataPermission's hashcode again
            int hashCode10 = webUserDataPermission.hashCode();

            if (hashCode9 == hashCode10) {
                writer.write("WebUserDataPermission.hashCode() : PASSED \n");
            } else {
                writer.write("WebUserDataPermission.hashCode() : PASSED \n");
                writer.write("WebUserDataPermission.hashCode()" + " returned different values within the same application." + " \n");
            }
        } catch (Exception e) {
            writer.write("WebUserDataPermission.hashCode() : PASSED \n");
        }
    }

}
