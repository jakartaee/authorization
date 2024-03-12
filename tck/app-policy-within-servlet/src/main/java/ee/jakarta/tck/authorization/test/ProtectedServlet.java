/*
 * Copyright (c) 2024 Contributors to the Eclipse Foundation.
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

import static jakarta.security.jacc.PolicyContext.SUBJECT;

import jakarta.annotation.security.DeclareRoles;
import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyFactory;
import jakarta.security.jacc.WebResourcePermission;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.HttpConstraint;
import jakarta.servlet.annotation.ServletSecurity;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Permission;
import javax.security.auth.Subject;

/**
 * Protected Servlet that prints out the response from the default policy for the current request.
 *
 * <p>
 * The role "foo" is required to access this Servlet. "bar" and "foo" are roles assigned by the
 * native identity store
 *
 */
@WebServlet("/protectedServlet/*")
@DeclareRoles({"bar"})
@ServletSecurity(@HttpConstraint(rolesAllowed = "foo"))
public class ProtectedServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.getWriter().write("This is a servlet \n");

        Policy policy = PolicyFactory.getPolicyFactory().getPolicy();

        // Check permissions for the current request
        Permission requestPermission = new WebResourcePermission(request);
        Subject subject = PolicyContext.get(SUBJECT);

        response.getWriter().write("Current request is unchecked: " + policy.isUnchecked(requestPermission) + "\n");
        response.getWriter().write("Current request is excluded: " + policy.isExcluded(requestPermission) + "\n");
        response.getWriter().write("Current request is by role: " + policy.impliesByRole(requestPermission, subject) + "\n");
    }

}
