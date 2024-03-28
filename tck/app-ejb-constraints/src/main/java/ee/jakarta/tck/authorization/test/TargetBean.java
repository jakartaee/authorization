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

import static jakarta.ejb.TransactionAttributeType.REQUIRED;

import jakarta.annotation.Resource;
import jakarta.annotation.security.DeclareRoles;
import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ejb.SessionContext;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;

@DeclareRoles({ "Administrator", "Manager", "Employee" })
@Stateless(name = "TargetBean")
public class TargetBean implements Target {

    private SessionContext sessionContext;

    @Resource
    public void setSessionContext(SessionContext sc) {
        sessionContext = sc;
    }

    @Override
    @TransactionAttribute(REQUIRED)
    public boolean IsCaller(String caller) {
        return !(sessionContext.getCallerPrincipal().getName().indexOf(caller) < 0);
    }

    @Override
    @RolesAllowed({ "Administrator" })
    @TransactionAttribute(REQUIRED)
    public boolean EjbNotAuthz() {
        return true;
    }

    @Override
    @RolesAllowed({ "Administrator", "Manager", "Employee" })
    @TransactionAttribute(REQUIRED)
    public boolean EjbIsAuthz() {
        return true;
    }

    @Override
    @RolesAllowed({ "Manager", "Employee" })
    @TransactionAttribute(REQUIRED)
    public boolean EjbSecRoleRef(String role) {
        return sessionContext.isCallerInRole(role);
    }

    @Override
    @PermitAll
    public boolean uncheckedTest() {
        return true;
    }

    @Override
    @DenyAll
    @TransactionAttribute(REQUIRED)
    public boolean excludeTest() {
        return true;
    }

}
