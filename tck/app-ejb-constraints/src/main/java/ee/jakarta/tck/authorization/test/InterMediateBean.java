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

import static jakarta.ejb.TransactionAttributeType.NEVER;
import static java.util.logging.Level.INFO;

import jakarta.annotation.Resource;
import jakarta.annotation.security.DeclareRoles;
import jakarta.annotation.security.RolesAllowed;
import jakarta.annotation.security.RunAs;
import jakarta.ejb.EJB;
import jakarta.ejb.EJBAccessException;
import jakarta.ejb.EJBs;
import jakarta.ejb.SessionContext;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionManagement;
import jakarta.ejb.TransactionManagementType;
import java.util.logging.Logger;

@EJBs({
    @EJB(name = "TargetBean", beanName = "TargetBean", beanInterface = Target.class) })
@TransactionManagement(TransactionManagementType.CONTAINER)
@DeclareRoles({ "Administrator", "Employee", "Manager" })
@RolesAllowed({ "Administrator", "Employee", "Manager" })
@RunAs("Manager")
@Stateless(name = "InterMediateBean")
public class InterMediateBean implements InterMediate {

    private Logger logger = Logger.getLogger(InterMediateBean.class.getName());

    // Lookup TargetBean and save the reference in ejb1
    @EJB(beanName = "TargetBean")
    private Target ejb1;

    private SessionContext sessionContext;

    @Resource
    public void setSessionContext(SessionContext sessionContext) {
        this.sessionContext = sessionContext;
    }

    @Override
    @RolesAllowed({ "Administrator", "Employee", "Manager" })
    @TransactionAttribute(NEVER)
    public boolean IsCallerB1(String caller) {
        String name = sessionContext.getCallerPrincipal().getName();
        logMsg("IsCallerB1: " + name);

        return !(name.indexOf(caller) < 0);
    }

    @Override
    @RolesAllowed({ "Administrator", "Employee", "Manager" })
    @TransactionAttribute(NEVER)
    public boolean IsCallerB2(String caller) {
        try {
            logMsg("Running IsCallerB2 :" + caller);
            return ejb1.IsCaller(caller);
        } catch (Exception e) {
            logMsg("Caught Unexpected exception e.getMessage()");
            return false;
        }
    }

    @Override
    @RolesAllowed({ "Administrator", "Employee", "Manager" })
    @TransactionAttribute(NEVER)
    public boolean InRole(String role) {
        try {
            logMsg("Running InRole : " + role);
            return ejb1.EjbSecRoleRef(role);
        } catch (Exception e) {
            logMsg("Caught Unexpected exception e.getMessage()");
            return false;
        }
    }

    @Override
    @RolesAllowed({ "Administrator", "Employee", "Manager" })
    @TransactionAttribute(NEVER)
    public boolean EjbNotAuthz() {
        try {
            ejb1.EjbNotAuthz();
            logMsg("Method call did not generate an expected jakarta.ejb.EJBAccessException");
            return false;
        } catch (EJBAccessException e) {
            logMsg("Caught jakarta.ejb.EJBAccessException as expected");
            cleanup(ejb1);
            return true;
        } catch (Exception e) {
            logMsg("Caught Unexpected exception e.getMessage()");
            cleanup(ejb1);
            return false;
        }
    }

    private void cleanup(Target ejbref) {

    }

    @Override
    @RolesAllowed({ "Administrator", "Employee", "Manager" })
    @TransactionAttribute(NEVER)
    public boolean EjbIsAuthz() {
        logMsg("In InterMediateBean.EjbIsAuthz method");
        try {
            boolean result = ejb1.EjbIsAuthz();

            if (!result) {
                return false;
            }

        } catch (Exception e) {
            logMsg("Caught Unexpected exception e.getMessage()");
            return false;
        }

        return true;
    }

    @Override
    @RolesAllowed({ "Administrator", "Employee", "Manager" })
    @TransactionAttribute(NEVER)
    public boolean EjbSecRoleRef(String role) {
        logMsg("In InterMediateBean.EjbSecRoleRef method");
        try {
            return ejb1.EjbSecRoleRef(role);
        } catch (Exception e) {
            logMsg("Caught Unexpected exception e.getMessage()");
            return false;
        }
    }

    @Override
    @RolesAllowed({ "Administrator", "Employee", "Manager" })
    @TransactionAttribute(NEVER)
    public boolean uncheckedTest() {
        logMsg("In InterMediateBean.uncheckedTest method");
        try {
            return ejb1.uncheckedTest();
        } catch (Exception e) {
            logMsg("InterMediateBean.unchecktedTest failed with exception: " + e.getMessage());
            return false;
        }
    }

    @Override
    @RolesAllowed({ "Administrator", "Employee", "Manager" })
    @TransactionAttribute(NEVER)
    public boolean excludeTest() {
        logMsg("In InterMediateBean.excludeTest method");

        try {
            ejb1.excludeTest();
            return false;
        } catch (EJBAccessException ex) {
            logMsg("InterMediateBean : Got expected EJBAccessException");
            return true;

        } catch (Exception e) {
            logMsg("InterMediateBean.excludeTest failed with exception: " + e.getMessage());
            return false;
        }
    }

    @TransactionAttribute(NEVER)
    public void logMsg(String msg) {
        logger.log(INFO, msg);
    }

}
