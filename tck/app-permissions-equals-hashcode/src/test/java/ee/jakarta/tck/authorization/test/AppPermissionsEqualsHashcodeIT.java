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
public class AppPermissionsEqualsHashcodeIT extends ArquillianBase {

    @Deployment(testable = false)
    public static Archive<?> createDeployment() {
        return mavenWar();
    }

    /**
     * @testName: EJBMethodPermissionEquals
     *
     * @assertion_ids: JACC:JAVADOC:4;
     *
     * @test_Strategy: 1. When we call the public servlet the equals() and hashcode() method will be
     *                 called on all Jakarta Authorization Permission classes. ( i.e
     *                 EJBMethodPermission, EJBRoleRefPermission,
     *                 WebResourcePermission, WebRoleRefPermission,
     *                 WebUserDataPermission)
     *
     */
    @Test
    public void EJBMethodPermissionEquals() {
      assertTrue(
          readFromServer("/publicServlet").contains("EJBMethodPermission.equals() : PASSED"));
    }

    /**
     * @testName: EJBMethodPermissionHashCode
     *
     * @assertion_ids: JACC:JAVADOC:6;
     *
     * @test_Strategy: 1. When we call the public servlet the equals() and hashcode() method will be
     *                 called on all Jakarta Authorization Permission classes. ( i.e
     *                 EJBMethodPermission, EJBRoleRefPermission,
     *                 WebResourcePermission, WebRoleRefPermission,
     *                 WebUserDataPermission)
     *
     */
    @Test
    public void EJBMethodPermissionHashCode() {
        assertTrue(
            readFromServer("/publicServlet").contains("EJBMethodPermission.hashCode() : PASSED"));
    }

    /**
     * @testName: EJBRoleRefPermissionEquals
     *
     * @assertion_ids: JACC:JAVADOC:9;
     *
     * @test_Strategy: 1. When we call the public servlet the equals() and hashcode() method will be
     *                 called on all Jakarta Authorization Permission classes. ( i.e
     *                 EJBMethodPermission, EJBRoleRefPermission,
     *                 WebResourcePermission, WebRoleRefPermission,
     *                 WebUserDataPermission)
     *
     */
    @Test
    public void EJBRoleRefPermissionEquals() {
        assertTrue(
            readFromServer("/publicServlet").contains("EJBRoleRefPermission.equals() : PASSED"));
    }

    /**
     * @testName: EJBRoleRefPermissionHashCode
     *
     * @assertion_ids: JACC:JAVADOC:11;
     *
     * @test_Strategy: 1. When we call the public servlet the equals() and hashcode() method will be
     *                 called on all Jakarta Authorization Permission classes. ( i.e
     *                 EJBMethodPermission, EJBRoleRefPermission,
     *                 WebResourcePermission, WebRoleRefPermission,
     *                 WebUserDataPermission)
     *
     */
    @Test
    public void EJBRoleRefPermissionHashCode() {
        assertTrue(
            readFromServer("/publicServlet").contains("EJBRoleRefPermission.hashCode() : PASSED"));
    }

    /**
     * @testName: WebResourcePermissionEquals
     *
     * @assertion_ids: JACC:JAVADOC:40
     *
     * @test_Strategy: 1. When we call the public servlet the equals() and hashcode() method will be
     *                 called on all Jakarta Authorization Permission classes. ( i.e
     *                 EJBMethodPermission, EJBRoleRefPermission,
     *                 WebResourcePermission, WebRoleRefPermission,
     *                 WebUserDataPermission)
     *
     */
    @Test
    public void WebResourcePermissionEquals() {
        assertTrue(
            readFromServer("/publicServlet").contains("WebResourcePermission.equals() : PASSED"));
    }

    /**
     * @testName: WebRoleRefPermissionEquals
     *
     * @assertion_ids: JACC:JAVADOC:47
     *
     * @test_Strategy: 1. When we call the public servlet the equals() and hashcode() method will be
     *                 called on all Jakarta Authorization Permission classes. ( i.e
     *                 EJBMethodPermission, EJBRoleRefPermission,
     *                 WebResourcePermission, WebRoleRefPermission,
     *                 WebUserDataPermission)
     *
     */
    @Test
    public void WebRoleRefPermissionEquals() {
        assertTrue(
            readFromServer("/publicServlet").contains("WebRoleRefPermission.equals() : PASSED"));
    }

    /**
     * @testName: WebUserDataPermissionEquals
     *
     * @assertion_ids: JACC:JAVADOC:53
     *
     * @test_Strategy: 1. When we call the public servlet the equals() and hashcode() method will be
     *                 called on all Jakarta Authorization Permission classes. ( i.e
     *                 EJBMethodPermission, EJBRoleRefPermission,
     *                 WebResourcePermission, WebRoleRefPermission,
     *                 WebUserDataPermission)
     *
     */
    @Test
    public void WebUserDataPermissionEquals() {
        assertTrue(
            readFromServer("/publicServlet").contains("WebUserDataPermission.equals() : PASSED"));
    }

    /**
     * @testName: WebResourcePermissionHashCode
     *
     * @assertion_ids: JACC:JAVADOC:42
     *
     * @test_Strategy: 1. When we call the public servlet the equals() and hashcode() method will be
     *                 called on all Jakarta Authorization Permission classes. ( i.e
     *                 EJBMethodPermission, EJBRoleRefPermission,
     *                 WebResourcePermission, WebRoleRefPermission,
     *                 WebUserDataPermission)
     *
     */
    @Test
    public void WebResourcePermissionHashCode() {
        assertTrue(
            readFromServer("/publicServlet").contains("WebResourcePermission.hashCode() : PASSED"));
    }

    /**
     * @testName: WebRoleRefPermissionHashCode
     *
     * @assertion_ids: JACC:JAVADOC:49
     *
     * @test_Strategy: 1. When we call the public servlet the equals() and hashcode() method will be
     *                 called on all Jakarta Authorization Permission classes. ( i.e
     *                 EJBMethodPermission, EJBRoleRefPermission,
     *                 WebResourcePermission, WebRoleRefPermission,
     *                 WebUserDataPermission)
     *
     */
    @Test
    public void WebRoleRefPermissionHashCode() {
        assertTrue(
            readFromServer("/publicServlet").contains("WebRoleRefPermission.hashCode() : PASSED"));
    }

    /**
     * @testName: WebUserDataPermissionHashCode
     *
     * @assertion_ids: JACC:JAVADOC:55
     *
     * @test_Strategy: 1. When we call the public servlet the equals() and hashcode() method will be
     *                 called on all Jakarta Authorization Permission classes. ( i.e
     *                 EJBMethodPermission, EJBRoleRefPermission,
     *                 WebResourcePermission, WebRoleRefPermission,
     *                 WebUserDataPermission)
     *
     */
    @Test
    public void WebUserDataPermissionHashCode() {
        assertTrue(
                readFromServer("/publicServlet").contains("WebUserDataPermission.hashCode() : PASSED"));
    }

}
