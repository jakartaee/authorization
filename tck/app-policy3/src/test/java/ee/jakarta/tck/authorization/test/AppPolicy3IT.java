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

import static ee.jakarta.tck.authorization.util.ShrinkWrap.mavenWar;
import static org.junit.Assert.assertTrue;

import com.gargoylesoftware.htmlunit.DefaultCredentialsProvider;
import ee.jakarta.tck.authorization.util.ArquillianBase;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;


@RunWith(Arquillian.class)
public class AppPolicy3IT extends ArquillianBase {

    @Deployment(testable = false)
    public static Archive<?> createDeployment() {
        return mavenWar();
    }

    /**
     * Access a protected Servlet, and check from within that Servlet whether the
     * permission checks from the Policy match with the expectations for that request.
     */
    @Test
    public void testAuthenticated() {
        DefaultCredentialsProvider credentialsProvider = new DefaultCredentialsProvider();
        credentialsProvider.addCredentials("reza", "secret1");

        getWebClient().setCredentialsProvider(credentialsProvider);

        String response = readFromServer("/protectedServlet");

        assertTrue(
            "Should have not have had unchecked access, but had.\n" +
            response,
            response.contains("Current request is unchecked: false"));

        assertTrue(
                "Should have not be excluded from access, but was.\n" +
                response,
                response.contains("Current request is excluded: false"));

        assertTrue(
                "Should have had access by role, but had not.\n" +
                response,
                response.contains("Current request is by role: true"));
    }

}
