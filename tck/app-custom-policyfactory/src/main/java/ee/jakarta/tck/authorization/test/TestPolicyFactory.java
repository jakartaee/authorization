/*
 * Copyright (c) 2024 Contributors to Eclipse Foundation.
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

import jakarta.security.jacc.Policy;
import jakarta.security.jacc.PolicyFactory;

/**
 * Test policy configuration factory.
 *
 * <p>
 * This factort is solely used to test for replacement and wrapping of the PolicyFactory.
 * It ignores the <code>contextId</code> which is not something real factories should
 * do in most cases, and therefor should not be used as an example of how to create
 * a custom PolicyFactory.
 */
public class TestPolicyFactory extends PolicyFactory {

    private Policy policy;

    public TestPolicyFactory(PolicyFactory policyFactory) {
        super(policyFactory);
        policy =  new TestPolicy(policyFactory.getPolicy());
    }

    public Policy getPolicy(String contextId) {
        return policy;
    }

    @Override
    public void setPolicy(String contextId, Policy policy) {
        this.policy = new TestPolicy(policy);
    }
}
