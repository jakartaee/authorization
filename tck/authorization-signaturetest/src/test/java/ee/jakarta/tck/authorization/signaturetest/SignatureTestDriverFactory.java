/*
 * Copyright (c) 2022 Oracle and/or its affiliates. All rights reserved.
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

package ee.jakarta.tck.authorization.signaturetest;

/**
 * Factory to obtain SignatureTestDriver implementations.
 */
public class SignatureTestDriverFactory {

    /**
     * Identifier for the driver that uses the Signature Test framwork for signature validation.
     */
    public static final String SIG_TEST = "sigtest";

    // ------------------------------------------------------------ Constructors

    // Access via factory method
    private SignatureTestDriverFactory() {
    }

    // ---------------------------------------------------------- Public Methods

    /**
     * Obtain a {@link SignatureTestDriver} instance based on the <code>type</code> argument.
     *
     * @param type the driver type to create
     * @return a {@link SignatureTestDriver} implementation
     */
    public static SignatureTestDriver getInstance(String type) {
        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Type was null or empty");
        }

        if (SIG_TEST.equals(type)) {
            return new SigTestDriver();
        }

        throw new IllegalArgumentException("Unknown Type: '" + type + '\'');


    }

}
