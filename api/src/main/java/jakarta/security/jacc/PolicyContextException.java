/*
 * Copyright (c) 1997, 2020 Oracle and/or its affiliates. All rights reserved.
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

package jakarta.security.jacc;

/**
 * This checked exception is thrown by implementations of the <code>PolicyConfiguration</code>
 * Interface, the <code>PolicyConfigurationFactory</code> abstract class, the
 * <code>PolicyContext</code> utility class, and implementations of the
 * <code>PolicyContextException</code> Interface.
 * 
 * <P>
 * This exception is used by jakarta.security.jacc implementation classes to rethrow checked exceptions occurring within
 * an implementation that are not declared by the interface or class being implemented.
 *
 * @see Exception
 * @see PolicyConfiguration
 * @see PolicyConfigurationFactory
 * @see PolicyContext
 * @see PolicyContextHandler
 *
 * @author Ron Monzillo
 * @author Gary Ellison
 */
public class PolicyContextException extends Exception {

	private static final long serialVersionUID = 3925692572777572935L;

	/**
     * Constructs a new PolicyContextException with <code>null</code> as its detail message. describing the cause of the
     * exception.
     */
    public PolicyContextException() {
        super();
    }

    /**
     * Constructs a new PolicyContextException with the specified detail message
     * 
     * @param message - a <code>String</code> containing a detail message describing the cause of the exception.
     */
    public PolicyContextException(String message) {
        super(message);
    }

	/**
	 * Constructs a new PolicyContextException with the specified detail message and cause. The cause will be encapsulated
	 * in the constructed exception.
	 * 
	 * @param message - A <code>String</code> containing a detail message describing the cause of the exception.
	 * @param cause - The Throwable that is "causing" this exception to be constructed. A null value is permitted, and the
	 * value passed through this parameter may subsequently be retrieved by calling <code>getCause()</code> on the
	 * constructed exception.
	 */
    public PolicyContextException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new PolicyContextException with the specified cause. The cause will be encapsulated in the constructed
     * exception.
     *
     * @param cause - the Throwable that is "causing" this exception to be constructed. A null value is permitted, and the
     * value passed through this parameter may subsequently be retrieved by calling <code>getCause()</code> on the
     * constructed exception.
     */
    public PolicyContextException(Throwable cause) {
        super(cause);
    }
}
