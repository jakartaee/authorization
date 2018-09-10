/*
 * Copyright (c) 1997, 2018 Oracle and/or its affiliates. All rights reserved.
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

package javax.security.jacc;

/**
 * This checked exception is thrown by implementations of the <code>javax.security.jacc.PolicyConfiguration</code>
 * Interface, the <code>javax.security.jacc.PolicyConfigurationFactory</code> abstract class, the
 * <code>javax.security.jacc.PolicyContext</code> utility class, and implementations of the
 * <code>javax.security.jacc.PolicyContextException</code> Interface.
 * <P>
 * This exception is used by javax.security.jacc implementation classes to rethrow checked exceptions ocurring within an
 * implementation that are not declared by the interface or class being implemented.
 *
 * @see java.lang.Exception
 * @see javax.security.jacc.PolicyConfiguration
 * @see javax.security.jacc.PolicyConfigurationFactory
 * @see javax.security.jacc.PolicyContext
 * @see javax.security.jacc.PolicyContextHandler
 *
 * @author Ron Monzillo
 * @author Gary Ellison
 */
public class PolicyContextException extends java.lang.Exception {

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
	 * @param msg - a <code>String</code> containing a detail message describing the cause of the exception.
	 */
	public PolicyContextException(String msg) {
		super(msg);
	}

	/**
	 * Constructs a new PolicyContextException with the specified detail message and cause. The cause will be encapsulated
	 * in the constructed exception.
	 * 
	 * @param msg - a <code>String containing a detail message describing the 
	 * cause of the exception.
	 * &#64;param cause - the Throwable that is "causing" this exception to be 
	 * constructed. A null value is permitted, and the value passed through
	 * this parameter may subsequently be retrieved by calling 
	 * <code>getCause()</code> on the constructed exception.
	 */
	public PolicyContextException(String msg, Throwable cause) {
		super(msg, cause);
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
