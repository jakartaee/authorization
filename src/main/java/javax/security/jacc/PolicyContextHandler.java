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
 * This interface defines the methods that must be implemented by handlers that are to be registered and activated by
 * the <code>PolicyContext</code> class. The <code>PolicyContext</code> class provides methods for containers to
 * register and activate container-specific <code>PolicyContext</code> handlers. <code>Policy</code> providers use the
 * <code>PolicyContext</code> class to activate handlers to obtain (from the container) additional policy relevant
 * context to apply in their access decisions. All handlers registered and activated via the <code>PolicyContext</code>
 * class must implement the <code>PolicyContextHandler</code> interface.
 *
 * @see javax.security.jacc.PolicyContext
 * @see javax.security.jacc.PolicyContextException
 *
 * @author Ron Monzillo
 * @author Gary Ellison
 */
public interface PolicyContextHandler {

	/**
	 * This public method returns a boolean result indicating whether or not the handler supports the context object
	 * identified by the (case-sensitive) key value.
	 * 
	 * @param key a <code>String</code> value identifying a context object that could be supported by the handler. The value
	 * of this parameter must not be null.
	 * @return a boolean indicating whether or not the context object corresponding to the argument key is handled by the
	 * handler.
	 *
	 * @throws javax.security.jacc.PolicyContextException if the implementation throws a checked exception that has not been
	 * accounted for by the method signature. The exception thrown by the implementation class will be encapsulated (during
	 * construction) in the thrown PolicyContextException
	 */
	public boolean supports(String key) throws javax.security.jacc.PolicyContextException;

	/**
	 * This public method returns the keys identifying the context objects supported by the handler. The value of each key
	 * supported by a handler must be a non-null <code>String</code> value.
	 * 
	 * @return an array containing <code>String</code> values identifing the context objects supported by the handler. The
	 * array must not contain duplicate key values. In the unlikely case that the Handler supports no keys, the handler must
	 * return a zero length array. The value null must never be returned by this method.
	 *
	 * @throws javax.security.jacc.PolicyContextException if the implementation throws a checked exception that has not been
	 * accounted for by the method signature. The exception thrown by the implementation class will be encapsulated (during
	 * construction) in the thrown PolicyContextException
	 */
	public String[] getKeys() throws javax.security.jacc.PolicyContextException;

	/**
	 * This public method is used by the <code>PolicyContext</code> class to activate the handler and obtain from it the
	 * context object identified by the (case-sensitive) key. In addition to the key, the handler will be activated with the
	 * handler data value associated within the <code>PolicyContext</code> class with the thread on which the call to this
	 * method is made.
	 * <P>
	 * Note that the policy context identifier associated with a thread is available to the handler by calling
	 * PolicyContext.getContextID().
	 * <P>
	 * 
	 * @param key a String that identifies the context object to be returned by the handler. The value of this paramter must
	 * not be null.
	 * @param data the handler data <code>Object</code> associated with the thread on which the call to this method has been
	 * made. Note that the value passed through this parameter may be <code>null</code>.
	 * @return The container and handler specific <code>Object</code> containing the desired context. A <code>null</code>
	 * value may be returned if the value of the corresponding context is null.
	 *
	 * @throws javax.security.jacc.PolicyContextException if the implementation throws a checked exception that has not been
	 * accounted for by the method signature. The exception thrown by the implementation class will be encapsulated (during
	 * construction) in the thrown PolicyContextException
	 */
	public Object getContext(String key, Object data) throws javax.security.jacc.PolicyContextException;

}
