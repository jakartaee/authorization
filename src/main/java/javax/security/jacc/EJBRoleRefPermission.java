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

import java.io.IOException;
import java.io.ObjectStreamField;
import java.security.Permission;

/**
 * Class for EJB <i><code>isCallerInRole (String reference)</code></i> permissions. An EJBRoleRefPermission is a named
 * permission and has actions.
 * <P>
 * The name of an EJBRoleRefPermission contains the value of the ejb-name element in the application's deployment
 * descriptor that identifies the EJB in whose context the permission is being evalutated.
 * <P>
 * the actions of an EJBRoleRefPermission identifies the role reference to which the permission applies. An
 * EJBRoleRefPermission is checked to determine if the subject is a member of the role identified by the reference.
 * <P>
 * Implementations of this class MAY implement newPermissionCollection or inherit its implementation from the super
 * class.
 *
 * @see java.security.Permission
 *
 * @author Ron Monzillo
 * @author Gary Ellison
 */

public final class EJBRoleRefPermission extends Permission {

	private final String actions;

	private transient int hashCodeValue = 0;

	private static final long serialVersionUID = 1L;

	/**
	 * The serialized fields of this permission are defined below. Whether or not the serialized fields correspond to actual
	 * (private) fields is an implementation decision.
	 * 
	 * @serialField actions String the canonicalized actions string (as returned by getActions).
	 */
	private static final ObjectStreamField[] serialPersistentFields = { new ObjectStreamField("actions", java.lang.String.class) };

	/**
	 * Creates a new EJBRoleRefPermission with the specified name and actions.
	 * 
	 * @param name the ejb-name that identifies the EJB in whose context the role references are to be evaluated.
	 * <P>
	 * @param actions identifies the role reference to which the permission pertains. The role reference is scoped to the
	 * EJB identified in the name parameter. The value of the role reference must not be <code>null</code> or the empty
	 * string.
	 */

	public EJBRoleRefPermission(String name, String actions) {
		super(name);
		this.actions = actions;
	}

	/**
	 * Checks two EJBRoleRefPermission objects for equality. EJBRoleRefPermission objects are equivalent if they have case
	 * equivalent name and actions values.
	 * <P>
	 * Two Permission objects, P1 and P2, are equivalent if and only if P1.implies(P2) && P2.implies(P1).
	 * <P>
	 * 
	 * @param o the EJBRoleRefPermission object being tested for equality with this EJBRoleRefPermission.
	 * <P>
	 * @return true if the argument EJBRoleRefPermission object is equivalent to this EJBRoleRefPermission.
	 */

	public boolean equals(Object o) {
		if (o == null || !(o instanceof EJBRoleRefPermission))
			return false;

		EJBRoleRefPermission that = (EJBRoleRefPermission) o;

		if (!this.getName().equals(that.getName()))
			return false;

		return this.actions.equals(that.actions);
	}

	/**
	 * Returns a canonical String representation of the actions of this EJBRoleRefPermission.
	 * <P>
	 * 
	 * @return a String containing the canonicalized actions of this EJBRoleRefPermission.
	 */

	public String getActions() {
		return this.actions;
	}

	/**
	 * Returns the hash code value for this EJBRoleRefPermission. The properties of the returned hash code must be as
	 * follows:
	 * <p>
	 * <ul>
	 * <li>During the lifetime of a Java application, the hashCode method must return the same integer value, every time it
	 * is called on a EJBRoleRefPermission object. The value returned by hashCode for a particular EJBRoleRefPermission need
	 * not remain consistent from one execution of an application to another.
	 * <li>If two EJBRoleRefPermission objects are equal according to the equals method, then calling the hashCode method on
	 * each of the two Permission objects must produce the same integer result (within an application).
	 * </ul>
	 * <P>
	 * 
	 * @return the integer hash code value for this object.
	 */

	public int hashCode() {

		if (hashCodeValue == 0) {

			String hashInput = this.getName() + " " + this.actions;

			hashCodeValue = hashInput.hashCode();
		}

		return this.hashCodeValue;
	}

	/**
	 * Determines if the argument Permission is "implied by" this EJBRoleRefPermission. For this to be the case,
	 * <p>
	 * </ul>
	 * <li>The argument must be an instanceof EJBRoleRefPermission
	 * <li>with name equivalent to that of this EJBRoleRefPermission, and
	 * <li>with the role reference equivalent to that of this EJBRoleRefPermission applies.
	 * <P>
	 * The name and actions comparisons described above are case sensitive.
	 * <P>
	 * 
	 * @param permission "this" EJBRoleRefPermission is checked to see if it implies the argument permission.
	 * <P>
	 * @return true if the specified permission is implied by this object, false if not.
	 */

	public boolean implies(Permission permission) {
		return this.equals(permission);
	}

	// ----------------- Private Methods ---------------------

	/**
	 * readObject reads the serialized fields from the input stream and uses them to restore the permission. This method
	 * need not be implemented if establishing the values of the serialized fields (as is done by defaultReadObject) is
	 * sufficient to initialize the permission.
	 */
	private void readObject(java.io.ObjectInputStream s) throws IOException, ClassNotFoundException {
		s.defaultReadObject();
	}

	/**
	 * writeObject is used to establish the values of the serialized fields before they are written to the output stream and
	 * need not be implemented if the values of the serialized fields are always available and up to date. The serialized
	 * fields are written to the output stream in the same form as they would be written by defaultWriteObject.
	 */
	private synchronized void writeObject(java.io.ObjectOutputStream s) throws IOException {
		s.defaultWriteObject();
	}

}
