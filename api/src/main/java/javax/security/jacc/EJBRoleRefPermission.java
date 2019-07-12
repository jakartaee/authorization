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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.security.Permission;

/**
 * Class for Jakarta Enterprise Beans <i><code>isCallerInRole (String reference)</code></i> permissions. 
 * An EJBRoleRefPermission is a named permission and has actions.
 * 
 * <p>
 * The name of an EJBRoleRefPermission contains the value of the ejb-name element in the application's deployment
 * descriptor that identifies the Jakarta Enterprise Bean in whose context the permission is being evalutated.
 * 
 * <p>
 * The actions of an EJBRoleRefPermission identifies the role reference to which the permission applies. An
 * EJBRoleRefPermission is checked to determine if the subject is a member of the role identified by the reference.
 * 
 * <p>
 * Implementations of this class MAY implement newPermissionCollection or inherit its implementation from the super
 * class.
 *
 * @see java.security.Permission
 *
 * @author Ron Monzillo
 * @author Gary Ellison
 */
public final class EJBRoleRefPermission extends Permission {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * The serialized fields of this permission are defined below. Whether or not the serialized fields correspond to actual
     * (private) fields is an implementation decision.
     * 
     * @serialField actions String the canonicalized actions string (as returned by getActions).
     */
    private static final ObjectStreamField[] serialPersistentFields = { new ObjectStreamField("actions", String.class) };

    private final String actions;
    private transient int hashCodeValue;
    

    /**
     * Creates a new EJBRoleRefPermission with the specified name and actions.
     * 
     * @param name the ejb-name that identifies the Jakarta Enterprise Bean in whose context the role references are to be evaluated.
     * @param actions identifies the role reference to which the permission pertains. The role reference is scoped to the
     * Jakarta Enterprise Bean identified in the name parameter. The value of the role reference must not be <code>null</code> or the empty
     * string.
     */
    public EJBRoleRefPermission(String name, String actions) {
        super(name);
        this.actions = actions;
    }

    /**
     * Checks two EJBRoleRefPermission objects for equality. EJBRoleRefPermission objects are equivalent if they have case
     * equivalent name and actions values.
     * 
     * <p>
     * Two Permission objects, P1 and P2, are equivalent if and only if P1.implies(P2) AND P2.implies(P1).
     * 
     * @param other the EJBRoleRefPermission object being tested for equality with this EJBRoleRefPermission.
     * 
     * @return true if the argument EJBRoleRefPermission object is equivalent to this EJBRoleRefPermission.
     */
    @Override
    public boolean equals(Object other) {
        if (other == null || !(other instanceof EJBRoleRefPermission)) {
            return false;
        }

        EJBRoleRefPermission that = (EJBRoleRefPermission) other;

        if (!this.getName().equals(that.getName())) {
            return false;
        }

        return this.actions.equals(that.actions);
    }

    /**
     * Returns a canonical String representation of the actions of this EJBRoleRefPermission.
     * 
     * @return a String containing the canonicalized actions of this EJBRoleRefPermission.
     */
    @Override
    public String getActions() {
        return actions;
    }

    /**
     * Returns the hash code value for this EJBRoleRefPermission.
     * 
     * <p>
     * The properties of the returned hash code must be as follows:
     * <ul>
     * <li>During the lifetime of a Java application, the hashCode method must return the same integer value, every time it
     * is called on a EJBRoleRefPermission object. The value returned by hashCode for a particular EJBRoleRefPermission need
     * not remain consistent from one execution of an application to another.
     * <li>If two EJBRoleRefPermission objects are equal according to the equals method, then calling the hashCode method on
     * each of the two Permission objects must produce the same integer result (within an application).
     * </ul>
     * 
     * @return the integer hash code value for this object.
     */
    @Override
    public int hashCode() {
        if (hashCodeValue == 0) {
            String hashInput = getName() + " " + actions;
            hashCodeValue = hashInput.hashCode();
        }

        return this.hashCodeValue;
    }

    /**
     * Determines if the argument Permission is "implied by" this EJBRoleRefPermission.
     * 
     * <p>
     * For this to be the case,
     * <ul>
     * <li>The argument must be an <code>instanceof</code> <code>EJBRoleRefPermission</code>
     * <li>with name equivalent to that of this <code>EJBRoleRefPermission</code>, and
     * <li>with the role reference equivalent to that of this <code>EJBRoleRefPermission</code> applies.
     * </ul>
     * <p>
     * The name and actions comparisons described above are case sensitive.
     * 
     * @param permission "this" EJBRoleRefPermission is checked to see if it implies the argument permission.
     * @return true if the specified permission is implied by this object, false if not.
     */
    @Override
    public boolean implies(Permission permission) {
        return equals(permission);
    }

    // ----------------- Private Methods ---------------------

    /**
     * readObject reads the serialized fields from the input stream and uses them to restore the permission. This method
     * need not be implemented if establishing the values of the serialized fields (as is done by defaultReadObject) is
     * sufficient to initialize the permission.
     * 
     * @param inputStream The stream from which the fields are read
     * 
     * @throws ClassNotFoundException If the class of an object couldn't be found
     * @throws IOException If an I/O error occurs
     */
    private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException {
        inputStream.defaultReadObject();
    }

    /**
     * writeObject is used to establish the values of the serialized fields before they are written to the output stream and
     * need not be implemented if the values of the serialized fields are always available and up to date. The serialized
     * fields are written to the output stream in the same form as they would be written by defaultWriteObject.
     * 
     * @param outputStream The stream to which the serialized fields are written
     * 
     * @throws IOException If an I/O error occurs while writing to the underlying stream
     */
    private synchronized void writeObject(ObjectOutputStream outputStream) throws IOException {
        outputStream.defaultWriteObject();
    }

}
