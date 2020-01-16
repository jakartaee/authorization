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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.lang.reflect.Method;
import java.security.Permission;
import java.util.HashMap;

/**
 * Class for Jakarta Enterprise Beans method permissions.
 * 
 * <p>
 * The name of an EJBMethodPermission contains the value of the ejb-name element in the application's deployment
 * descriptor that identifies the target Jakarta Enterprise Bean.
 * 
 * <p>
 * The actions of an EJBMethodPermission identifies the methods of the Jakarta Enterprise Bean to which the permission applies.
 * 
 * <p>
 * Implementations of this class MAY implement newPermissionCollection or inherit its implementation from the super
 * class.
 *
 * @see java.security.Permission
 *
 * @author Ron Monzillo
 * @author Gary Ellison
 *
 */
public final class EJBMethodPermission extends Permission {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * The serialized fields of this permission are defined below. Whether or not the serialized fields correspond to actual
     * (private) fields is an implementation decision.
     * 
     * @serialField actions String the canonicalized actions string (as returned by getActions).
     */
    private static final ObjectStreamField[] serialPersistentFields = { new ObjectStreamField("actions", String.class) };

    private static final String interfaceKeys[] = { "Local", "LocalHome", "Remote", "Home", "ServiceEndpoint" };
    
    private static HashMap<String, Integer> interfaceHash = new HashMap<String, Integer>();
    static {
        for (int i = 0; i < interfaceKeys.length; i++) {
            interfaceHash.put(interfaceKeys[i], i);
        }
    }

    private transient int methodInterface;
    private transient String otherMethodInterface;
    private transient String methodName;
    private transient String methodParams;
    private transient String actions;
    private transient int hashCodeValue;
    

    /**
     * Creates a new EJBMethodPermission with the specified name and actions.
     * 
     * <p>
     * The name contains the value of the ejb-name element corresponding to an Jakarta Enterprise Bean in the application's deployment
     * descriptor.
     * 
     * <p>
     * The actions contains a methodSpec. The syntax of the actions parameter is defined as follows:
     * 
     * <pre>
     *      methodNameSpec ::= methodName | emptyString
     *
     *      methodInterfaceName ::= String
     *
     *      methodInterfaceSpec ::= methodInterfaceName | emptyString
     *
     *      typeName ::= typeName | typeName []
     *
     *      methodParams ::= typeName | methodParams comma typeName
     *
     *      methodParamsSpec ::= emptyString | methodParams
     *
     *      methodSpec ::= null |
     *           methodNameSpec |
     *           methodNameSpec comma methodInterfaceName |
     *           methodNameSpec comma methodInterfaceSpec comma methodParamsSpec
     * </pre>
     * 
     * <p>
     * A MethodInterfaceName is a non-empty String and should contain a method-intf value as defined for use in Jakarta Enterprise Beans
     * deployment descriptors. An implementation must be flexible such that it supports additional interface names
     * especially if they are standardized by the Jakarta Enterprise Beans Specification. The Jakarta Enterprise Beans Specification 
     * currently defines the following method-intf values:
     * 
     * <pre>
     * { "Home", "LocalHome", "Remote", "Local", "ServiceEndpoint" }
     * </pre>
     * 
     * <p>
     * A null or empty string methodSpec indicates that the permission applies to all methods of the Jakarta Enterprise Bean. 
     * A methodSpec with a methodNameSpec of the empty string matches all methods of the Jakarta Enterprise Bean that match the 
     * methodInterface and methodParams elements of the methodSpec.
     * 
     * <p>
     * A methodSpec with a methodInterfaceSpec of the empty string matches all methods of the Jakarta Enterprise Bean that match the
     * methodNameSpec and methodParamsSpec elements of the methodSpec.
     * 
     * <p>
     * A methodSpec without a methodParamsSpec matches all methods of the Jakarta Enterprise Bean that match the methodNameSpec and
     * methodInterface elements of the methodSpec.
     * 
     * <p>
     * The order of the typeNames in methodParams array must match the order of occurence of the corresponding parameters in
     * the method signature of the target method(s). Each typeName in the methodParams must contain the canonical form of
     * the corresponding parameter's typeName as defined by the getActions method. A methodSpec with an empty
     * methodParamsSpec matches all 0 argument methods of the Jakarta Enterprise Bean that match the methodNameSpec and 
     * methodInterfaceSpec elements of the methodSpec.
     * 
     * @param name of the Jakarta Enterprise Bean to which the permission pertains.
     * @param actions identifies the methods of the Jakarta Enterprise Bean to which the permission pertains.
     */
    public EJBMethodPermission(String name, String actions) {
        super(name);
        setMethodSpec(actions);
    }

    /**
     * Creates a new EJBMethodPermission with name corresponding to the EJBName and actions composed from methodName,
     * methodInterface, and methodParams.
     * 
     * @param EJBName The string representation of the name of the Jakarta Enterprise Bean as it appears in the corresponding 
     * ejb-name element
     * in the deployment descriptor.
     * @param methodName A string that may be used to indicate the method of the Jakarta Enterprise Bean to which the permission 
     * pertains. A value of null or "" indicates that the permission pertains to all methods that match the other parameters of 
     * the permission specification without consideration of method name.
     * @param methodInterface A string that may be used to specify the Jakarta Enterprise Bean interface to which the permission 
     * pertains. A value of null or "", indicates that the permission pertains to all methods that match the other parameters of 
     * the permission specification without consideration of the interface they occur on.
     * @param methodParams An array of strings that may be used to specify (by typeNames) the parameter signature of the
     * target methods. The order of the typeNames in methodParams array must match the order of occurrence of the
     * corresponding parameters in the method signature of the target method(s). Each typeName in the methodParams array
     * must contain the canonical form of the corresponding parameter's typeName as defined by the getActions method. An
     * empty methodParams array is used to represent a method signature with no arguments. A value of null indicates that
     * the permission pertains to all methods that match the other parameters of the permission specification without
     * consideration of method signature.
     */
    public EJBMethodPermission(String EJBName, String methodName, String methodInterface, String[] methodParams) {
        super(EJBName);
        setMethodSpec(methodName, methodInterface, methodParams);
    }

    /**
     * Creates a new EJBMethodPermission with name corresponding to the EJBName and actions composed from methodInterface,
     * and the Method object.
     * 
     * <p>
     * A container uses this constructor prior to checking if a caller has permission to call the method of an Jakarta 
     * Enterprise Bean.
     * 
     * @param EJBName The string representation of the name of the Jakarta Enterprise Bean as it appears in the 
     * corresponding ejb-name element in the deployment descriptor.
     * @param methodInterface A string that may be used to specify the Jakarta Enterprise Bean interface to which the 
     * permission pertains. A value of null or "", indicates that the permission pertains to all methods that match 
     * the other parameters of the permission specification without consideration of the interface they occur on.
     * @param method an instance of the Java.lang.reflect.Method class corresponding to the method that the container is
     * trying to determine whether the caller has permission to access. This value must not be null.
     */
    public EJBMethodPermission(String EJBName, String methodInterface, Method method) {
        super(EJBName);
        setMethodSpec(methodInterface, method);
    }

    /**
     * Checks two EJBMethodPermission objects for equality. EJBMethodPermission objects are equivalent if they have case
     * sensitive equivalent name and actions values.
     * 
     * <p>
     * Two Permission objects, P1 and P2, are equivalent if and only if P1.implies(P2) AND P2.implies(P1).
     * 
     * @param o the EJBMethodPermission object being tested for equality with this EJBMethodPermission
     * 
     * @return true if the argument EJBMethodPermission object is equivalent to this EJBMethodPermission.
     */
    @Override
    public boolean equals(Object o) {
        if (o == null || !(o instanceof EJBMethodPermission)) {
            return false;
        }

        EJBMethodPermission that = (EJBMethodPermission) o;

        if (!this.getName().equals(that.getName())) {
            return false;
        }

        if (this.methodName != null) {
            if (that.methodName == null || !this.methodName.equals(that.methodName)) {
                return false;
            }
        } else if (that.methodName != null) {
            return false;
        }

        if (this.methodInterface != that.methodInterface) {
            return false;
        }

        if (this.methodInterface == -2 && !this.otherMethodInterface.equals(that.otherMethodInterface)) {
            return false;
        }

        if (this.methodParams != null) {
            if (that.methodParams == null || !this.methodParams.equals(that.methodParams)) {
                return false;
            }
        } else if (that.methodParams != null) {
            return false;
        }

        return true;
    }

    /**
     * Returns a String containing a canonical representation of the actions of this EJBMethodPermission. The Canonical form
     * of the actions of an EJBMethodPermission is described by the following syntax description.
     * 
     * <pre>
     *      methodNameSpec ::= methodName | emptyString
     *
     *      methodInterfaceName ::= String
     *
     *      methodInterfaceSpec ::= methodInterfaceName | emptyString
     *
     *      typeName ::= typeName | typeName []
     *
     *      methodParams ::= typeName | methodParams comma typeName
     *
     *      methodParamsSpec ::= emptyString | methodParams
     *
     *      methodSpec ::= null |
     *           methodName |
     *           methodNameSpec comma methodInterfaceName |
     *           methodNameSpec comma methodInterfaceSpec comma methodParamsSpec
     * </pre>
     * 
     * <p>
     * The canonical form of each typeName must begin with the fully qualified Java name of the corresponding parameter's
     * type. The canonical form of a typeName for an array parameter is the fully qualified Java name of the array's
     * component type followed by as many instances of the string "[]" as there are dimensions to the array. No additional
     * characters (e.g. blanks) may occur in the canonical form.
     * 
     * <p>
     * A MethodInterfaceName is a non-empty String and should contain a method-intf value as defined for use in Jakarta 
     * Enterprise Beans deployment descriptors. An implementation must be flexible such that it supports additional interface 
     * names especially if they are standardized by the Jakarta Enterprise Beans Specification. The Jakarta Enterprise Beans 
     * Specification currently defines the following method-intf values:
     * 
     * <pre>
     * { "Home", "LocalHome", "Remote", "Local", "ServiceEndpoint" }
     * </pre>
     * 
     * @return a String containing the canonicalized actions of this EJBMethodPermission.
     */
    @Override
    public String getActions() {
        if (this.actions == null) {

            String iSpec = (this.methodInterface == -1 ? null : (this.methodInterface < 0 ? this.otherMethodInterface : interfaceKeys[this.methodInterface]));

            if (this.methodName == null) {
                if (iSpec == null) {
                    if (this.methodParams != null) {
                        this.actions = "," + this.methodParams;
                    }
                } else if (this.methodParams == null) {
                    this.actions = "," + iSpec;
                } else {
                    this.actions = "," + iSpec + this.methodParams;
                }
            } else if (iSpec == null) {
                if (this.methodParams == null) {
                    this.actions = this.methodName;
                } else {
                    this.actions = this.methodName + "," + this.methodParams;
                }
            } else if (this.methodParams == null) {
                this.actions = this.methodName + "," + iSpec;
            } else {
                this.actions = this.methodName + "," + iSpec + this.methodParams;
            }
        }

        return this.actions;
    }

    /**
     * Returns the hash code value for this EJBMethodPermission.
     * 
     * <p>
     * The properties of the returned hash code must be as follows:
     * 
     * <ul>
     * <li>During the lifetime of a Java application, the hashCode method must return the same integer value every time it
     * is called on a EJBMethodPermission object. The value returned by hashCode for a particular EJBMethodPermission need
     * not remain consistent from one execution of an application to another.
     * <li>If two EJBMethodPermission objects are equal according to the equals method, then calling the hashCode method on
     * each of the two Permission objects must produce the same integer result (within an application).
     * </ul>
     * 
     * @return the integer hash code value for this object.
     */
    @Override
    public int hashCode() {
        if (hashCodeValue == 0) {

            String hashInput;
            String actions = this.getActions();

            if (actions == null) {
                hashInput = this.getName();
            } else {
                hashInput = this.getName() + " " + actions;
            }

            hashCodeValue = hashInput.hashCode();
        }
        
        return this.hashCodeValue;
    }

    /**
     * Determines if the argument Permission is "implied by" this EJBMethodPermission. 
     * 
     * <p>
     * For this to be the case,
     * <ul>
     * <li>The argument must be an instanceof EJBMethodPermission
     * <li>with name equivalent to that of this EJBMethodPermission, and
     * <li>the methods to which the argument permission applies (as defined in its actions) must be a subset of the methods
     * to which this EJBMethodPermission applies (as defined in its actions).
     * </ul>
     * 
     * <p>
     * The argument permission applies to a subset of the methods to which this permission applies if all of the following
     * conditions are met.
     * <ul>
     * <li>the method name component of the methodNameSpec of this permission is null, the empty string, or equivalent to
     * the method name of the argument permission, and
     * <li>the method interface component of the methodNameSpec of this permission is null, the empty string, or equivalent
     * to the method interface of the argument permission, and
     * <li>the method parameter list component of the methodNameSpec of this permission is null, the empty string, or
     * equivalent to the method parameter list of the argument permission.
     * </ul>
     * 
     * <p>
     * The name and actions comparisons described above are case sensitive.
     * 
     * @param permission "this" EJBMethodPermission is checked to see if it implies the argument permission.
     * @return true if the specified permission is implied by this object, false if not.
     */
    @Override
    public boolean implies(Permission permission) {
        if (permission == null || !(permission instanceof EJBMethodPermission)) {
            return false;
        }

        EJBMethodPermission that = (EJBMethodPermission) permission;

        if (!this.getName().equals(that.getName())) {
            return false;
        }

        if (this.methodName != null && (that.methodName == null || !this.methodName.equals(that.methodName))) {
            return false;
        }

        if (this.methodInterface != -1 && (that.methodInterface == -1 || this.methodInterface != that.methodInterface)) {
            return false;
        }

        if (this.methodInterface == -2 && !this.otherMethodInterface.equals(that.otherMethodInterface)) {
            return false;
        }

        if (this.methodParams != null && (that.methodParams == null || !this.methodParams.equals(that.methodParams))) {
            return false;
        }

        return true;
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
        setMethodSpec((String) inputStream.readFields().get("actions", null));
    }

    /**
     * writeObject is used to establish the values of the serialized fields before they are written to the output stream and
     * need not be implemented if the values of the serialized fields are always available and up to date. The serialized
     * fields are written to the output stream in the same form as they would be written by defaultWriteObject.
     * 
     * @param outputStream The stream to which the serialized fields are written
     * 
     * @throws IOException If an I/O error occurs while writing to the underlying stream
     * 
     */
    private synchronized void writeObject(ObjectOutputStream outputStream) throws IOException {
        outputStream.putFields().put("actions", this.getActions());
        outputStream.writeFields();
    }

    private void setMethodSpec(String actions) {

        String mInterface = null;

        this.methodName = null;
        this.methodParams = null;

        if (actions != null) {

            if (actions.length() > 0) {

                int i = actions.indexOf(',');
                if (i < 0) {
                    this.methodName = actions;
                } else if (i >= 0) {

                    if (i != 0) {
                        this.methodName = actions.substring(0, i);
                    }

                    if (actions.length() == i + 1) {
                        throw new IllegalArgumentException("illegal actions spec");
                    }

                    int j = actions.substring(i + 1).indexOf(',');
                    if (j < 0) {
                        mInterface = actions.substring(i + 1);
                    } else {
                        if (j > 0) {
                            mInterface = actions.substring(i + 1, i + j + 1);
                        }
                        this.methodParams = actions.substring(i + j + 1);

                        if (this.methodParams.length() > 1 && this.methodParams.endsWith(",")) {
                            throw new IllegalArgumentException("illegal methodParam");
                        }
                    }
                }
            } else {
                // canonical form of emptystring actions is null
                actions = null;
            }
        }

        this.methodInterface = validateInterface(mInterface);

        if (this.methodInterface < -1) {
            this.otherMethodInterface = mInterface;
        }

        this.actions = actions;
    }

    private void setMethodSpec(String methodName, String mInterface, String[] methodParams) {
        if (methodName != null && methodName.indexOf(',') >= 0) {
            throw new IllegalArgumentException("illegal methodName");
        }

        this.methodInterface = validateInterface(mInterface);

        if (this.methodInterface < -1) {
            this.otherMethodInterface = mInterface;
        }

        if (methodParams != null) {

            StringBuffer mParams = new StringBuffer(",");

            for (int i = 0; i < methodParams.length; i++) {
                if (methodParams[i] == null || methodParams[i].indexOf(',') >= 0) {
                    throw new IllegalArgumentException("illegal methodParam");
                }
                if (i == 0) {
                    mParams.append(methodParams[i]);
                } else {
                    mParams.append("," + methodParams[i]);
                }
            }
            this.methodParams = mParams.toString();
        } else {
            this.methodParams = null;
        }

        this.methodName = methodName;
    }

    private void setMethodSpec(String mInterface, Method method) {
        this.methodInterface = validateInterface(mInterface);

        if (this.methodInterface < -1) {
            this.otherMethodInterface = mInterface;
        }

        this.methodName = method.getName();

        Class<?>[] params = method.getParameterTypes();

        StringBuffer methodParameters = new StringBuffer(",");

        for (int i = 0; i < params.length; i++) {

            String parameterName = params[i].getName();
            Class<?> componentType = params[i].getComponentType();

            // Canonicalize parameter if it is an Array.
            if (componentType != null) {
                String brackets = "[]";
                while (componentType.getComponentType() != null) {
                    componentType = componentType.getComponentType();
                    brackets = brackets + "[]";
                }
                parameterName = componentType.getName() + brackets;
            }

            if (i == 0) {
                methodParameters.append(parameterName);
            } else {
                methodParameters.append("," + parameterName);
            }
        }

        this.methodParams = methodParameters.toString();
    }

    private static int validateInterface(String methodInterface) {
        int result = -1;
        if (methodInterface != null && methodInterface.length() > 0) {
            Integer i = (Integer) interfaceHash.get(methodInterface);
            if (i != null) {
                result = i.intValue();
            } else {
                result = -2;
            }
        }
        
        return result;
    }

}
