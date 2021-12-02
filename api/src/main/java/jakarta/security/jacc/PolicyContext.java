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

import java.security.SecurityPermission;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This utility class is used by containers to communicate policy context identifiers and other policy relevant context
 * to <code>Policy</code> providers. <code>Policy</code> providers use the policy context identifier to select the
 * subset of policy to apply in access decisions.
 * 
 * <p>
 * The value of a policy context identifier is a <code>
 * String</code> and each thread has an independently established policy context identifier. A container will establish
 * the thread-scoped value of a policy context identifier by calling the static <code>setContextID</code> method. The
 * value of a thread-scoped policy context identifier is available (to <code>Policy</code>) by calling the static
 * <code>getContextID</code> method.
 * 
 * <p>
 * This class is also used by <code>Policy</code> providers to request additional thread-scoped policy relevant context
 * objects from the calling container. Containers register container-specific <code>PolicyContext</code> handlers using
 * the static <code>registerHandler</code> method. Handler registration is scoped to the class, such that the same
 * handler registrations are active in all thread contexts. Containers may use the static method
 * <code>setHandlerData</code> to establish a thread-scoped parameter that will be passed to handlers when they are
 * activated by <code>Policy</code> providers. The static <code>getContext</code> method is used to activate a handler
 * and obtain the corresponding context object.
 * 
 * <p>
 * The static accessor functions provided by this class allow per-thread policy context values to be established and
 * communicated independent of a common reference to a particular PolicyContext instance.
 * 
 * <p>
 * The PolicyContext class may encapsulate static ThreadLocal instance variables to represent the policy context
 * identifier and handler data values.
 * 
 * <p>
 * The Application server must bundle or install the PolicyContext class, and the containers of the application server
 * must prevent the methods of the PolicyContext class from being called from calling contexts that are not authorized
 * to call these methods. With the exception of the getContextID and GetHandlerKeys methods, containers must restrict
 * and afford access to the methods of the PolicyContext class to calling contexts trusted by the container to perform
 * container access decisions. The PolicyContext class may satisfy this requirement (on behalf of its container) by
 * rejecting calls made from an AccessControlContext that has not been granted the "setPolicy" SecurityPermission, and
 * by ensuring that Policy providers used to perform container access decisions are granted the "setPolicy" permission.
 *
 * @see PolicyContextHandler
 *
 * @author Ron Monzillo
 * @author Gary Ellison
 */
public final class PolicyContext {

    private PolicyContext() {
    }

    /**
     * This static instance variable contains the policy context identifier value. It's initial value is null.
     */
    private static ThreadLocal<String> threadLocalContextID = new ThreadLocal<String>();

    /**
     * This static instance variable contains the handler parameter data object. It's initial value is null.
     */
    private static ThreadLocal<Object> threadLocalHandlerData = new ThreadLocal<Object>();

    /**
     * This static instance variable contains the mapping of container registered <code>PolicyContextHandler</code> objects
     * with the keys that identify the context objects returned by the handlers.
     */
    private static Map<String, PolicyContextHandler> handlerTable = new ConcurrentHashMap<String, PolicyContextHandler>();

    /**
     * Authorization protected method used to modify the value of the policy context identifier associated with the thread
     * on which this method is called.
     * 
     * @param contextID a <code>String</code> that represents the value of the policy context identifier to be assigned to
     * the PolicyContext for the calling thread. The value <code>null
     * </code> is a legitimate value for this parameter.
     *
     * @throws SecurityException if the calling AccessControlContext is not authorized by the container to call
     * this method.
     */
    public static void setContextID(String contextID) {
        checkSetPolicyPermission();

        threadLocalContextID.set(contextID);
    }

    /**
     * This static method returns the value of the policy context identifier associated with the thread on which the
     * accessor is called.
     * 
     * @return The <code>String</code> (or <code>null</code>) policy context identifier established for the thread. This
     * method must return the default policy context identifier, <code>null</code>, if the policy context identifier of the
     * thread has not been set via <code>setContext</code> to another value.
     *
     * @throws SecurityException if the calling AccessControlContext is not authorized by the container to call
     * this method. Containers may choose to authorize calls to this method by any AccessControlContext.
     */
    public static String getContextID() {
        return threadLocalContextID.get();
    }

    /**
     * Authorization protected method that may be used to associate a thread-scoped handler data object with the
     * PolicyContext. The handler data object will be made available to handlers, where it can serve to supply or bind the
     * handler to invocation scoped state within the container.
     * 
     * @param data a container-specific object that will be associated with the calling thread and passed to any handler
     * activated by a <code>Policy</code> provider (on the thread). The value <code>null</code> is a legitimate value for
     * this parameter, and is the value that will be used in the activation of handlers if the <code>setHandlerData</code>
     * has not been called on the thread.
     *
     * @throws SecurityException if the calling AccessControlContext is not authorized by the container to call
     * this method.
     */
    public static void setHandlerData(Object data) {
        checkSetPolicyPermission();

        threadLocalHandlerData.set(data);
    }

    /**
     * Authorization protected method used to register a container specific <code>PolicyContext</code> handler. A handler
     * may be registered to handle multiple keys, but at any time, at most one handler may be registered for a key.
     * 
     * @param key a (case-sensitive) <code>String</code> that identifies the context object handled by the handler. The
     * value of this parameter must not be null.
     * @param handler an object that implements the <code>PolicyContextHandler</code> interface. The value of this parameter
     * must not be null.
     * @param replace this boolean value defines the behavior of this method if, when it is called, a
     * <code>PolicyContextHandler</code> has already been registered to handle the same key. In that case, and if the value
     * of this argument is <code>true</code>, the existing handler is replaced with the argument handler. If the value of
     * this parameter is false the existing registration is preserved and an exception is thrown.
     *
     * @throws IllegalArgumentException if the value of either of the handler or key arguments is null, or the
     * value of the replace argument is <code>false</code> and a handler with the same key as the argument handler is
     * already registered.
     *
     * @throws SecurityException if the calling AccessControlContext is not authorized by the container to call
     * this method.
     *
     * @throws PolicyContextException if an operation by this method on the argument
     * PolicyContextHandler causes it to throw a checked exception that is not accounted for in the signature of this
     * method.
     */
    public static void registerHandler(String key, PolicyContextHandler handler, boolean replace) throws PolicyContextException {
        if (handler == null || key == null) {
            throw new IllegalArgumentException("invalid (null) key or handler");
        }
        
        if (!handler.supports(key)) {
            throw new IllegalArgumentException("handler does not support key");
        }
        
        checkSetPolicyPermission();

        if (handlerTable.containsKey(key) && replace == false) {
            throw new IllegalArgumentException("handler exists");
        }
        
        handlerTable.put(key, handler);
    }

    /**
     * This method may be used to obtain the keys that identify the container specific context handlers registered by the
     * container.
     *
     * @return A <code>Set</code>, the elements of which, are the <code>String</code> key values that identify the handlers
     * that have been registered and therefore may be activated on the <code>PolicyContext</code>.
     *
     * @throws SecurityException if the calling AccessControlContext is not authorized by the container to call
     * this method. Containers may choose to authorize calls to this method by any AccessControlContext.
     */
    public static Set getHandlerKeys() {
        return handlerTable.keySet();
    }

    /**
     * This method may be used by a <code>Policy</code> provider to activate the <code>PolicyContextHandler</code>
     * registered to the context object key and cause it to return the corresponding policy context object from the
     * container. When this method activates a handler, it passes to the handler the context object key and the handler data
     * associated with the calling thread.
     *
     * @param key a <code>String</code> that identifies the <code>PolicyContextHandler</code> to activate and the context
     * object to be acquired from the handler. The value of this parameter must not be null.
     * @return the container and handler specific object containing the desired context. A <code>null</code> value is
     * returned if the corresponding handler has been registered, and the value of the corresponding context is null.
     *
     * @throws IllegalArgumentException if a <code>PolicyContextHandler</code> has not been registered for the key
     * or the registered handler no longer supports the key.
     *
     * @throws SecurityException if the calling AccessControlContext is not authorized by the container to call
     * this method.
     *
     * @throws PolicyContextException if an operation by this method on the identified
     * PolicyContextHandler causes it to throw a checked exception that is not accounted for in the signature of this
     * method.
     */
    public static Object getContext(String key) throws PolicyContextException {
        if (key == null) {
            throw new IllegalArgumentException("invalid key");
        }
        
        PolicyContextHandler handler = handlerTable.get(key);
        if (handler == null || !handler.supports(key)) {
            throw new IllegalArgumentException("unknown handler key");
        }

        checkSetPolicyPermission();

        return handler.getContext(key, threadLocalHandlerData.get());
    }
    
    
    // ### Private methods
    
    private static void checkSetPolicyPermission() {
         SecurityManager securityManager = System.getSecurityManager();
         if (securityManager != null) {
             securityManager.checkPermission(new SecurityPermission("setPolicy"));
         }
    }

}
