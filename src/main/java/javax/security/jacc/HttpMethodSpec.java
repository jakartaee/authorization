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

import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/**
 * This class is used ...
 * <P>
 *
 * @author Ron Monzillo
 * @author Gary Ellison
 */
final class HttpMethodSpec {

    private static final String comma = ",";
    private static final String emptyString = "";
    private static final String exclaimationPoint = "!";
    private static final char exclaimationPointChar = '!';

    private static String methodKeys[] = { "DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT", "TRACE" };
    private static int mapSize = methodKeys.length;

    private static HashMap<String, Integer> methodHash = new HashMap<String, Integer>();
    static {
        int b = 1;
        for (int i = 0; i < mapSize; i++) {
            methodHash.put(methodKeys[i], b);
            b = b << 1;
        }
    }

    private static int allSet;
    static {
        allSet = 0;
        for (int i = 0; i < mapSize; i++) {
            allSet = allSet << 1;
            allSet += 1;
        }
    }

    private static HttpMethodSpec specArray[] = new HttpMethodSpec[allSet + 1];
    static {
        for (int i = 0; i < allSet + 1; i++) {
            specArray[i] = new HttpMethodSpec(false, i);
        }
    }

    private static HttpMethodSpec exceptionSpecArray[] = new HttpMethodSpec[allSet + 1];
    static {
        for (int i = 0; i < allSet + 1; i++) {
            exceptionSpecArray[i] = new HttpMethodSpec(true, i);
        }
    }

    private static HttpMethodSpec allSpec = new HttpMethodSpec(false, 0);
    private static List<String> extensionMethods = new ArrayList<String>();

    HttpMethodSpec standardSpec;
    boolean exceptionList;
    int standardMap;
    BitSet extensionSet;
    String actions;

    static HttpMethodSpec getSpec(String actions) {
        HttpMethodSpec spec;

        if (actions == null || actions.equals(emptyString)) {
            spec = allSpec;
        } else {

            BitSet set = new BitSet();
            spec = getStandardSpec(actions, set);

            if (!set.isEmpty()) {
                spec = new HttpMethodSpec(spec, set);
            }
        }
        
        return spec;
    }

    static HttpMethodSpec getSpec(String[] methods) {
        HttpMethodSpec spec;

        if (methods == null || methods.length == 0) {
            spec = allSpec;
        } else {

            int map = 0;
            BitSet set = new BitSet();

            for (int i = 0; i < methods.length; i++) {
                Integer bit = (Integer) methodHash.get(methods[i]);
                if (bit != null) {
                    map |= bit.intValue();
                } else {
                    setExtensionBit(methods[i], set);
                }
            }

            if (set.isEmpty()) {
                spec = specArray[map];
            } else {
                spec = new HttpMethodSpec(specArray[map], set);
            }
        }
        
        return spec;
    }
    
    
    // ### Package level methods

    String getActions() {
        if (standardMap == 0 && extensionSet == null) {
            return null;
        }

        synchronized (this) {
            if (actions != null) {
                return actions;
            }

            if (standardSpec != null) {
                actions = getExtensionActions(standardSpec.getActions(), standardMap, extensionSet);
            } else {
                actions = getStandardActions(exceptionList, standardMap);
            }
        }

        return actions;
    }

    boolean implies(HttpMethodSpec that) {
        boolean doesImplies;
        
        if (this.standardMap == 0 && this.extensionSet == null) {
            
            // Null actions implies everything
            
            doesImplies = true;
        } else if (that.standardMap == 0 && that.extensionSet == null) {
            
            // Only the null actions can imply the null actions
            
            doesImplies = false;
        } else if (this.exceptionList && that.exceptionList) {
            
            // Both are an HttpMethodExceptionList
            
            doesImplies = (this.standardMap & that.standardMap) == this.standardMap;
            if (doesImplies) {
                if (this.extensionSet != null) {
                    if (that.extensionSet == null) {
                        doesImplies = false;
                    } else {
                        BitSet clone = (BitSet) that.extensionSet.clone();
                        clone.and(this.extensionSet);
                        doesImplies = clone.equals(this.extensionSet) ? true : false;
                    }
                }
            }
        } else if (this.exceptionList == that.exceptionList) {
            
            // Neither is an HttpMethodExceptionList
            
            doesImplies = (this.standardMap & that.standardMap) == that.standardMap;
            if (doesImplies) {
                if (that.extensionSet != null) {
                    if (this.extensionSet == null) {
                        doesImplies = false;
                    } else {
                        BitSet clone = (BitSet) that.extensionSet.clone();
                        clone.and(this.extensionSet);
                        doesImplies = clone.equals(that.extensionSet);
                    }
                }
            }
        } else if (this.exceptionList) {
            
            // One or the other is an HttpMethodExceptionList
            
            doesImplies = (this.standardMap & that.standardMap) == 0;
            if (doesImplies) {
                if (that.extensionSet != null) {
                    if (this.extensionSet == null) {
                        doesImplies = true;
                    } else {
                        doesImplies = this.extensionSet.intersects(that.extensionSet) ? false : true;
                    }
                }
            }
        } else {
            
            // An explicit list can never imply an exception list
            
            doesImplies = false;
        }

        return doesImplies;
    }
    
    @Override
    public String toString() {
        return getActions();
    }

    @Override
    public int hashCode() {
        return (this.exceptionList ? 1 : 0) + (this.standardMap << 1) + ((this.extensionSet == null ? 0 : this.extensionSet.hashCode()) << mapSize + 1);
    }

    @Override
    public boolean equals(Object that) {
        boolean isEqual = false;
        
        if (that != null && that instanceof HttpMethodSpec) {
            if (that == this) {
                isEqual = true;
            } else {
                isEqual = this.hashCode() == ((HttpMethodSpec) that).hashCode();
            }
        }
        
        return isEqual;
    }
    

    // beginning of private methods

    private HttpMethodSpec(boolean isExceptionList, int map) {
        standardSpec = null;
        exceptionList = isExceptionList;
        standardMap = map;
        extensionSet = null;
        actions = null;
    }

    private HttpMethodSpec(HttpMethodSpec spec, BitSet set) {
        standardSpec = spec;
        exceptionList = spec.exceptionList;
        standardMap = spec.standardMap;
        extensionSet = set.isEmpty() ? null : set;
        actions = null;
    }

    private static void setExtensionBit(String method, BitSet set) {
        int bitPos;
        synchronized (extensionMethods) {
            bitPos = extensionMethods.indexOf(method);
            if (bitPos < 0) {
                bitPos = extensionMethods.size();
                // *** should ensure method is syntactically legal
                extensionMethods.add(method);
            }
        }
        set.set(bitPos);
    }

    private static String getExtensionMethod(int bitPos) {
        synchronized (extensionMethods) {
            if (bitPos >= 0 && bitPos < extensionMethods.size()) {
                return (String) extensionMethods.get(bitPos);
            } else {
                throw new RuntimeException("invalid (extensionMethods) bit position: '" + bitPos + "' size: '" + extensionMethods.size() + " '");
            }
        }
    }

    private static HttpMethodSpec getStandardSpec(String actions, BitSet set) {
        boolean isExceptionList = false;
        
        if (actions.charAt(0) == exclaimationPointChar) {
            isExceptionList = true;
            if (actions.length() < 2) {
                throw new IllegalArgumentException("illegal HTTP method Spec actions: '" + actions + "'");
            }
            actions = actions.substring(1);
        }

        int map = makeMethodSet(actions, set);

        if (isExceptionList) {
            return exceptionSpecArray[map];
        }
        
        return specArray[map];
    }

    private static int makeMethodSet(String actions, BitSet set) {
        int i = 0;
        int mSet = 0;
        int commaPos = 0;

        while (commaPos >= 0 && i < actions.length()) {

            commaPos = actions.indexOf(comma, i);

            if (commaPos != 0) {

                String method;
                if (commaPos < 0) {
                    method = actions.substring(i);
                } else {
                    method = actions.substring(i, commaPos);
                }
                Integer bit = (Integer) methodHash.get(method);
                if (bit != null) {
                    mSet |= bit.intValue();
                } else {
                    setExtensionBit(method, set);
                }

                i = commaPos + 1;
            }

            else {
                throw new IllegalArgumentException("illegal HTTP method Spec actions: '" + actions + "'");
            }
        }

        return mSet;
    }

    private String getExtensionActions(String standardActions, int map, BitSet set) {
        List<String> methods = null;
        for (int i = set.nextSetBit(0); i >= 0; i = set.nextSetBit(i + 1)) {
            if (methods == null) {
                methods = new ArrayList<String>();
            }
            methods.add(getExtensionMethod(i));
        }
        
        if (methods == null) {
            return standardActions;
        }
        
        Collections.sort(methods);
        StringBuffer actions = new StringBuffer(standardActions == null ? (exceptionList ? exclaimationPoint : emptyString) : standardActions);
        for (int i = 0; i < methods.size(); i++) {
            if (i > 0 || map > 0) {
                actions.append(comma);
            }
            actions.append(methods.get(i));
        }
        
        return actions.toString();
    }

    private String getStandardActions(boolean isExceptionList, int map) {
        int bitValue = 1;

        StringBuffer actBuf = null;

        for (int i = 0; i < mapSize; i++) {

            if ((map & bitValue) == bitValue) {
                if (actBuf == null) {
                    actBuf = new StringBuffer(isExceptionList ? exclaimationPoint : emptyString);
                } else {
                    actBuf.append(comma);
                }
                actBuf.append((String) methodKeys[i]);
            }
            bitValue = bitValue * 2;
        }

        if (actBuf == null) {
            return isExceptionList ? exclaimationPoint : emptyString;
        }
        
        return actBuf.toString();
    }

}
