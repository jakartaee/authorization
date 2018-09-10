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

	private static Object methodKeys[] = { "DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT", "TRACE" };

	private static int mapSize = methodKeys.length;

	private static HashMap methodHash = new HashMap();
	static {
		int b = 1;
		for (int i = 0; i < mapSize; i++) {
			methodHash.put(methodKeys[i], Integer.valueOf(b));
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

	private static ArrayList extensionMethods = new ArrayList();

	HttpMethodSpec standardSpec;

	boolean exceptionList;
	int standardMap;
	BitSet extensionSet;
	String actions;

	static HttpMethodSpec getSpec(String actions) {
		HttpMethodSpec rvalue;

		if (actions == null || actions.equals(emptyString)) {
			rvalue = allSpec;
		} else {

			BitSet set = new BitSet();
			rvalue = getStandardSpec(actions, set);

			if (!set.isEmpty()) {
				rvalue = new HttpMethodSpec(rvalue, set);
			}
		}
		return rvalue;
	}

	static HttpMethodSpec getSpec(String[] methods) {
		HttpMethodSpec rvalue;

		if (methods == null || methods.length == 0) {
			rvalue = allSpec;
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
				rvalue = specArray[map];
			} else {
				rvalue = new HttpMethodSpec(specArray[map], set);
			}
		}
		return rvalue;
	}

	@Override
	public String toString() {
		return getActions();
	}

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

	@Override
	public int hashCode() {
		return (this.exceptionList ? 1 : 0) + (this.standardMap << 1) + ((this.extensionSet == null ? 0 : this.extensionSet.hashCode()) << mapSize + 1);
	}

	@Override
	public boolean equals(Object that) {
		boolean rvalue = false;
		if (that != null && that instanceof HttpMethodSpec) {
			if (that == this) {
				rvalue = true;
			} else {
				rvalue = this.hashCode() == ((HttpMethodSpec) that).hashCode();
			}
		}
		return rvalue;
	}

	boolean implies(HttpMethodSpec that) {
		boolean rvalue;
		// null actions implies everything
		if (this.standardMap == 0 && this.extensionSet == null) {
			rvalue = true;
		}
		// only the null actions can implie the null actions
		else if (that.standardMap == 0 && that.extensionSet == null) {
			rvalue = false;
		}
		// both are an HttpMethodExceptionList
		else if (this.exceptionList && that.exceptionList) {
			rvalue = (this.standardMap & that.standardMap) == this.standardMap;
			if (rvalue) {
				if (this.extensionSet != null) {
					if (that.extensionSet == null) {
						rvalue = false;
					} else {
						BitSet clone = (BitSet) that.extensionSet.clone();
						clone.and(this.extensionSet);
						rvalue = clone.equals(this.extensionSet) ? true : false;
					}
				}
			}
		}
		// neither is an HttpMethodExceptionList
		else if (this.exceptionList == that.exceptionList) {
			rvalue = (this.standardMap & that.standardMap) == that.standardMap;
			if (rvalue) {
				if (that.extensionSet != null) {
					if (this.extensionSet == null) {
						rvalue = false;
					} else {
						BitSet clone = (BitSet) that.extensionSet.clone();
						clone.and(this.extensionSet);
						rvalue = clone.equals(that.extensionSet);
					}
				}
			}
		}
		// one or the other is an HttpMethodExceptionList
		else if (this.exceptionList) {
			rvalue = (this.standardMap & that.standardMap) == 0;
			if (rvalue) {
				if (that.extensionSet != null) {
					if (this.extensionSet == null) {
						rvalue = true;
					} else {
						rvalue = this.extensionSet.intersects(that.extensionSet) ? false : true;
					}
				}
			}
		}
		// an explicit list can never imply an exception list
		else {
			rvalue = false;
		}

		return rvalue;
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

		HttpMethodSpec rvalue;
		if (isExceptionList) {
			rvalue = exceptionSpecArray[map];
		} else {
			rvalue = specArray[map];
		}

		return rvalue;
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
		ArrayList methods = null;
		for (int i = set.nextSetBit(0); i >= 0; i = set.nextSetBit(i + 1)) {
			if (methods == null) {
				methods = new ArrayList();
			}
			methods.add(getExtensionMethod(i));
		}
		String rvalue;
		if (methods == null) {
			rvalue = standardActions;
		} else {
			Collections.sort(methods);
			StringBuffer actBuf = new StringBuffer(standardActions == null ? (exceptionList ? exclaimationPoint : emptyString) : standardActions);
			for (int i = 0; i < methods.size(); i++) {
				if (i > 0 || map > 0) {
					actBuf.append(comma);
				}
				actBuf.append(methods.get(i));
			}
			rvalue = actBuf.toString();
		}
		return rvalue;
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
		} else {
			return actBuf.toString();
		}
	}

}
