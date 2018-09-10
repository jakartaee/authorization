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

import java.util.Arrays;

/**
 * This class extends the URLPattern class and is used to represent URLPatternSpec objects. URLPatternSpec objects occur
 * within WebResourcePermission and WebUserDataPermission objects.
 * 
 * <P>
 *
 * @author Ron Monzillo
 * @author Gary Ellison
 */

class URLPatternSpec extends URLPattern {

	private static String EMPTY_STRING = "";

	private transient int hashCodeValue = 0;

	private String canonicalSpec = null;

	private final String urlPatternList;

	private URLPattern[] urlPatternArray = null;

	/**
	 * Creates a new URLPatternSpec that identifies the web resources to which a WebResourcePermission or
	 * WebUserDataPermission applies. The syntax of the name parameter is as follows:
	 * <P>
	 * 
	 * <Pre>
	 *
	 *          URLPatternList ::= URLPattern | URLPatternList colon URLPattern
	 *
	 *          URLPatternSpec ::= URLPattern | URLPattern colon URLPatternList
	 *
	 *          name ::= URLPatternSpec
	 * </Pre>
	 * <P>
	 * The first URLPattern in a URLPatternSpec may be any of the pattern types, exact, path-prefix, extension, or default
	 * as defined in the <i>Java Servlet Specification)</i>. When a URLPatternSpec includes a URLPatternList, the patterns
	 * of the URLPatternList identify the resources to which the permission does NOT apply and depend on the pattern type
	 * and value of the first pattern as follows:
	 * <p>
	 * <ul>
	 * <li>No pattern may exist in the URLPatternList that matches the first pattern.
	 * <li>If the first pattern is a path-prefix pattern, only exact patterns matched by the first pattern and path-prefix
	 * patterns matched by, but different from, the first pattern may occur in the URLPatternList.
	 * <li>If the first pattern is an extension pattern, only exact patterns that are matched by the first pattern and
	 * path-prefix patterns may occur in the URLPatternList.
	 * <li>If the first pattern is the default pattern, "/", any pattern except the default pattern may occur in the
	 * URLPatternList.
	 * <li>If the first pattern is an exact pattern a URLPatternList must not be present in the URLPatternSpec.
	 * </ul>
	 * <P>
	 * 
	 * @param urlPatternSpec a String containing a URLPatternSpec that identifies the application specific web resources to
	 * which the permission pertains. All URLPatterns in the URLPatternSpec are relative to the context path of the deployed
	 * web application module, and the same URLPattern must not occur more than once in a URLPatternSpec.
	 */

	public URLPatternSpec(String urlPatternSpec) {
		super(getFirstPattern(urlPatternSpec));
		int colon = urlPatternSpec.indexOf(":");
		if (colon >= 0) {
			urlPatternList = urlPatternSpec.substring(colon + 1);
			setURLPatternArray();
		} else
			urlPatternList = null;
	}

	/**
	 * This method returns a String containing the first URLPattern in this URLPatternSpec.
	 */

	public String getURLPattern() {
		return super.toString();
	}

	/*
	 * Checks two URLPatternSpec objects for equality. A reference URLPatternSpec is equivalent to an argument
	 * URLPatternSpec if their first patterns are equivalent, and the patterns of its URLPatternList collectively match
	 * exactly the same set of patterns as are matched by the patterns of the URLPatternList of the argument URLPatternSpec.
	 */
	public boolean equals(Object o) {
		if (o == null || !(o instanceof URLPatternSpec))
			return false;

		URLPatternSpec that = (URLPatternSpec) o;

		return this.toString().equals(that.toString());
	}

	/**
	 * Returns the hash code value for this URLPatternSpec properties of the returned hash code must be as follows:
	 * <p>
	 * <ul>
	 * <li>During the lifetime of a Java application, the hashCode method must return the same integer value, every time it
	 * is called on a URLPatternSpec object. The value returned by hashCode for a particular URlPatternSpec need not remain
	 * consistent from one execution of an application to another.
	 * <li>If two URLPatternSpec objects are equal according to the equals method, then calling the hashCode method on each
	 * of the two objects must produce the same integer result (within an application).
	 * </ul>
	 * <P>
	 * 
	 * @return the integer hash code value for this object.
	 */

	public int hashCode() {
		if (hashCodeValue == 0)
			hashCodeValue = this.toString().hashCode();

		return hashCodeValue;
	}

	/**
	 * Determines if the argument URLPatternSpec is "implied by" this URLPatternSpec. For this to be the case, all of the
	 * following must be true:
	 * <p>
	 * <ul>
	 * <li>The argument is an instanceof URLPatternSpec, and
	 * <li>The first Pattern in the argument URLPatternSpec is matched by the first URLPattern of this URLPatternSpec.
	 * <li>The first Pattern in the argument URLPatternSpec is NOT matched by any URLPattern in the URLPatternList of this
	 * URLPatternSpec.
	 * <li>If the first Pattern in the argument URLPatternSpec matches the first Pattern in this URLPatternSpec, then every
	 * URLPattern in the URLPatternList of this URLPatternSpec is matched by a URLPattern in the URLPatternList of the
	 * argument URLPatternSpec.
	 * </ul>
	 * <P>
	 * URLPattern matching is performed using the <i>Servlet matching rules</i> where two URL patterns match if they are
	 * related as follows:
	 * <p>
	 * <ul>
	 * <li>their pattern values are String equivalent, or
	 * <li>this pattern is the path-prefix pattern "/*", or
	 * <li>this pattern is a path-prefix pattern (that is, it starts with "/" and ends with "/*") and the argument pattern
	 * starts with the substring of this pattern, minus its last 2 characters, and the next character of the argument
	 * pattern, if there is one, is "/", or
	 * <li>this pattern is an extension pattern (that is, it starts with "*.") and the argument pattern ends with this
	 * pattern, or
	 * <li>the reference pattern is the special default pattern, "/", which matches all argument patterns.
	 * </ul>
	 * <P>
	 * All of the comparisons described above are case sensitive.
	 * <P>
	 * 
	 * @param that "this" URLPatternSpec is checked to see if it implies the argument URLPatternSpec.
	 * <P>
	 * @return true if the specified URLPatternSpec is implied by this URLPatternSpec, false if not.
	 */

	public boolean implies(URLPatternSpec that) {
		if (that == null)
			return false;

		if (!super.implies(that))
			return false;

		for (int i = 0; urlPatternArray != null && i < urlPatternArray.length; i++)

			if (urlPatternArray[i] != null && urlPatternArray[i].implies(that))
				return false;

		if (urlPatternArray != null && ((URLPattern) that).implies(this)) {

			if (that.urlPatternArray == null)
				return false;

			boolean flags[] = new boolean[urlPatternArray.length];

			for (int i = 0; i < flags.length; i++)
				flags[i] = false;

			int count = 0;

			for (int j = 0; j < that.urlPatternArray.length; j++) {

				for (int i = 0; i < flags.length; i++) {

					if (!flags[i])
						if (urlPatternArray[i] == null || (that.urlPatternArray[j] != null && that.urlPatternArray[j].implies(urlPatternArray[i]))) {

							count += 1;
							flags[i] = true;
							if (count == flags.length)
								return true;
						}
				}
			}

			return (count == flags.length);
		}

		return true;
	}

	/*
	 * This method returns a canonical String representation of the URLPatternSpec. By this time, the patterns have already
	 * been sorted, and pruned by setURLPatternArray, such that all this method has to do is glue them together into a
	 * string.
	 */

	public String toString() {
		if (canonicalSpec == null) {

			if (urlPatternList == null)
				canonicalSpec = super.toString();

			else {

				StringBuffer s = null;

				for (int i = 0; i < urlPatternArray.length; i++) {
					if (urlPatternArray[i] != null) {
						if (s == null)
							s = new StringBuffer(urlPatternArray[i].toString());
						else
							s.append(":" + urlPatternArray[i].toString());
					}
				}

				if (s == null)
					canonicalSpec = super.toString();
				else
					canonicalSpec = super.toString() + ":" + s.toString();
			}
		}

		return canonicalSpec;
	}

	// ----------------- Private Methods ---------------------

	private static String getFirstPattern(String urlPatternSpec) {
		if (urlPatternSpec == null)
			throw new IllegalArgumentException("Invalid URLPatternSpec");
		int colon = urlPatternSpec.indexOf(":");
		if (colon < 0)
			return urlPatternSpec;
		else if (colon > 0)
			return urlPatternSpec.substring(0, colon);
		else if (colon == 0)
			return EMPTY_STRING;
		throw new IllegalArgumentException("Invalid URLPatternSpec");
	}

	private void setURLPatternArray() {
		if (urlPatternArray == null && urlPatternList != null) {

			String[] tokens = urlPatternList.split(":", -1);

			int count = tokens.length;

			if (count == 0)
				throw new IllegalArgumentException("colon followed by empty URLPatternList");
			urlPatternArray = new URLPattern[count];

			int firstType = this.patternType();

			for (int i = 0; i < count; i++) {

				urlPatternArray[i] = new URLPattern(tokens[i]);

				if (urlPatternArray[i].implies(this))
					throw new IllegalArgumentException("pattern in URLPatternList implies first pattern");

				switch (firstType) {
				case URLPattern.PT_PREFIX:
				case URLPattern.PT_EXTENSION:
					switch (urlPatternArray[i].patternType()) {
					case URLPattern.PT_PREFIX:
						if (firstType == URLPattern.PT_PREFIX) {
							if (super.equals(urlPatternArray[i]) || !super.implies(urlPatternArray[i]))
								throw new IllegalArgumentException("Invalid prefix pattern in URLPatternList");
						}
						break;
					case URLPattern.PT_EXACT:
						if (!super.implies(urlPatternArray[i]))
							throw new IllegalArgumentException("Invalid exact pattern in URLPatternList");
						break;
					default:
						throw new IllegalArgumentException("Invalid pattern type in URLPatternList");
					}
				case URLPattern.PT_DEFAULT:
					if (super.equals(urlPatternArray[i]))
						throw new IllegalArgumentException("Invalid default pattern in URLPatternList");
					break;
				case URLPattern.PT_EXACT:
					throw new IllegalArgumentException("invalid URLPatternSpec");
				default:
					throw new IllegalArgumentException("Invalid pattern type in URLPatternList");
				}
			}

			Arrays.sort(urlPatternArray);

			for (int i = 0; i < urlPatternArray.length; i++) {
				if (urlPatternArray[i] != null) {
					switch (urlPatternArray[i].patternType()) {
					case URLPattern.PT_PREFIX:
						for (int j = i + 1; j < urlPatternArray.length; j++)
							if (urlPatternArray[i].implies(urlPatternArray[j]))
								urlPatternArray[j] = null;
						break;
					default:
						break;
					}
				}
			}
		}
	}

}
