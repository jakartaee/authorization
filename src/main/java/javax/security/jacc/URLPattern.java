/*
 * Copyright (c) 1997-2018 Oracle and/or its affiliates. All rights reserved.
 * Copyright 2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package javax.security.jacc;

/**
 *
 * @see
 *
 * @author Ron Monzillo
 *
 * @serial exclude
 */
class URLPattern extends Object implements Comparable {

	private static String DEFAULT_PATTERN = "/";

	private int patternType = -1;

	private final String pattern;

	public URLPattern() {
		this.pattern = DEFAULT_PATTERN;
		this.patternType = PT_DEFAULT;
	}

	// note tht the EMPTY_STRING is legitimte URL_PATTERN
	public URLPattern(String p) {
		if (p == null) {
			this.pattern = DEFAULT_PATTERN;
			this.patternType = PT_DEFAULT;
		} else
			this.pattern = p;
	}

	/* changed to order default pattern / below extension */
	public static final int PT_DEFAULT = 0;
	public static final int PT_EXTENSION = 1;
	public static final int PT_PREFIX = 2;
	public static final int PT_EXACT = 3;

	public int patternType() {
		if (this.patternType < 0) {
			if (this.pattern.startsWith("*."))
				this.patternType = PT_EXTENSION;
			else if (this.pattern.startsWith("/") && this.pattern.endsWith("/*"))
				this.patternType = PT_PREFIX;
			else if (this.pattern.equals(DEFAULT_PATTERN))
				this.patternType = PT_DEFAULT;
			else
				this.patternType = PT_EXACT;
		}
		return this.patternType;
	}

	public int compareTo(Object o) {

		if (!(o instanceof URLPattern))
			throw new ClassCastException("argument must be URLPattern");

		URLPattern p = (URLPattern) o;

		int refPatternType = this.patternType();

		/*
		 * The comparison yields increasing sort order by pattern type. That is, prefix patterns sort before exact patterns.
		 * Also shorter length patterns precede longer length patterns. This is important for the URLPatternList
		 * canonicalization done by URLPatternSpec.setURLPatternArray
		 */
		int result = refPatternType - p.patternType();

		if (result == 0) {

			if (refPatternType == PT_PREFIX || refPatternType == PT_EXACT) {

				result = this.getPatternDepth() - p.getPatternDepth();

				if (result == 0)
					result = this.pattern.compareTo(p.pattern);

			}

			else
				result = this.pattern.compareTo(p.pattern);
		}

		return (result > 0 ? 1 : (result < 0 ? -1 : 0));
	}

	/**
	 * Does this pattern imply (that is, match) the argument pattern? This method follows the same rules (in the same order)
	 * as those used for mapping requests to servlets.
	 * <P>
	 * Two URL patterns match if they are related as follows:
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
	 * 
	 * @param p URLPattern to determine if implied by (matched by) this URLPattern to
	 */
	public boolean implies(URLPattern p) {

		// Normalize the argument
		if (p == null)
			p = new URLPattern(null);

		String path = p.pattern;
		String pattern = this.pattern;

		// Check for exact match
		if (pattern.equals(path))
			return (true);

		// Check for path prefix matching
		if (pattern.startsWith("/") && pattern.endsWith("/*")) {
			pattern = pattern.substring(0, pattern.length() - 2);

			int length = pattern.length();

			if (length == 0)
				return (true); // "/*" is the same as the DEFAULT_PATTERN

			return (path.startsWith(pattern) && (path.length() == length || path.substring(length).startsWith("/")));
		}

		// Check for suffix matching
		if (pattern.startsWith("*.")) {
			int slash = path.lastIndexOf('/');
			int period = path.lastIndexOf('.');
			if ((slash >= 0) && (period > slash) && path.endsWith(pattern.substring(1))) {
				return (true);
			}
			return (false);
		}

		// Check for universal mapping
		if (pattern.equals(DEFAULT_PATTERN))
			return (true);

		return (false);
	}

	public boolean equals(Object obj) {
		if (!(obj instanceof URLPattern))
			return false;
		return this.pattern.equals(((URLPattern) obj).pattern);
	}

	public String toString() {
		return this.pattern;
	}

	public int getPatternDepth() {

		int i = 0;
		int depth = 1;

		while (i >= 0) {

			i = this.pattern.indexOf("/", i);

			if (i >= 0) {

				if (i == 0 && depth != 1)
					throw new IllegalArgumentException("// in pattern");

				i += 1;
			}
		}

		return depth;
	}
}
