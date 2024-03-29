///////////////////////////////////////////////////////////////////////
NOTE TO WRITERS:
These CLI examples can be customized as necessary.
///////////////////////////////////////////////////////////////////////

Start the Junit tests using the following command:

[source,oac_no_warn]
----
mvn verify
----

[[GCMCU]]

Example 5-1 {TechnologyShortName} TCK Signature Tests

To run the {TechnologyShortName} TCK signature tests, enter the
following commands:

[source,subs="attributes"]
----
mvn -f authorization-signaturetest/pom.xml verify
----

[[GCMBV]]


Example 5-2 Single Test Directory

To run a single test directory, enter the following commands:

[source,subs="attributes"]
----
mvn -f {singleTestDirectoryExample}/pom.xml verify 

or alternatively 

mvn clean && mvn clean -pl :{singleTestDirectoryExample}

----

[[GCMCA]]


Example 5-3 Single test

To run a single test with a single test directory, enter the following commands:

[source,subs="attributes"]
----
mvn clean && mvn clean install -pl :app-custom-policy -Dit.test=AppCustomPolicyIT#testAuthenticated

----

Example 5-4 Single test with debugging (GlassFish)

To run a single test with a single test directory with the JVM running GlassFish suspending on port 9009, enter the following commands:

[source,subs="attributes"]
----
mvn clean && mvn clean install -pl :app-custom-policy -Dit.test=AppCustomPolicyIT#testAuthenticated -Dglassfish.suspend

----

Example 5-5 Running a technology preview version of this TCK

A technology preview version may include dependencies that are in staging. If that is the case, start
the Junit tests using the following command:

[source,subs="attributes"]
----
mvn verify -Pstaging

----



