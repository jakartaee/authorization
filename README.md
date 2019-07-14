# Jakarta Authorization

This repository contains the code for Jakarta Authorization.

[Online JavaDoc](https://javadoc.io/doc/jakarta.security.jacc/jakarta.security.jacc-api/)

Building
--------

Jakarta Authorization can be built by executing the following from the project root:

``mvn clean package``

The API jar can then be found in /app/target.

Making Changes
--------------

To make changes, fork this repository, make your changes, and submit a pull request.

About Jakarta Authorization
-------------

Jakarta Authorization defines a low-level SPI for authorization modules, which are repositories of permissions 
facilitating subject based security by determining whether a given subject has a given permission, and algorithms
to transform security constraints for specific containers (such as Jakarta- Servlet or Enterprise Beans) into 
these permissions.
