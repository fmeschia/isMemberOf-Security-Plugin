isMemberOf Security Plug-in for OpenDJ
======================================
by Francesco Meschia

Problem statement
-----------------
The values of the *isMemberOf* virtual attribute are the Distinguished Names of those groups (entries of class *groupofnames* or *groupofuniquenames*) that a person's entry belongs to (i.e. group that have the person's entry DN among the values of their *member*/*uniqueMember* attribute).

As such, the use of the *isMemberOf* attribute is liable for a potential security problem. The directory administrators may decide that it makes sense to restrict the visibility of the members of a group (by setting an ACI on the group's entry), but users may still discover the members of the "restricted" group by searching people using a filter based on the *isMemberOf* attribute. The LDAP standard has no provision to set an ACI for the *values* of an attributes.

Solution
--------
This OpenDJ plug-in addresses this problem by treating the values of the *isMemberOf* attribute with their correct semantics, and assessing the visibility of the associated groups' *member*/*uniqueMember* attribute as *search* and *compare* operations are executed.

The plug-in operates under a "visibility metaphor": if you have no right to see members of a given group, then the values of the *isMemberOf* attribute corresponding to that group should not be visible to you at all, in any LDAP operation you may perform. In this way, not only you can't see the values themselves, but no information is leaked through any operation (i.e. you can't filter based on groups you are not authorized to see, because no LDAP operation you can invoke can "see" the corresponding values).

The plug-in operates in three different ways:

* when an entry is fetched during a *search* operation, it is examined before being returned to the client. Any value of the *isMemberOf* attribute is checked to see whether the user's bind can see the members of the corresponding group. If the user's bind can't see them, the value is removed from the entry.

* before a *compare* operation is performed, the plug-in checks to see whether the attribute being compared is *isMemberOf*, and if so it checks whether the user's bind has the right to see the members of the group corresponding to the value that the attribute is compared against. If the user's bind can't see them, the compare operation always returns a logical FALSE (visibility metaphor: if you can't see that value, no entry can have an attribute matching it)

* before a *search* operation is performed, the plug-in parses the expression used as search filter:

    - If a filter element contains an equality match on the *isMemberOf* attribute, the plug-in checks to see whether the user's bind can see the members of the group that corresponds to the value that the attribute is matched against. If the user can't see them, the filter element is replaced by a logical FALSE (visibility metaphor, as above).
	
	- If a filter element contains a presence match on the *isMemberOf* attribute, that element is replaced by a series of elements, in OR with one another, each one of them being an equality match against one of the DNs of the group that the user's bind can see the members of (corollary to the visibility metaphor: you can see no values other than the ones you are authorized to see). In this way, a potential information leak is avoided (i.e. without this substitution, users could infer that some person entries must be part of some group that they can't see, even though they couldn't tell what group).
	
	- If a filter element contains any other match on the *isMemberOf* attribute, it will be left alone. OpenDJ will ignore it anyway, because equality and presence are the only matching rules honored by OpenDJ for the isMemberOf attribute.
	
Building the plug-in
--------------------
To build the plug-in, you need Apache Maven 3 or later. Simply pull the plug-in sources, and issue the command:

	mvn package

This will build the plug-in JAR file in the `target` directory.

Installing the plug-in
----------------------
To install the plug-in:

* copy the `target/ismemberof-security-plugin-<version>.jar` file into the `${OPENDJ_HOME}/lib/extensions` directory
	
* copy the `resource/config/ismemberof-security-plugin.ldif` file into the `${OPENDJ_HOME}/config` directory

* copy the `resource/schema/99-ismemberof-security-plugin.ldif` file into the `${OPENDJ_HOME}/config/schema` directory

Then restart OpenDJ. After that, issue the command:

    dsconfig -h `hostname` -p 4444 -D "cn=Directory Manager" create-plugin \
	--plugin-name "isMemberOf Security Plugin" --type ismemberof-security \
	--set enabled:true --set plugin-type:preparsecompare --set plugin-type:preparsesearch \
	--set plugin-type:searchresultentry -X

Then enter the directory manager's password and confirm. The plugin is now installed.
