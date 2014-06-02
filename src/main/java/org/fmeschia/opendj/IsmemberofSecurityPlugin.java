/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at
 * trunk/opends/resource/legal-notices/OpenDS.LICENSE
 * or https://OpenDS.dev.java.net/OpenDS.LICENSE.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at
 * trunk/opends/resource/legal-notices/OpenDS.LICENSE.  If applicable,
 * add the following below this CDDL HEADER, with the fields enclosed
 * by brackets "[]" replaced with your own identifying information:
 *      Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 *      Copyright 2014 Francesco Meschia
 */
package org.fmeschia.opendj;

import static org.fmeschia.opendj.messages.IsmemberofSecurityPluginMessages.ERR_INITIALIZE_PLUGIN;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.opends.messages.Message;
import org.opends.server.api.plugin.DirectoryServerPlugin;
import org.opends.server.api.plugin.PluginResult.IntermediateResponse;
import org.opends.server.api.plugin.PluginResult.PreParse;
import org.opends.server.api.plugin.PluginType;
import org.opends.server.config.ConfigException;
import org.opends.server.core.DirectoryServer;
import org.opends.server.protocols.internal.InternalClientConnection;
import org.opends.server.protocols.internal.InternalSearchOperation;
import org.opends.server.types.Attribute;
import org.opends.server.types.AttributeBuilder;
import org.opends.server.types.AttributeType;
import org.opends.server.types.AttributeValue;
import org.opends.server.types.AuthenticationInfo;
import org.opends.server.types.ByteStringBuilder;
import org.opends.server.types.CanceledOperationException;
import org.opends.server.types.DirectoryException;
import org.opends.server.types.FilterType;
import org.opends.server.types.InitializationException;
import org.opends.server.types.RawFilter;
import org.opends.server.types.ResultCode;
import org.opends.server.types.SearchResultEntry;
import org.opends.server.types.SearchScope;
import org.opends.server.types.operation.PreParseCompareOperation;
import org.opends.server.types.operation.PreParseSearchOperation;
import org.opends.server.types.operation.SearchEntrySearchOperation;

import org.fmeschia.opendj.server.IsmemberofSecurityPluginCfg;

/**
 * The isMemberOf security plug-in implementation class. 
 * 
 * This plug-in will prevent authenticated binds from obtaining information 
 * (from the isMemberOf virtual attribute) about membership in groups that they 
 * have no right upon (as inferred from the bind's ability to obtain the 
 * member/uniqueMember attribute).
 * 
 * There are three LDAP use cases that may leak undue information about group
 * membership:
 * 
 * 1. Users request the isMemberOf attribute for an entry, and values of 
 *    this attribute show membership in groups that the user's bind has no
 *    right upon.
 * 2. Users compare the isMemberOf attribute of an entry with the DN name
 *    of a group that the user's bind has no right upon.
 * 3. Users search the directory without requesting the isMemberOf attribute
 *    directly, but they use the isMemberOf attribute in the filter clause
 *    to obtain list of members of groups that the user's bind has no right
 *    upon.
 *    
 * This plug-in addresses both these information leakage cases. Its overarching
 * goal is to make sure that a user can only see isMemberOf values that point
 * to groups that the user can fetch members from. All other values are
 * effectively made invisible, not comparable and not searchable. We call this
 * the "visibility metaphor".
 */
public class IsmemberofSecurityPlugin extends
DirectoryServerPlugin<IsmemberofSecurityPluginCfg> {

	// the current configuration.
	@SuppressWarnings("unused")
	private IsmemberofSecurityPluginCfg config;

	// Attribute type constants used to speed up things
	private final AttributeType memberAttributeType = DirectoryServer.getAttributeType("member");
	private final AttributeType uniqueMemberAttributeType = DirectoryServer.getAttributeType("uniquemember");
	private final AttributeType isMemberOfAttributeType = DirectoryServer.getAttributeType("ismemberof");


	/**
	 * Default constructor.
	 */
	public IsmemberofSecurityPlugin() {
		super();
	}


	/**
	 * Performs any initialization necessary for this plug-in.  This will
	 * be called as soon as the plug-in has been loaded and before it is
	 * registered with the server.
	 */
	@Override()
	public void initializePlugin(Set<PluginType> pluginTypes,
			IsmemberofSecurityPluginCfg configuration)
					throws ConfigException, InitializationException {
		// this plug-in may only be used either as a process search result plug-in
		// or as a pre-parse search plug-in
		for (PluginType t : pluginTypes) {
			switch (t) {
			case SEARCH_RESULT_ENTRY:
				break;
			case PRE_PARSE_SEARCH:
				break;
			case PRE_PARSE_COMPARE:
				break;
			default:
				Message message = ERR_INITIALIZE_PLUGIN.get(String.valueOf(t));
				throw new ConfigException(message);
			}
		}
		// don't bother calling this plugin for internal operations
		setInvokeForInternalOperations(false);
		// save the configuration. This plug-in has actually no configuration,
		// but it's best to save it anyway
		this.config = configuration;
	}


	/**
	 * Indicates whether the provided configuration is acceptable for this 
	 * plug-in. 
	 */
	public boolean isConfigurationAcceptable(IsmemberofSecurityPluginCfg config, List<Message> messages)
	{
		return true;
	}


	/**
	 * Checks whether a certain user can read members of a given group.
	 * @param authenticationInfo the user's authentication info
	 * @param groupDnAsString the group's DN as String
	 * @return true if the bind has access to either the member or the
	 * uniqueMember attribute
	 * @throws DirectoryException if the search generates an error
	 */

	private boolean canReadMembers(AuthenticationInfo authenticationInfo, String groupDnAsString) throws DirectoryException {
		boolean out = false;
		InternalClientConnection conn = new InternalClientConnection(authenticationInfo);
		InternalSearchOperation searchOp = conn.processSearch(groupDnAsString, SearchScope.BASE_OBJECT, "(objectclass=*)");
		List<SearchResultEntry> entries = searchOp.getSearchEntries();
		for (SearchResultEntry resultEntry : entries) {
			if (resultEntry.hasAttribute(uniqueMemberAttributeType) ||
					resultEntry.hasAttribute(memberAttributeType)) out = true;
		}
		return out;
	}


	/**
	 * Returns a list of all the groups that the user can fetch members from.
	 * @param authInfo the user's authentication info
	 * @return the list of groups that the user can fetch members from
	 * @throws DirectoryException
	 */

	private List<String> getAuthorizedGroups(AuthenticationInfo authInfo) throws DirectoryException {
		List<String> out = new ArrayList<String>();
		InternalClientConnection conn = new InternalClientConnection(authInfo);
		// look from DIT down for groupofnames or groupofuniquenames that have
		// members visible to the user
		InternalSearchOperation searchOp = conn.processSearch(
				"",	SearchScope.WHOLE_SUBTREE, 
				"(|(&(objectclass=groupofuniquenames)(uniqueMember=*))(&(objectclass=groupofnames)(member=*)))");
		List<SearchResultEntry> entries = searchOp.getSearchEntries();
		for (SearchResultEntry entry : entries) {
			// build a list of stringified DNs
			out.add(entry.getDN().toString());
		}
		return out;
	}


	/**
	 * This is the hook point that allows to performs any necessary processing 
	 * before a search result entry is sent to a client. 
	 * In order to minimize performance impact, the whole logic is skipped
	 * unless the isMemberOf attribute is present in the candidate entry.
	 * If the attribute is present, each value is interpreted as the DN of a
	 * group, and the canReadMembers() method is called to check whether the
	 * user can read the members of that group. If it turns out that the user
	 * can't, the value is removed from the attribute of the candidate entry.
	 * @param searchOperation The search operation with which the search entry 
	 * is associated.
	 * @param searchEntry The search result entry that is to be sent to the 
	 * client. Its contents may be altered by the plugin if necessary.
	 * @returns A directive about the result of the plugin processing.
	 */

	@Override
	public IntermediateResponse processSearchEntry(
			SearchEntrySearchOperation searchOperation,
			SearchResultEntry searchEntry) {
		// processing takes place only if the isMemberOf attribute is present
		if (searchEntry.hasAttribute(isMemberOfAttributeType)) {
			// there should be only one attribute with that name, but anyway...
			for (Attribute attr : searchEntry.getAttribute(isMemberOfAttributeType)) {
				List<AttributeValue> toBeRemoved = new ArrayList<AttributeValue>();
				Iterator<AttributeValue> iter = attr.iterator();
				// iterate over the attribute values
				while (iter.hasNext()) {
					AttributeValue value = iter.next();
					try {
						// each value is the DN of a group. If the user is not
						// authorized to fetch members of that group, the 
						// value is slated for removal
						if (!canReadMembers(searchOperation.
								getClientConnection().
								getAuthenticationInfo(), value.toString()))
							toBeRemoved.add(value);
					} catch (Exception e) {
						// TODO this needs to be better than just a printStackTrace()
						e.printStackTrace();
						// exception is interpreted as inability to fetch
						toBeRemoved.add(value);
					}
				}
				if (toBeRemoved.size() > 0) {
					// build a new attribute based on the attribute just processed,
					// that will contain only those values that need to be removed
					AttributeBuilder builder = new AttributeBuilder(attr);
					Iterator<AttributeValue> valueIter = attr.iterator();
					// iterate over the values of the attribute
					while (valueIter.hasNext()) {
						AttributeValue attrVal = valueIter.next();
						// any value that is not slated for removal will be
						// deleted from the list of attributes to be removed
						if (!toBeRemoved.contains(attrVal)) {
							builder.remove(attrVal);
						}
					}
					Attribute attrToBeRemoved = builder.toAttribute();
					// this list will contain the values actually removed
					// it is not used, it's just there for diagnostic purposes
					List<AttributeValue> removedValues = new ArrayList<AttributeValue>();
					// remove the undesired values
					searchEntry.removeAttribute(attrToBeRemoved, removedValues);
				}
			}
		}
		return IntermediateResponse.continueOperationProcessing(true);
	}


	/**
	 * This is the hook point for any processing that should be done before the
	 * Directory Server parses the elements of a compare request.
	 * In order to avoid information leakage, the compare operation is checked
	 * to see if it involves the isMemberOf attribute. If so, only operations
	 * involving groups on which the user has permission to see the members are
	 * permitted. Comparisons involving groups on which the user has no
	 * permissions will result in an error being returned to the client.
	 * @param compareOperation The compare operation that has been requested.
	 * @return Information about the result of the plugin processing.
	 */

	@Override
	public PreParse doPreParse(PreParseCompareOperation compareOperation)
			throws CanceledOperationException {
		PreParse out = PreParse.continueOperationProcessing(); // default result
		if (compareOperation.getRawAttributeType().equalsIgnoreCase("isMemberOf")) {
			// if the comparison involves the isMemberOf attribute, the value
			// of the assertion is assumed to be a group DN
			String matchingGroupDnAsString = compareOperation.getAssertionValue().toString();
			try {
				// if the user can't fetch the members of the group, stop
				// with an insufficient access right error
				if (!canReadMembers(compareOperation.getClientConnection().getAuthenticationInfo(), matchingGroupDnAsString))
					out = PreParse.stopProcessing(ResultCode.COMPARE_FALSE, Message.EMPTY);
			} catch (DirectoryException e) {
				// TODO Need better exception handling
				e.printStackTrace();
				// in case of an exception, also stop processing and 
				// return an insufficient access right error
				out = PreParse.stopProcessing(ResultCode.COMPARE_FALSE, Message.EMPTY);
			}
		}
		return out;
	}


	/**
	 * This is the hook point for any processing that should be done before 
	 * the Directory Server parses the elements of a search request.
	 * In order to avoid information leakage, the filter used by the
	 * search operation is parsed and re-written, so that any filter element 
	 * involving an equality comparison of isMemberOf with a group that
	 * the user has no right to see, is replaced with a logical false value.
	 * This is effectively equivalent to making the prohibited isMemberOf
	 * values invisible from filters.
	 * Note that equality comparisons are the only possible ones for isMemberOf
	 * (no other matching rule is defined in the schema), so we can leave
	 * alone substring, presence and other comparisons involving isMemberOf,
	 * because OpenDJ will sanitize them anyway.
	 * @param searchOperation The search operation that has been requested.
	 * @return Information about the result of the plugin processing.
	 */

	@Override
	public PreParse doPreParse(PreParseSearchOperation searchOperation)
			throws CanceledOperationException {
		PreParse out = PreParse.continueOperationProcessing(); // default case
		// rebuild the filter
		RawFilter newFilter = rebuildFilter(
				searchOperation.getRawFilter(),
				searchOperation.getClientConnection().getAuthenticationInfo());
		// if the new filter is null, replace it with a logical true value
		if (newFilter == null) newFilter = RawFilter.createPresenceFilter("objectClass"); 
		// replace the old filter in the search operation with the rewritten one
		searchOperation.setRawFilter(newFilter);
		return out;
	}


	/**
	 * Rebuilds a filter, replacing all components that involve equality
	 * comparisons of the isMemberOf attribute with DNs of groups for which
	 * the user is not authorized, with logical false values (!(objectclass=*))
	 * Equality is the only possible matching rule defined for isMemberOf,
	 * so there is no reason to check anything else.
	 * This method recursively calls itself to break down complex filters into
	 * elementary expressions
	 * @param filter the original filter
	 * @param authInfo the user's authentication info
	 * @return the rebuilt filter
	 */

	private RawFilter rebuildFilter(RawFilter filter, AuthenticationInfo authInfo) {
		RawFilter out = null;
		RawFilter rewrittenFilter;
		// as per RFC 4515, filter, a filter element is either a comparison, or
		// one of AND, OR or NOT
		if (filter.getFilterType() == FilterType.AND) {
			// if this is an AND block, rewrite it by recursively rebuilding
			// all block components 
			ArrayList<RawFilter> filterComponents = new ArrayList<RawFilter>();
			for (RawFilter filterComponent : filter.getFilterComponents()) {
				rewrittenFilter = rebuildFilter(filterComponent, authInfo);
				filterComponents.add(rewrittenFilter);
			}
			out = RawFilter.createANDFilter(filterComponents);
		} else if (filter.getFilterType() == FilterType.OR) {
			// if this is an OR block, rewrite it by recursively rebuilding
			// all block components 
			ArrayList<RawFilter> filterComponents = new ArrayList<RawFilter>();
			for (RawFilter filterComponent : filter.getFilterComponents()) {
				rewrittenFilter = rebuildFilter(filterComponent, authInfo);
				filterComponents.add(rewrittenFilter);
			}
			out = RawFilter.createORFilter(filterComponents);
		} else if (filter.getFilterType() == FilterType.NOT) {
			// for a NOT block, rewrite it by recursively rebuilding
			// its component
			RawFilter filterComponent = filter.getNOTComponent();
			rewrittenFilter = rebuildFilter(filterComponent, authInfo);		
			out = RawFilter.createNOTFilter(rewrittenFilter);
		} else {
			// if not a AND, OR or NOT, then this is an elemental comparison
			if (!filter.getAttributeType().equalsIgnoreCase("isMemberOf")) {
				// if the comparison does not involve isMemberOf, leave it alone
				out = filter;
			} else {
				if (filter.getFilterType() == FilterType.PRESENT) {
					// if this is a presence match, to maintain the metaphor of
					// group visibility we need to replace the filter with an
					// OR of all the membership in all the "authorized" groups
					try {
						// we get a list of the authorized group names
						List<String> authorizedGroupDns = getAuthorizedGroups(authInfo);
						// we prepare to build a list of filter components
						// to build the OR filter
						ArrayList<RawFilter> filterComponents = new ArrayList<RawFilter>();
						ByteStringBuilder builder = new ByteStringBuilder();
						for (String authorizedGroupDn : authorizedGroupDns) {
							// for each group, we create a (ismemberof=<name>)
							// filter component
							builder.clear();
							builder.append(authorizedGroupDn);
							filterComponents.add(RawFilter.createEqualityFilter(
									"isMemberOf", builder.toByteString()));
						}
						// and we build an OR filter from the list of component
						out = RawFilter.createORFilter(filterComponents);
					} catch (DirectoryException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
						// if something goes wrong, we fall back to OpenDJ
						// standard behavior. This means that all entries that
						// are members of any group will be returned (regardless
						// of visibility), but anyway this shouldn't leak any
						// real membership information
						out = filter;
					}
				} else if (filter.getFilterType() == FilterType.EQUALITY){
					// if this is an equality match, let's see if the user can
					// read the members of the group used as comparison 
					String matchingGroupDnAsString = filter.getAssertionValue().toString();
					try {
						if (canReadMembers(authInfo, matchingGroupDnAsString)) {
							// if members can be fetched, the filter is valid
							out = filter;
						} else {
							// otherwise, the filter will be replaced with a
							// logical FALSE value (!(objectclass=*))
							out = RawFilter.createNOTFilter(RawFilter.createPresenceFilter("objectClass")); 
						}
					} catch (DirectoryException e) {
						// TODO Need to improve this
						e.printStackTrace();
						out = RawFilter.createNOTFilter(RawFilter.createPresenceFilter("objectClass"));
					}
				} else {
					// if the comparison is not of the EQUALITY or PRESENT type,
					// OpenDJ will take care of that (no other matching rules 
					// are defined for the isMemberOf attribute type)
					out = filter;
				}
			}
		}
		return out;
	}
}
