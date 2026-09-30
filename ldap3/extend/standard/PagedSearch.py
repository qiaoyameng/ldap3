"""
"""

# Created on 2014.07.08
#
# Author: Giovanni Cannata
#
# Copyright 2014 - 2025 Giovanni Cannata
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

from ... import SUBTREE, DEREF_ALWAYS
from ...utils.dn import safe_dn
from ...core.results import DO_NOT_RAISE_EXCEPTIONS, RESULT_SIZE_LIMIT_EXCEEDED
from ...core.exceptions import LDAPOperationResult, LDAPSortControlError
from ...protocol.rfc2891 import sort_request_control, SORT_REQUEST_CONTROL, SORT_RESPONSE_CONTROL, SORT_RESULT_SUCCESS
from ...utils.log import log, log_enabled, ERROR, BASIC, PROTOCOL, NETWORK, EXTENDED


def _prepare_paged_controls(controls, sort_order, sort_criticality):
    # merges the caller controls with the server side sort control (RFC 2891)
    search_controls = list(controls) if controls else []
    if sort_order is not None:
        # removes any previously included sort request control to prevent reusing it with a different cookie
        search_controls = [control for control in search_controls if str(control['controlType']) != SORT_REQUEST_CONTROL]
        search_controls.append(sort_request_control(sort_order, sort_criticality))
    return search_controls


def _check_sort_result(result, sort_order):
    # verifies the sort response control of every page, no entry is returned if sorting failed
    if sort_order is None:
        return

    if 'controls' not in result or SORT_RESPONSE_CONTROL not in result['controls']:
        raise LDAPSortControlError('server did not return the sort response control')

    sort_result = result['controls'][SORT_RESPONSE_CONTROL]['value']
    if sort_result['result'] != SORT_RESULT_SUCCESS:
        if log_enabled(PROTOCOL):
            log(PROTOCOL, 'server side sort failed with result <%s> for <%s>', sort_result, result.get('message', ''))
        failing_attribute = (' on attribute %r' % sort_result['attr']) if sort_result.get('attr') else ''
        raise LDAPSortControlError('server side sort failed with result code %s%s' % (
            sort_result['result'], failing_attribute))


def paged_search_generator(connection,
                           search_base,
                           search_filter,
                           search_scope=SUBTREE,
                           dereference_aliases=DEREF_ALWAYS,
                           attributes=None,
                           size_limit=0,
                           time_limit=0,
                           types_only=False,
                           get_operational_attributes=False,
                           controls=None,
                           paged_size=100,
                           paged_criticality=False,
                           sort_order=None,
                           sort_criticality=True):
    if connection.check_names and search_base:
        search_base = safe_dn(search_base)

    search_controls = _prepare_paged_controls(controls, sort_order, sort_criticality)

    responses = []
    original_connection = None
    original_auto_referrals = connection.auto_referrals
    connection.auto_referrals = False  # disable auto referrals because it cannot handle paged searches
    cookie = True  # performs search operation at least one time
    cachekey = None  # for referrals cache
    while cookie:
        result = connection.search(search_base,
                                   search_filter,
                                   search_scope,
                                   dereference_aliases,
                                   attributes,
                                   size_limit,
                                   time_limit,
                                   types_only,
                                   get_operational_attributes,
                                   search_controls,
                                   paged_size,
                                   paged_criticality,
                                   None if cookie is True else cookie)

        if not connection.strategy.sync:
            response, result = connection.get_response(result)
        else:
            if connection.strategy.thread_safe:
                _, result, response, _ = result
            else:
                response = connection.response
                result = connection.result

        # the sort result of every page is checked before returning any entry of the page
        _check_sort_result(result, sort_order)

        if result['referrals'] and original_auto_referrals:  # if rererrals are returned start over the loop with a new connection to the referral
            if not original_connection:
                original_connection = connection
            _, connection, cachekey = connection.strategy.create_referral_connection(result['referrals'])   # change connection to a valid referrals
            continue

        responses.extend(response)
        try:
            cookie = result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        except KeyError:
            cookie = None

        if connection.raise_exceptions and result and result['result'] not in DO_NOT_RAISE_EXCEPTIONS:
            if log_enabled(PROTOCOL):
                log(PROTOCOL, 'paged search operation result <%s> for <%s>', result, connection)
            if result['result'] == RESULT_SIZE_LIMIT_EXCEEDED:
                for yielded_response in responses:  # entries collected so far are still returned
                    yield yielded_response
                responses = []
            raise LDAPOperationResult(result=result['result'], description=result['description'], dn=result['dn'], message=result['message'], response_type=result['type'])

        # entries are yielded in the same order the server sent them, required for a stable sorted paging
        while responses:
            yield responses.pop(0)

    if original_connection:
        connection = original_connection
        if connection.use_referral_cache and cachekey:
            connection.strategy.referral_cache[cachekey] = connection
        else:
            connection.unbind()

    connection.auto_referrals = original_auto_referrals
    connection.response = None


def paged_search_accumulator(connection,
                             search_base,
                             search_filter,
                             search_scope=SUBTREE,
                             dereference_aliases=DEREF_ALWAYS,
                             attributes=None,
                             size_limit=0,
                             time_limit=0,
                             types_only=False,
                             get_operational_attributes=False,
                             controls=None,
                             paged_size=100,
                             paged_criticality=False,
                             sort_order=None,
                             sort_criticality=True):
    if connection.check_names and search_base:
        search_base = safe_dn(search_base)

    responses = []
    for response in paged_search_generator(connection,
                                           search_base,
                                           search_filter,
                                           search_scope,
                                           dereference_aliases,
                                           attributes,
                                           size_limit,
                                           time_limit,
                                           types_only,
                                           get_operational_attributes,
                                           controls,
                                           paged_size,
                                           paged_criticality,
                                           sort_order,
                                           sort_criticality):
        responses.append(response)

    connection.response = responses
    return responses
