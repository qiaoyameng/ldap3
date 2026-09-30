"""
"""

# Created on 2026.09.30
#
# Author: Giovanni Cannata
#
# Copyright 2026 Giovanni Cannata
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

from pyasn1.type.univ import OctetString, Sequence, SequenceOf, Boolean, Enumerated
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType, DefaultedNamedType
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1.type.constraint import ValueRangeConstraint

from .controls import build_control
from ..core.exceptions import LDAPControlError

# Server Side Sorting as per RFC 2891

SORT_REQUEST_OID = '1.2.840.113556.1.4.473'
SORT_RESPONSE_OID = '1.2.840.113556.1.4.474'

# sortResult ENUMERATED values as per RFC 2891
SORT_RESULT_SUCCESS = 0
SORT_RESULT_OPERATIONS_ERROR = 1
SORT_RESULT_TIME_LIMIT_EXCEEDED = 3
SORT_RESULT_STRONG_AUTH_REQUIRED = 8
SORT_RESULT_ADMIN_LIMIT_EXCEEDED = 11
SORT_RESULT_NO_SUCH_ATTRIBUTE = 16
SORT_RESULT_INAPPROPRIATE_MATCHING = 18
SORT_RESULT_INSUFFICIENT_ACCESS_RIGHTS = 50
SORT_RESULT_BUSY = 51
SORT_RESULT_UNWILLING_TO_PERFORM = 53
SORT_RESULT_OTHER = 80

SORT_RESULT_CODES = {
    SORT_RESULT_SUCCESS: 'success',
    SORT_RESULT_OPERATIONS_ERROR: 'operationsError',
    SORT_RESULT_TIME_LIMIT_EXCEEDED: 'timeLimitExceeded',
    SORT_RESULT_STRONG_AUTH_REQUIRED: 'strongAuthRequired',
    SORT_RESULT_ADMIN_LIMIT_EXCEEDED: 'adminLimitExceeded',
    SORT_RESULT_NO_SUCH_ATTRIBUTE: 'noSuchAttribute',
    SORT_RESULT_INAPPROPRIATE_MATCHING: 'inappropriateMatching',
    SORT_RESULT_INSUFFICIENT_ACCESS_RIGHTS: 'insufficientAccessRights',
    SORT_RESULT_BUSY: 'busy',
    SORT_RESULT_UNWILLING_TO_PERFORM: 'unwillingToPerform',
    SORT_RESULT_OTHER: 'other'
}


class AttributeType(OctetString):
    # AttributeDescription ::= LDAPString
    pass


class OrderingRule(OctetString):
    # orderingRule    [0] MatchingRuleId OPTIONAL
    tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 0))


class ReverseOrder(Boolean):
    # reverseOrder    [1] BOOLEAN DEFAULT FALSE
    tagSet = Boolean.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 1))


class SortKey(Sequence):
    # SEQUENCE {
    #     attributeType   AttributeDescription,
    #     orderingRule    [0] MatchingRuleId OPTIONAL,
    #     reverseOrder    [1] BOOLEAN DEFAULT FALSE }
    componentType = NamedTypes(NamedType('attributeType', AttributeType()),
                               OptionalNamedType('orderingRule', OrderingRule()),
                               DefaultedNamedType('reverseOrder', ReverseOrder(False)))


class SortKeyList(SequenceOf):
    # SortKeyList ::= SEQUENCE OF SortKey
    componentType = SortKey()


class SortResultCode(Enumerated):
    subtypeSpec = Enumerated.subtypeSpec + ValueRangeConstraint(0, 80)


class SortResultAttributeType(OctetString):
    # attributeType [0] AttributeDescription OPTIONAL
    tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 0))


class SortResult(Sequence):
    # SortResult ::= SEQUENCE {
    #    sortResult  ENUMERATED { ... },
    #    attributeType [0] AttributeDescription OPTIONAL }
    componentType = NamedTypes(NamedType('sortResult', SortResultCode()),
                               OptionalNamedType('attributeType', SortResultAttributeType()))


def parse_sort_key(key):
    """
    Parse a sort key specification in the form 'attribute', '-attribute',
    'attribute:matchingRuleOid' or '-attribute:matchingRuleOid'.
    Return a tuple (attribute_type, matching_rule, reverse_order).
    """
    if not isinstance(key, str):
        raise LDAPControlError('sort key must be a string')
    key = key.strip()
    reverse_order = key.startswith('-')
    if reverse_order:
        key = key[1:]
    attribute_type, _, matching_rule = key.partition(':')
    attribute_type = attribute_type.strip()
    matching_rule = matching_rule.strip() or None
    if not attribute_type:
        raise LDAPControlError('missing attribute type in sort key')
    return attribute_type, matching_rule, reverse_order


def sort_keys_to_list(sort_keys):
    """Normalize a sort key specification to a list of (attribute, matching_rule, reverse) tuples."""
    if isinstance(sort_keys, str):
        sort_keys = [sort_keys]
    return [parse_sort_key(key) for key in sort_keys]


def sort_request_control(criticality, sort_keys):
    """
    Build the Sort Request control (1.2.840.113556.1.4.473) as per RFC 2891.
    sort_keys is a string or a list of strings, each in the form
    'attribute', '-attribute' (reverse), 'attribute:matchingRuleOid'
    or '-attribute:matchingRuleOid'.
    """
    control_value = SortKeyList()
    for position, (attribute_type, matching_rule, reverse_order) in enumerate(sort_keys_to_list(sort_keys)):
        sort_key = SortKey()
        sort_key.setComponentByName('attributeType', AttributeType(attribute_type))
        if matching_rule:
            sort_key.setComponentByName('orderingRule', OrderingRule(matching_rule))
        sort_key.setComponentByName('reverseOrder', ReverseOrder(reverse_order))
        control_value.setComponentByPosition(position, sort_key)

    return build_control(SORT_REQUEST_OID, criticality, control_value)


def sort_response_control(sort_result=SORT_RESULT_SUCCESS, attribute_type=None, criticality=False):
    """
    Build the Sort Response control (1.2.840.113556.1.4.474) as per RFC 2891.
    Used by mock strategies to return the outcome of a sort request.
    """
    control_value = SortResult()
    control_value.setComponentByName('sortResult', SortResultCode(sort_result))
    if attribute_type:
        control_value.setComponentByName('attributeType', SortResultAttributeType(attribute_type))

    return build_control(SORT_RESPONSE_OID, criticality, control_value)
