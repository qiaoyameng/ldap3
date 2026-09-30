"""
LDAP Server Side Sorting control as per RFC 2891
"""

# Created on 2026.09.30
#
# Author: Giovanni Cannata
#
# Copyright 2013 - 2026 Giovanni Cannata
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

from pyasn1.type.univ import OctetString, SequenceOf, Sequence, Enumerated, Boolean
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple
from pyasn1.error import PyAsn1Error

from .controls import build_control
from ..utils.asn1 import decoder
from ..core.exceptions import LDAPControlError

# controls as per RFC 2891

SORT_REQUEST_CONTROL = '1.2.840.113556.1.4.473'
SORT_RESPONSE_CONTROL = '1.2.840.113556.1.4.474'

# sortResult values, ENUMERATED { successResults(0), operationsError(1),
# timeLimitExceeded(3), strongAuthRequired(8), adminLimitExceeded(11),
# noSuchAttribute(16), unwillingToPerform(53), other(80) }

SORT_RESULT_SUCCESS = 0
SORT_RESULT_OPERATIONS_ERROR = 1
SORT_RESULT_TIME_LIMIT_EXCEEDED = 3
SORT_RESULT_STRONG_AUTH_REQUIRED = 8
SORT_RESULT_ADMIN_LIMIT_EXCEEDED = 11
SORT_RESULT_NO_SUCH_ATTRIBUTE = 16
SORT_RESULT_INAPPROPRIATE_MATCHING = 18
SORT_RESULT_UNWILLING_TO_PERFORM = 53
SORT_RESULT_OTHER = 80


class AttributeType(OctetString):
    # attributeType   AttributeDescription
    pass


class OrderingRule(OctetString):
    # orderingRule [0] MatchingRuleId OPTIONAL
    # the field is context tagged [0] as per RFC 2891
    tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 0))


class ReverseOrder(Boolean):
    # reverseOrder    [1] BOOLEAN DEFAULT FALSE
    tagSet = Boolean.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 1))


class SortKey(Sequence):
    # SortKey ::= SEQUENCE {
    #     attributeType   AttributeDescription,
    #     orderingRule    [0] MatchingRuleId OPTIONAL,
    #     reverseOrder    [1] BOOLEAN DEFAULT FALSE }
    componentType = NamedTypes(NamedType('attributeType', AttributeType()),
                               OptionalNamedType('orderingRule', OrderingRule()),
                               OptionalNamedType('reverseOrder', ReverseOrder()))


class SortRequestControlValue(SequenceOf):
    # SortKeyList ::= SEQUENCE SIZE (1..MAX) OF SortKey
    # (the sort request control value is the SortKeyList itself)
    componentType = SortKey()


class SortResultCode(Enumerated):
    # ENUMERATED { successResults(0), operationsError(1), timeLimitExceeded(3),
    # strongAuthRequired(8), adminLimitExceeded(11), noSuchAttribute(16),
    # unwillingToPerform(53), other(80) }
    pass


class AttributeDescription(OctetString):
    pass


class SortResultAttributeType(OctetString):
    # attributeType [0] AttributeDescription OPTIONAL
    tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 0))


class SortResponseControlValue(Sequence):
    # SortResult ::= SEQUENCE {
    #     sortResult  ENUMERATED {
    #         successResults (0),
    #         operationsError (1),
    #         timeLimitExceeded (3),
    #         strongAuthRequired (8),
    #         adminLimitExceeded (11),
    #         noSuchAttribute (16),
    #         unwillingToPerform (53),
    #         other (80) },
    #     attributeType [0] AttributeDescription OPTIONAL }
    componentType = NamedTypes(NamedType('sortResult', SortResultCode()),
                               OptionalNamedType('attributeType', SortResultAttributeType()))


def _coerce_sort_key(sort_key):
    # accepts a SortKey ASN.1 object, a tuple (attribute_type, ordering_rule, reverse_order)
    # or a dict {'attribute_type': ..., 'ordering_rule': ..., 'reverse_order': ...}
    if isinstance(sort_key, SortKey):
        return sort_key

    ordering_rule = None
    reverse_order = False
    if isinstance(sort_key, dict):
        attribute_type = sort_key.get('attribute_type') or sort_key.get('attributeType')
        if attribute_type is None:
            raise LDAPControlError('sort key must include the attribute_type')
        ordering_rule = sort_key.get('ordering_rule')
        reverse_order = bool(sort_key.get('reverse_order', False))
    elif isinstance(sort_key, (tuple, list)):
        if not sort_key:
            raise LDAPControlError('sort key must include the attribute_type')
        attribute_type = sort_key[0]
        if len(sort_key) > 1 and sort_key[1] is not None:
            ordering_rule = sort_key[1]
        if len(sort_key) > 2 and sort_key[2] is not None:
            reverse_order = bool(sort_key[2])
    elif isinstance(sort_key, str):
        attribute_type = sort_key
    elif isinstance(sort_key, bytes):
        attribute_type = sort_key.decode('utf-8')
    else:
        raise LDAPControlError('unable to decode sort key %r' % (sort_key,))

    if isinstance(attribute_type, bytes):
        attribute_type = attribute_type.decode('utf-8')
    if ordering_rule is not None and isinstance(ordering_rule, bytes):
        ordering_rule = ordering_rule.decode('utf-8')

    if attribute_type is None:
        raise LDAPControlError('sort key must include the attribute_type')

    key = SortKey()
    key.setComponentByName('attributeType', AttributeType(str(attribute_type)))
    if ordering_rule is not None:
        key.setComponentByName('orderingRule', OrderingRule(str(ordering_rule)))
    if reverse_order:
        key.setComponentByName('reverseOrder', ReverseOrder(True))

    return key


def sort_request_control(sort_order=None, criticality=True):
    """
    Builds the server-side sort request control as per RFC 2891.

    :param sort_order: list of sort keys. Each key can be a string (attribute name),
                       a tuple (attribute_type, ordering_rule_or_None, reverse_order),
                       or a dict with keys 'attribute_type', 'ordering_rule' and 'reverse_order'.
    :param criticality: control is critical by default, as suggested in RFC 2891
    """
    if sort_order is None:
        sort_order = []

    control_value = SortRequestControlValue()
    for index, sort_key in enumerate(sort_order):
        control_value.setComponentByPosition(index, _coerce_sort_key(sort_key))

    if not len(control_value):
        raise LDAPControlError('sort request control requires at least one sort key')

    return build_control(SORT_REQUEST_CONTROL, criticality, control_value)


def sort_response_control(sort_result=SORT_RESULT_SUCCESS, attribute_type=None, criticality=False):
    """
    Builds the server-side sort response control as per RFC 2891.
    """
    control_value = SortResponseControlValue()
    control_value.setComponentByName('sortResult', SortResultCode(int(sort_result)))
    if attribute_type is not None:
        control_value.setComponentByName('attributeType', SortResultAttributeType(str(attribute_type)))

    return build_control(SORT_RESPONSE_CONTROL, criticality, control_value)


def sort_request_to_list(control_value):
    """
    Decodes a sort request control value into a list of dictionaries:
    [{'attr': attribute_type, 'ordering_rule': OID or None, 'reverse_order': bool}, ...]
    """
    if isinstance(control_value, (bytes, bytearray)):
        try:
            control_value, unprocessed = decoder.decode(bytes(control_value), asn1Spec=SortRequestControlValue())
        except PyAsn1Error as error:
            raise LDAPControlError('unable to decode sort request control: %s' % error)
        if unprocessed:
            raise LDAPControlError('unprocessed data in sort request control')

    sort_keys = []
    for index in range(len(control_value)):
        sort_key = control_value[index]
        ordering_rule = bytes(sort_key['orderingRule']) if sort_key['orderingRule'].hasValue() else None
        reverse_order = bool(sort_key['reverseOrder']) if sort_key['reverseOrder'].hasValue() else False
        sort_keys.append({'attr': str(sort_key['attributeType']),
                          'ordering_rule': str(ordering_rule, 'utf-8') if ordering_rule is not None else None,
                          'reverse_order': reverse_order})

    return sort_keys


def sort_response_to_dict(control_value):
    """
    Decodes a sort response control value into a dictionary:
    {'result': sortResult code, 'attr': attribute_type or None}
    """
    if isinstance(control_value, dict):  # already decoded by the strategy control decoder
        return control_value

    if isinstance(control_value, (bytes, bytearray)):
        try:
            control_value, unprocessed = decoder.decode(bytes(control_value), asn1Spec=SortResponseControlValue())
        except PyAsn1Error as error:
            raise LDAPControlError('unable to decode sort response control: %s' % error)
        if unprocessed:
            raise LDAPControlError('unprocessed data in sort response control')

    attribute_type = None
    if 'attributeType' in control_value and control_value['attributeType'].hasValue():
        attribute_type = bytes(control_value['attributeType'])

    return {'result': int(control_value['sortResult']),
            'attr': str(attribute_type, 'utf-8') if attribute_type is not None else None}
