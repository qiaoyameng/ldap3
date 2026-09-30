"""
"""

# Created on 2026.09.30
#
# Author: Giovanni Cannata
#
# Copyright 2013 - 2025 Giovanni Cannata
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

from ..operation.search import parse_filter, compile_filter
from ..utils.conv import escape_filter_chars, to_unicode
from ..core.exceptions import LDAPControlError
from .controls import build_control


def assertion_control(search_filter, criticality=True, schema=None, auto_escape=True, auto_encode=False, validator=None, check_names=False):
    """Create an Assertion control as per RFC 4528 for a request.
    When passed as a control to the controls parameter of an operation, the
    server evaluates the search_filter against the target entry before
    performing the operation; if the filter doesn't match the operation is
    not performed and the assertionFailed (122) result code is returned.
    The control is critical by default so that a server that doesn't support
    it refuses the operation instead of silently ignoring the assertion.
    """
    filter_value = compile_filter(parse_filter(search_filter, schema, auto_escape, auto_encode, validator, check_names).elements[0])
    return build_control('1.3.6.1.1.12', criticality, filter_value)


def _read_tlv(data, pos):
    # reads a BER TLV triplet, returns (tag, content, next_pos)
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:  # long form
        num_octets = length & 0x7F
        length = 0
        for i in range(num_octets):
            length = (length << 8) | data[pos + i]
        pos += num_octets
    return tag, data[pos:pos + length], pos + length


def _escape_value(value):
    try:
        return escape_filter_chars(to_unicode(value, from_server=True))
    except UnicodeError:
        return escape_filter_chars(bytes(value))


def _filter_component_to_string(data, pos=0):
    # converts a BER encoded Filter (as per RFC 4511) to its string representation (as per RFC 4515)
    tag, content, next_pos = _read_tlv(data, pos)
    tag_class = tag & 0xC0
    tag_type = tag & 0x1F
    if tag_class != 0x80:  # only context specific tags are valid in a Filter
        raise LDAPControlError('invalid tag in assertion control filter')
    if tag_type == 0:  # and [0] SET OF Filter
        filter_string = '(&'
        child_pos = 0
        while child_pos < len(content):
            child_string, child_pos = _filter_component_to_string(content, child_pos)
            filter_string += child_string
        return filter_string + ')', next_pos
    elif tag_type == 1:  # or [1] SET OF Filter
        filter_string = '(|'
        child_pos = 0
        while child_pos < len(content):
            child_string, child_pos = _filter_component_to_string(content, child_pos)
            filter_string += child_string
        return filter_string + ')', next_pos
    elif tag_type == 2:  # not [2] Filter
        child_string, _ = _filter_component_to_string(content, 0)
        return '(!' + child_string + ')', next_pos
    elif tag_type in (3, 5, 6, 8):  # equalityMatch, greaterOrEqual, lessOrEqual, approxMatch AttributeValueAssertion
        operators = {3: '=', 5: '>=', 6: '<=', 8: '~='}
        _, attribute, ava_pos = _read_tlv(content, 0)
        _, value, _ = _read_tlv(content, ava_pos)
        return '(' + to_unicode(attribute, from_server=True) + operators[tag_type] + _escape_value(value) + ')', next_pos
    elif tag_type == 4:  # substrings [4] SubstringFilter
        _, attribute, seq_pos = _read_tlv(content, 0)
        _, substrings, _ = _read_tlv(content, seq_pos)
        filter_string = '(' + to_unicode(attribute, from_server=True) + '='
        child_pos = 0
        if child_pos >= len(substrings):
            raise LDAPControlError('invalid substrings in assertion control filter')
        while child_pos < len(substrings):
            sub_tag, sub_content, child_pos = _read_tlv(substrings, child_pos)
            sub_type = sub_tag & 0x1F
            if sub_type == 0:  # initial
                filter_string += _escape_value(sub_content) + '*'
            elif sub_type == 1:  # any
                if not filter_string.endswith('*'):
                    filter_string += '*'
                filter_string += _escape_value(sub_content) + '*'
            elif sub_type == 2:  # final
                filter_string += '*' + _escape_value(sub_content)
            else:
                raise LDAPControlError('invalid substring type in assertion control filter')
        return filter_string + ')', next_pos
    elif tag_type == 7:  # present [7] AttributeDescription
        return '(' + to_unicode(content, from_server=True) + '=*)', next_pos
    elif tag_type == 9:  # extensibleMatch [9] MatchingRuleAssertion
        matching_rule = attribute = value = None
        dn_attributes = False
        child_pos = 0
        while child_pos < len(content):
            child_tag, child_content, child_pos = _read_tlv(content, child_pos)
            child_type = child_tag & 0x1F
            if child_type == 1:
                matching_rule = to_unicode(child_content, from_server=True)
            elif child_type == 2:
                attribute = to_unicode(child_content, from_server=True)
            elif child_type == 3:
                value = child_content
            elif child_type == 4:
                dn_attributes = child_content != b'\\x00'
        filter_string = '('
        if attribute:
            filter_string += attribute
        if dn_attributes:
            filter_string += ':dn'
        if matching_rule:
            filter_string += ':' + matching_rule
        filter_string += ':='
        if value is not None:
            filter_string += _escape_value(value)
        return filter_string + ')', next_pos
    else:
        raise LDAPControlError('unknown filter component in assertion control')


def assertion_control_value_to_string(control_value):
    """Converts the value of an Assertion control (a BER encoded Filter as
    per RFC 4528) to its string representation as per RFC 4515."""
    filter_string, _ = _filter_component_to_string(bytes(control_value), 0)
    return filter_string
