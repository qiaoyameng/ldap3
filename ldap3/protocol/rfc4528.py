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

from ..core.exceptions import LDAPControlError
from ..operation.search import parse_filter, compile_filter
from ..utils.asn1 import decode_sequence, decode_octet_string, decode_boolean
from ..utils.conv import escape_filter_chars, escape_bytes, to_unicode
from .controls import build_control

ASSERTION_CONTROL_OID = '1.3.6.1.1.12'  # Assertion Control as per RFC 4528


def assertion_control(search_filter, criticality=True):
    """Create an Assertion Control as per RFC 4528. The control value is the
    BER encoding of a SearchFilter. The server evaluates the filter against
    the target entry before performing the operation and returns
    assertionFailed (122) if the filter doesn't match. As per RFC 4528 the
    criticality SHOULD be TRUE.
    """
    filter_root = parse_filter(search_filter, None, auto_escape=True, auto_encode=False, validator=None, check_names=False)
    return build_control(ASSERTION_CONTROL_OID, criticality, compile_filter(filter_root.elements[0]))


def decode_assertion_control_value(control_value):
    """Decode the controlValue of an Assertion Control (RFC 4528), a BER encoded
    SearchFilter, and return the equivalent LDAP filter string representation (RFC 4515).
    """
    decoded = decode_sequence(control_value, 0, len(control_value), FILTER_CONTEXT)
    if len(decoded) != 1:
        raise LDAPControlError('invalid filter in assertion control value')
    return decoded[0][3]


def _decode_and_filter(message, start, stop):
    return '(&' + ''.join(element[3] for element in decode_sequence(message, start, stop, FILTER_CONTEXT)) + ')'


def _decode_or_filter(message, start, stop):
    return '(|' + ''.join(element[3] for element in decode_sequence(message, start, stop, FILTER_CONTEXT)) + ')'


def _decode_not_filter(message, start, stop):
    return '(!' + decode_sequence(message, start, stop, FILTER_CONTEXT)[0][3] + ')'


def _decode_ava_filter(operator):
    def decode_ava(message, start, stop):
        decoded = decode_sequence(message, start, stop)
        return '(' + to_unicode(decoded[0][3]) + operator + _assertion_value_to_string(decoded[1][3]) + ')'
    return decode_ava


def _decode_present_filter(message, start, stop):
    return '(' + to_unicode(decode_octet_string(message, start, stop)) + '=*)'


def _decode_substrings_filter(message, start, stop):
    decoded = decode_sequence(message, start, stop, SUBSTRINGS_CONTEXT)
    parts = [(substring[2], _assertion_value_to_string(substring[3])) for substring in decoded[1][3]]
    substrings = '*'.join(part[1] for part in parts)
    if parts[0][0] != 0:  # no initial substring
        substrings = '*' + substrings
    if parts[-1][0] != 2:  # no final substring
        substrings += '*'
    return '(' + to_unicode(decoded[0][3]) + '=' + substrings + ')'


def _decode_extensible_filter(message, start, stop):
    decoded = decode_sequence(message, start, stop, EXTENSIBLE_MATCH_CONTEXT)
    attribute = None
    matching_rule = None
    dn_attributes = False
    match_value = b''
    for element in decoded:
        if element[2] == 1:  # matchingRule
            matching_rule = to_unicode(element[3])
        elif element[2] == 2:  # type
            attribute = to_unicode(element[3])
        elif element[2] == 3:  # matchValue
            match_value = element[3]
        elif element[2] == 4:  # dnAttributes
            dn_attributes = bool(element[3])
    extensible_filter = '(' + (attribute if attribute else '')
    if dn_attributes:
        extensible_filter += ':dn'
    if matching_rule:
        extensible_filter += ':' + matching_rule
    extensible_filter += ':=' + _assertion_value_to_string(match_value) + ')'
    return extensible_filter


def _assertion_value_to_string(assertion_value):
    try:
        return escape_filter_chars(to_unicode(assertion_value))
    except UnicodeDecodeError:
        return to_unicode(escape_bytes(assertion_value))


SUBSTRINGS_CONTEXT = {
    0: decode_octet_string,  # initial
    1: decode_octet_string,  # any
    2: decode_octet_string  # final
}

EXTENSIBLE_MATCH_CONTEXT = {
    1: decode_octet_string,  # matchingRule
    2: decode_octet_string,  # type
    3: decode_octet_string,  # matchValue
    4: decode_boolean  # dnAttributes
}

FILTER_CONTEXT = {
    0: _decode_and_filter,  # and
    1: _decode_or_filter,  # or
    2: _decode_not_filter,  # not
    3: _decode_ava_filter('='),  # equalityMatch
    4: _decode_substrings_filter,  # substrings
    5: _decode_ava_filter('>='),  # greaterOrEqual
    6: _decode_ava_filter('<='),  # lessOrEqual
    7: _decode_present_filter,  # present
    8: _decode_ava_filter('~='),  # approxMatch
    9: _decode_extensible_filter  # extensibleMatch
}
