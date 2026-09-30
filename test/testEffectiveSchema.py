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

import unittest

from ldap3 import Server, Connection, OFFLINE_SLAPD_2_4, OFFLINE_AD_2012_R2, OFFLINE_DS389_1_3_3
from ldap3.protocol.rfc4512 import SchemaInfo
from ldap3.abstract.effectiveSchema import (get_effective_schema,
                                            EffectiveSchemaDefinition,
                                            EffectiveAttributeDefinition,
                                            LDAPEffectiveSchemaError,
                                            UNKNOWN_OBJECT_CLASS,
                                            UNKNOWN_SUPERIOR_CLASS,
                                            OBJECT_CLASS_CYCLE,
                                            INCOMPATIBLE_STRUCTURAL_CLASSES,
                                            UNKNOWN_ATTRIBUTE_TYPE,
                                            UNKNOWN_SUPERIOR_ATTRIBUTE,
                                            ATTRIBUTE_TYPE_CYCLE,
                                            MUST, MAY)


def build_schema(attribute_types, object_classes):
    raw = {'attributeTypes': list(attribute_types), 'objectClasses': list(object_classes)}
    attributes = {'attributeTypes': list(raw['attributeTypes']), 'objectClasses': list(raw['objectClasses'])}
    return SchemaInfo('cn=schema', attributes, raw)


PERSON_ATTRIBUTES = [
    "( 1.1.1 NAME 'topAttr' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
    "( 1.1.2 NAME 'commonName' SUP 1.1.1 )",
    "( 1.1.3 NAME 'cn' SUP commonName )",
    "( 1.1.4 NAME ( 'sn' 'surname' ) SUP 1.1.1 SINGLE-VALUE )",
    "( 1.1.5 NAME 'givenName' )",
    "( 1.1.6 NAME 'mail' )",
    "( 1.1.7 NAME 'employeeNumber' SINGLE-VALUE )",
    "( 1.1.8 NAME 'o' )",
    "( 1.1.9 NAME 'ou' )",
    "( 1.1.10 NAME 'displayName' )",
    "( 1.1.11 NAME 'postalCode' )",
    "( 1.1.12 NAME 'fooAttr' )",
]

PERSON_CLASSES = [
    "( 2.1 NAME 'top' ABSTRACT MUST topAttr )",
    "( 2.2 NAME 'person' SUP top STRUCTURAL MUST ( commonName $ sn ) MAY givenName )",
    "( 2.3 NAME 'organizationalPerson' SUP person STRUCTURAL MUST postalCode MAY ( o $ ou $ employeeNumber ) )",
    "( 2.4 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( mail $ displayName ) )",
    "( 2.5 NAME 'emailUser' AUXILIARY MAY mail )",
    "( 2.6 NAME 'device' SUP top STRUCTURAL MUST fooAttr )",
]


class TestEffectiveSchemaMerging(unittest.TestCase):
    def setUp(self):
        self.schema = build_schema(PERSON_ATTRIBUTES, PERSON_CLASSES)

    def test_returns_effective_definition(self):
        effective = get_effective_schema(self.schema, 'inetOrgPerson')
        self.assertIsInstance(effective, EffectiveSchemaDefinition)

    def test_must_merged_along_inheritance_chain(self):
        effective = get_effective_schema(self.schema, 'inetOrgPerson')
        mandatory = sorted(name for name in effective.mandatory_attributes)
        self.assertEqual(mandatory, ['commonName', 'postalCode', 'sn', 'topAttr'])

    def test_may_merged_along_inheritance_chain(self):
        effective = get_effective_schema(self.schema, 'inetOrgPerson')
        optional = sorted(name for name in effective.optional_attributes)
        self.assertEqual(optional, ['displayName', 'employeeNumber', 'givenName', 'mail', 'o', 'ou'])

    def test_auxiliary_class_attributes_merged(self):
        effective = get_effective_schema(self.schema, 'inetOrgPerson', 'emailUser')
        self.assertIn('mail', effective.attributes)
        self.assertIn('emailUser', effective.auxiliary_classes)

    def test_must_wins_over_may_across_classes(self):
        schema = build_schema(["( 9.9.1 NAME 'x' )"],
                              ["( 9.1 NAME 'a' AUXILIARY MAY x )",
                               "( 9.2 NAME 'b' AUXILIARY MUST x )"])
        effective = get_effective_schema(schema, 'a', 'b')
        self.assertTrue(effective.attributes['x'].mandatory)

    def test_same_lineage_structural_classes_are_compatible(self):
        schema = build_schema(["( 1.1.5 NAME 'givenName' )"],
                              ["( 2.1 NAME 'top' ABSTRACT )",
                               "( 2.2 NAME 'person' SUP top STRUCTURAL MUST givenName )",
                               "( 2.3 NAME 'organizationalPerson' SUP person STRUCTURAL )"])
        effective = get_effective_schema(schema, ['person', 'organizationalPerson'])
        self.assertTrue(effective.is_valid)

    def test_class_kind_lists(self):
        effective = get_effective_schema(self.schema, 'inetOrgPerson', 'emailUser')
        self.assertEqual(effective.structural_classes, ['inetOrgPerson', 'organizationalPerson', 'person'])
        self.assertEqual(effective.abstract_classes, ['top'])
        self.assertEqual(effective.auxiliary_classes, ['emailUser'])


class TestEffectiveSchemaAliasesAndAttributes(unittest.TestCase):
    def setUp(self):
        self.schema = build_schema(PERSON_ATTRIBUTES, PERSON_CLASSES)

    def test_aliases_resolve_to_same_attribute(self):
        effective = get_effective_schema(self.schema, 'person')
        self.assertIs(effective.attributes['sn'], effective.attributes['surname'])
        self.assertEqual(effective.attributes['sn'].oid, '1.1.4')

    def test_same_oid_different_aliases_merged(self):
        schema = build_schema(
            ["( 14.1 NAME ( 'alpha' 'aleph' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
             "( 14.1 NAME 'alphaFirst' SINGLE-VALUE )"],
            ["( 24.1 NAME 'oc' STRUCTURAL MUST alpha )"])
        effective = get_effective_schema(schema, 'oc')
        self.assertEqual(effective.attributes['aleph'].oid, '14.1')
        self.assertEqual(effective.attributes['alphaFirst'].oid, '14.1')
        self.assertIs(effective.attributes['alpha'], effective.attributes['aleph'])
        self.assertTrue(effective.attributes['alpha'].single_value)
        self.assertTrue({'alpha', 'aleph', 'alphaFirst'}.issubset(set(effective.attributes['alpha'].names)))

    def test_oid_reference_resolves(self):
        schema = build_schema(["( 15.1 NAME 'byOid' )"],
                              ["( 25.1 NAME 'oc' STRUCTURAL MUST 15.1 )"])
        effective = get_effective_schema(schema, 'oc')
        self.assertIn('byOid', effective.attributes)
        self.assertIn('15.1', effective.attributes)
        self.assertEqual(effective.attributes['15.1'].oid, '15.1')

    def test_single_value_direct(self):
        effective = get_effective_schema(self.schema, 'organizationalPerson')
        self.assertTrue(effective.attributes['employeeNumber'].single_value)
        self.assertEqual(effective.attributes['employeeNumber'].single_value_source, 'employeeNumber')

    def test_single_value_inherited_from_parent(self):
        schema = build_schema(
            ["( 10.1 NAME 'c' SINGLE-VALUE )",
             "( 10.2 NAME 'b' SUP c )",
             "( 10.3 NAME 'a' SUP b )",
             "( 10.4 NAME 'plain' )"],
            ["( 20.1 NAME 'oc' STRUCTURAL MUST a MAY plain )"])
        effective = get_effective_schema(schema, 'oc')
        self.assertTrue(effective.attributes['a'].single_value)
        self.assertEqual(effective.attributes['a'].single_value_source, 'c')
        self.assertFalse(effective.attributes['plain'].single_value)

    def test_syntax_inherited(self):
        effective = get_effective_schema(self.schema, 'person')
        self.assertEqual(effective.attributes['commonName'].syntax, '1.3.6.1.4.1.1466.115.121.1.15')

    def test_provenance_sources_recorded(self):
        effective = get_effective_schema(self.schema, 'inetOrgPerson', 'emailUser')
        mail = effective.attributes['mail']
        sources = [(source['object_class'], source['requirement']) for source in mail.sources]
        self.assertIn(('inetOrgPerson', MAY), sources)
        self.assertIn(('emailUser', MAY), sources)
        cn = effective.attributes['commonName']
        must_sources = [source for source in cn.sources if source['requirement'] == MUST]
        self.assertTrue(any('person' in source['path'] for source in must_sources))


class TestEffectiveSchemaErrors(unittest.TestCase):
    def test_unknown_object_class_strict(self):
        schema = build_schema([], [])
        with self.assertRaises(LDAPEffectiveSchemaError) as cm:
            get_effective_schema(schema, 'nope')
        self.assertEqual(cm.exception.issues[0].code, UNKNOWN_OBJECT_CLASS)
        self.assertEqual(cm.exception.issues[0].paths, [['nope']])

    def test_unknown_object_class_non_strict(self):
        schema = build_schema([], [])
        effective = get_effective_schema(schema, 'nope', strict=False)
        self.assertEqual(effective.issues[0].code, UNKNOWN_OBJECT_CLASS)
        self.assertFalse(effective.is_valid)

    def test_incompatible_structural_classes_full_paths(self):
        schema = build_schema(PERSON_ATTRIBUTES, PERSON_CLASSES)
        with self.assertRaises(LDAPEffectiveSchemaError) as cm:
            get_effective_schema(schema, ['inetOrgPerson', 'device'])
        issue = next(issue for issue in cm.exception.issues if issue.code == INCOMPATIBLE_STRUCTURAL_CLASSES)
        paths = issue.paths
        self.assertEqual(paths[0], ['inetOrgPerson', 'organizationalPerson', 'person'])
        self.assertEqual(paths[1], ['device'])
        # attributes are still computed, nothing dropped
        partial = cm.exception.effective_schema
        self.assertIn('commonName', partial.attributes)
        self.assertIn('fooAttr', partial.attributes)

    def test_multi_superior_structural_conflict(self):
        schema = build_schema(
            ["( 18.1 NAME 'z' )"],
            ["( 28.1 NAME 'r1' STRUCTURAL )",
             "( 28.2 NAME 'r2' STRUCTURAL )",
             "( 28.3 NAME 'multi' SUP ( r1 $ r2 ) STRUCTURAL MUST z )"])
        effective = get_effective_schema(schema, 'multi', strict=False)
        codes = [issue.code for issue in effective.issues]
        self.assertIn(INCOMPATIBLE_STRUCTURAL_CLASSES, codes)

    def test_unknown_superior_class_keeps_own_attributes(self):
        schema = build_schema(
            ["( 30.1 NAME 'mail' )"],
            ["( 30.2 NAME 'orphan' SUP missingParent STRUCTURAL MAY mail )"])
        effective = get_effective_schema(schema, 'orphan', strict=False)
        issue = next(issue for issue in effective.issues if issue.code == UNKNOWN_SUPERIOR_CLASS)
        self.assertEqual(issue.paths[0], ['orphan', 'missingParent'])
        self.assertIn('mail', effective.attributes)

    def test_object_class_cycle_reports_full_path(self):
        schema = build_schema(
            ["( 31.1 NAME 'a' )"],
            ["( 31.2 NAME 'cycA' SUP cycB STRUCTURAL MUST a )",
             "( 31.3 NAME 'cycB' SUP cycA STRUCTURAL )"])
        effective = get_effective_schema(schema, 'cycA', strict=False)
        issue = next(issue for issue in effective.issues if issue.code == OBJECT_CLASS_CYCLE)
        flattened = [name for path in issue.paths for name in path]
        self.assertIn('cycA', flattened)
        self.assertIn('cycB', flattened)
        # attributes collected before/after the cycle edge are not lost
        self.assertIn('a', effective.attributes)

    def test_unknown_attribute_referenced_not_dropped(self):
        schema = build_schema(
            ["( 32.1 NAME 'known' )"],
            ["( 32.2 NAME 'oc' STRUCTURAL MUST ( known $ mystery ) )"])
        effective = get_effective_schema(schema, 'oc', strict=False)
        issue = next(issue for issue in effective.issues if issue.code == UNKNOWN_ATTRIBUTE_TYPE)
        self.assertEqual(issue.references, ['mystery'])
        self.assertIn('mystery', effective.attributes)
        self.assertFalse(effective.attributes['mystery'].known)
        self.assertTrue(effective.attributes['mystery'].mandatory)

    def test_unknown_superior_attribute(self):
        schema = build_schema(
            ["( 33.1 NAME 'd' SUP ghost )"],
            ["( 33.2 NAME 'oc' STRUCTURAL MUST d )"])
        effective = get_effective_schema(schema, 'oc', strict=False)
        self.assertTrue(any(issue.code == UNKNOWN_SUPERIOR_ATTRIBUTE for issue in effective.issues))
        self.assertIn('d', effective.attributes)

    def test_attribute_type_cycle(self):
        schema = build_schema(
            ["( 34.1 NAME 'a2' SUP b2 )",
             "( 34.2 NAME 'b2' SUP a2 )"],
            ["( 34.3 NAME 'oc' STRUCTURAL MUST a2 )"])
        effective = get_effective_schema(schema, 'oc', strict=False)
        issue = next(issue for issue in effective.issues if issue.code == ATTRIBUTE_TYPE_CYCLE)
        flattened = [name for path in issue.paths for name in path]
        self.assertIn('a2', flattened)
        self.assertIn('b2', flattened)
        self.assertIn('a2', effective.attributes)

    def test_all_issues_collected_together(self):
        schema = build_schema(
            ["( 35.1 NAME 'x' )"],
            ["( 35.2 NAME 'ok' AUXILIARY MAY x )"])
        with self.assertRaises(LDAPEffectiveSchemaError) as cm:
            get_effective_schema(schema, ['missingOne', 'missingTwo', 'ok'])
        codes = [issue.code for issue in cm.exception.issues]
        self.assertEqual(codes.count(UNKNOWN_OBJECT_CLASS), 2)


class TestEffectiveSchemaBundledOffline(unittest.TestCase):
    def _schema(self, get_info):
        server = Server('host.invalid', get_info=get_info)
        connection = Connection(server)
        connection.refresh_server_info()
        self.assertIsNotNone(server.schema)
        return server.schema

    def test_slapd_inetorgperson(self):
        schema = self._schema(OFFLINE_SLAPD_2_4)
        effective = schema.get_effective_schema('inetOrgPerson')
        self.assertTrue(effective.is_valid, [str(issue) for issue in effective.issues])
        self.assertIn('cn', effective.attributes)
        self.assertIn('sn', effective.attributes)
        self.assertTrue(effective.attributes['cn'].mandatory)
        self.assertIsInstance(effective.attributes['cn'], EffectiveAttributeDefinition)

    def test_ad_user_with_auxiliary(self):
        schema = self._schema(OFFLINE_AD_2012_R2)
        effective = get_effective_schema(schema, 'user')
        self.assertTrue(effective.is_valid, [str(issue) for issue in effective.issues])
        self.assertIn('objectCategory', effective.attributes)
        self.assertTrue(effective.attributes['objectCategory'].mandatory)
        self.assertIn('cn', effective.attributes)
        self.assertTrue(effective.attributes['cn'].mandatory)
        self.assertIn('distinguishedName', effective.attributes)
        self.assertFalse(effective.attributes['distinguishedName'].mandatory)

    def test_ds389_inetorgperson(self):
        server = Server('host.invalid', get_info=OFFLINE_DS389_1_3_3)
        connection = Connection(server)
        connection.refresh_server_info()
        effective = get_effective_schema(connection, 'inetOrgPerson')
        self.assertTrue(effective.is_valid, [str(issue) for issue in effective.issues])
        self.assertIn('cn', effective.attributes)

    def test_repr_contains_must_may(self):
        schema = self._schema(OFFLINE_SLAPD_2_4)
        effective = schema.get_effective_schema('inetOrgPerson')
        text = repr(effective)
        self.assertIn('MUST attributes', text)
        self.assertIn('cn', text)


if __name__ == '__main__':
    unittest.main()
