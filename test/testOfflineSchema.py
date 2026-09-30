"""
"""

# Created on 2013.09.13
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

import unittest

from ldap3 import Server, OFFLINE_EDIR_9_1_4, SchemaInfo, DsaInfo
from ldap3.core.exceptions import LDAPSchemaError
from ldap3.protocol.rfc4512 import ObjectClassInfo, AttributeTypeInfo
from test.config import test_server, get_connection, drop_connection


class Test(unittest.TestCase):
    def setUp(self):
        self.connection = get_connection(get_info=OFFLINE_EDIR_9_1_4)

    def tearDown(self):
        drop_connection(self.connection)
        self.assertFalse(self.connection.bound)

    def test_offline_schema(self):
        if not self.connection.strategy.pooled:
            if not self.connection.server.schema:
                self.connection.refresh_server_info()
            self.assertEqual(type(self.connection.server.schema), SchemaInfo)

    def test_object_classes(self):
        if not self.connection.strategy.pooled:
            if not self.connection.server.info:
                self.connection.refresh_server_info()
            self.assertEqual(type(self.connection.server.schema.object_classes['inetOrgPerson']), ObjectClassInfo)

    def test_attributes_types(self):
        if not self.connection.strategy.pooled:
            if not self.connection.server.info:
                self.connection.refresh_server_info()
            self.assertEqual(type(self.connection.server.schema.attribute_types['cn']), AttributeTypeInfo)

    def test_json_definition(self):
        if not self.connection.strategy.pooled:
            if not self.connection.server.info:
                self.connection.refresh_server_info()
            json_info = self.connection.server.info.to_json()
            json_schema = self.connection.server.schema.to_json()
            info = DsaInfo.from_json(json_info)
            schema = SchemaInfo.from_json(json_schema)
            server1 = Server.from_definition(test_server, info, schema)
            json_info1 = server1.info.to_json()
            json_schema1 = server1.schema.to_json()
            self.assertEqual(json_info, json_info1)
            self.assertEqual(json_schema, json_schema1)


class TestEffectiveSchema(unittest.TestCase):
    @staticmethod
    def schema_from_definitions(attributes, classes):
        return SchemaInfo('cn=schema',
                          dict(attributeTypes=attributes, objectClasses=classes),
                          dict())

    @staticmethod
    def valid_schema():
        attributes = [
            "( 1.1 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            "( 1.2 NAME ( 'uid' 'userid' ) SUP 1.1 SINGLE-VALUE )",
            "( 1.3 NAME 'mail' )",
            "( 1.4 NAME 'phone' SUP 1.2 )",
            "( 1.5 NAME 'displayName' )",
        ]
        classes = [
            "( 2.1 NAME 'top' ABSTRACT MUST cn )",
            "( 2.2 NAME 'base' SUP top STRUCTURAL MUST uid MAY mail )",
            "( 2.3 NAME 'leaf' SUP base STRUCTURAL MAY phone )",
            "( 2.4 NAME 'namedAux' AUXILIARY MAY displayName )",
        ]
        return TestEffectiveSchema.schema_from_definitions(attributes, classes)

    def test_effective_must_may_sources_and_single_value(self):
        definition = self.valid_schema().get_effective_definition(['leaf'], ['namedAux'])

        self.assertTrue(definition.valid)
        self.assertEqual(sorted(definition.must), ['cn', 'uid'])
        self.assertEqual(sorted(definition.may), ['displayName', 'mail', 'phone'])

        uid = definition.attributes['userid']
        self.assertIs(uid, definition.attributes['uid'])
        self.assertEqual(uid.oid, '1.2')
        self.assertEqual(uid.names, ['uid', 'userid'])
        self.assertEqual(uid.aliases, ['userid'])
        self.assertTrue(uid.single_value)
        self.assertTrue(uid.mandatory)
        self.assertEqual(uid.sources[0].path, ['leaf', 'base'])

        phone = definition.attributes['phone']
        self.assertTrue(phone.single_value)
        self.assertEqual(phone.oid, '1.4')
        self.assertEqual(phone.names, ['phone'])

    def test_same_oid_aliases_are_merged(self):
        schema = self.schema_from_definitions([
            "( 1.1 NAME 'cn' )",
            "( 1.1 NAME 'commonName' )",
        ], [
            "( 2.1 NAME 'top' ABSTRACT )",
            "( 2.2 NAME 'person' SUP top STRUCTURAL MUST cn MAY commonName )",
        ])

        definition = schema.get_effective_definition(['person'])

        self.assertTrue(definition.valid)
        self.assertIs(definition.attributes['cn'], definition.attributes['commonName'])
        self.assertEqual(definition.attributes['cn'].oid, '1.1')
        self.assertEqual(definition.attributes['cn'].names, ['cn', 'commonName'])

    def test_must_overrides_may_and_oid_is_queryable(self):
        schema = self.schema_from_definitions([
            "( 1.1 NAME 'cn' )",
            "( 1.2 NAME 'mail' )",
        ], [
            "( 2.1 NAME 'top' ABSTRACT MUST cn MAY mail )",
            "( 2.2 NAME 'person' SUP top STRUCTURAL MUST mail )",
        ])

        definition = schema.get_effective_definition(['person'])

        self.assertIn('mail', definition.must)
        self.assertNotIn('mail', definition.may)
        self.assertIs(definition.attributes['1.2'], definition.attributes['mail'])
        self.assertTrue(definition.attributes['mail'].mandatory)

    def test_structural_and_inheritance_errors_keep_all_attributes(self):
        schema = self.schema_from_definitions([
            "( 1.1 NAME 'cn' )",
            "( 1.2 NAME 'uid' )",
            "( 1.3 NAME 'cycleA' SUP 1.4 )",
            "( 1.4 NAME 'cycleB' SUP 1.3 )",
            "( 1.5 NAME 'brokenAttr' SUP 9.9 )",
        ], [
            "( 2.1 NAME 'top' ABSTRACT MUST cn )",
            "( 2.2 NAME 'person' SUP top STRUCTURAL MUST uid )",
            "( 2.3 NAME 'device' SUP top STRUCTURAL )",
            "( 2.4 NAME 'broken' SUP missingSuperior STRUCTURAL MAY brokenAttr )",
            "( 2.5 NAME 'cycleA' SUP cycleB AUXILIARY MAY cycleA )",
            "( 2.6 NAME 'cycleB' SUP cycleA AUXILIARY )",
        ])

        definition = schema.get_effective_definition(['person', 'device', 'broken'], ['cycleA'])

        self.assertFalse(definition.valid)
        self.assertEqual(sorted(definition.must), ['cn', 'uid'])
        self.assertIn('brokenAttr', definition.may)
        self.assertIn('cycleA', definition.may)

        error_types = [error['type'] for error in definition.errors]
        self.assertIn('incompatible_structural_classes', error_types)
        self.assertIn('unknown_superior', error_types)
        self.assertIn('object_class_inheritance_cycle', error_types)
        self.assertIn('unknown_attribute_superior', error_types)

        incompatible = next(error for error in definition.errors
                            if error['type'] == 'incompatible_structural_classes')
        self.assertEqual(incompatible['object_classes'], ['person', 'device', 'broken'])
        self.assertIn(['person', 'top'], incompatible['paths'])
        self.assertIn(['device', 'top'], incompatible['paths'])
        self.assertIn(['broken', 'missingSuperior'], incompatible['paths'])

        unknown_superior = next(error for error in definition.errors
                                if error['type'] == 'unknown_superior')
        self.assertEqual(unknown_superior['path'], ['broken', 'missingSuperior'])

        class_cycle = next(error for error in definition.errors
                           if error['type'] == 'object_class_inheritance_cycle')
        self.assertEqual(class_cycle['path'], ['cycleA', 'cycleB', 'cycleA'])

    def test_attribute_inheritance_cycle_path(self):
        schema = self.schema_from_definitions([
            "( 1.6 NAME 'cyclicA' SUP 1.7 )",
            "( 1.7 NAME 'cyclicB' SUP 1.6 )",
        ], [
            "( 2.7 NAME 'cyclicAux' AUXILIARY MAY cyclicA )",
        ])

        definition = schema.get_effective_definition(None, ['cyclicAux'])

        self.assertEqual(definition.errors[0]['type'], 'attribute_inheritance_cycle')
        self.assertEqual(definition.errors[0]['path'], ['cyclicA', 'cyclicB', 'cyclicA'])

    def test_strict_returns_definition_with_exception(self):
        schema = self.schema_from_definitions([], [
            "( 2.1 NAME 'person' SUP missing STRUCTURAL )",
        ])

        with self.assertRaises(LDAPSchemaError) as ctx:
            schema.get_effective_definition(['person'], strict=True)

        self.assertEqual(ctx.exception.effective_schema.errors[0]['type'], 'unknown_superior')
