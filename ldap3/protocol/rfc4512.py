"""
"""

# Created on 2013.09.11
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

from os import linesep
import re
import json

from .oid import CLASS_ABSTRACT, CLASS_STRUCTURAL, CLASS_AUXILIARY, ATTRIBUTE_USER_APPLICATION, \
    ATTRIBUTE_DIRECTORY_OPERATION, ATTRIBUTE_DISTRIBUTED_OPERATION, ATTRIBUTE_DSA_OPERATION
from .. import SEQUENCE_TYPES, STRING_TYPES, get_config_parameter
from ..utils.conv import escape_bytes, json_hook, check_json_dict, format_json, to_unicode
from ..utils.ciDict import CaseInsensitiveWithAliasDict
from ..protocol.formatters.standard import format_attribute_values
from .oid import Oids, decode_oids, decode_syntax, oid_to_string
from ..core.exceptions import LDAPSchemaError, LDAPDefinitionError


def constant_to_class_kind(value):
    if value == CLASS_STRUCTURAL:
        return 'Structural'
    elif value == CLASS_ABSTRACT:
        return 'Abstract'
    elif value == CLASS_AUXILIARY:
        return 'Auxiliary'
    else:
        return '<unknown>'


def constant_to_attribute_usage(value):
    if value == ATTRIBUTE_USER_APPLICATION:
        return 'User Application'
    elif value == ATTRIBUTE_DIRECTORY_OPERATION:
        return "Directory operation"
    elif value == ATTRIBUTE_DISTRIBUTED_OPERATION:
        return 'Distributed operation'
    elif value == ATTRIBUTE_DSA_OPERATION:
        return 'DSA operation'
    else:
        return 'unknown'


def attribute_usage_to_constant(value):
    if value == 'userApplications':
        return ATTRIBUTE_USER_APPLICATION
    elif value == 'directoryOperation':
        return ATTRIBUTE_DIRECTORY_OPERATION
    elif value == 'distributedOperation':
        return ATTRIBUTE_DISTRIBUTED_OPERATION
    elif value == 'dSAOperation':
        return ATTRIBUTE_DSA_OPERATION
    else:
        return 'unknown'


def quoted_string_to_list(quoted_string):
    string = quoted_string.strip()
    if not string:
        return list()

    if string[0] == '(' and string[-1] == ')':
        string = string[1:-1]
    elements = string.split("'")
    # return [check_escape(element.strip("'").strip()) for element in elements if element.strip()]
    return [element.strip("'").strip() for element in elements if element.strip()]


def oids_string_to_list(oid_string):
    string = oid_string.strip()
    if string[0] == '(' and string[-1] == ')':
        string = string[1:-1]
    elements = string.split('$')
    return [element.strip() for element in elements if element.strip()]


def extension_to_tuple(extension_string):
    string = extension_string.strip()
    name, _, values = string.partition(' ')
    return name, quoted_string_to_list(values)


def list_to_string(list_object):
    if not isinstance(list_object, SEQUENCE_TYPES):
        return list_object

    r = ''
    for element in list_object:
        r += (list_to_string(element) if isinstance(element, SEQUENCE_TYPES) else str(element)) + ', '

    return r[:-2] if r else ''


class EffectiveSchemaSource(object):
    """Origin of an attribute requirement in an effective object class definition."""

    def __init__(self, requirement, object_class, path, reference=None):
        self.requirement = requirement
        self.object_class = object_class
        self.path = path
        self.reference = reference

    def __repr__(self):
        return 'EffectiveSchemaSource(%r, %r, %r)' % (self.requirement, self.object_class, self.path)


class EffectiveSchemaAttribute(object):
    """Effective attribute type after following attribute supertype constraints."""

    def __init__(self, oid, names=None, single_value=False, syntax=None, definition=None):
        self.oid = oid
        self.names = names or []
        self.aliases = self.names[1:] if self.names else []
        self.single_value = single_value
        self.syntax = syntax
        self.definition = definition
        self.sources = []

    @property
    def mandatory(self):
        return any(source.requirement == 'MUST' for source in self.sources)

    @property
    def may(self):
        return any(source.requirement == 'MAY' for source in self.sources)

    def __repr__(self):
        return 'EffectiveSchemaAttribute(%r, %r, single_value=%r)' % (self.oid, self.names, self.single_value)


class EffectiveSchemaDefinition(object):
    """Required and optional attributes allowed by a set of LDAP object classes."""

    def __init__(self, object_classes=None, auxiliary_classes=None, attributes=None, errors=None):
        self.object_classes = object_classes or []
        self.auxiliary_classes = auxiliary_classes or []
        self.attributes = attributes or CaseInsensitiveWithAliasDict()
        self.must = CaseInsensitiveWithAliasDict()
        self.may = CaseInsensitiveWithAliasDict()
        self.errors = errors or []

    @property
    def mandatory_attributes(self):
        return self.must

    @property
    def optional_attributes(self):
        return self.may

    @property
    def required_attributes(self):
        return self.must

    @property
    def allowed_attributes(self):
        return self.attributes

    @property
    def valid(self):
        return not self.errors

    def __contains__(self, item):
        return item in self.attributes

    def __getitem__(self, item):
        return self.attributes[item]

    def __iter__(self):
        return iter(self.attributes)

    def __len__(self):
        return len(self.attributes)

    def __repr__(self):
        return 'EffectiveSchemaDefinition(must=%r, may=%r, errors=%r)' % (
            [attribute.names[0] if attribute.names else attribute.oid for attribute in self.must.values()],
            [attribute.names[0] if attribute.names else attribute.oid for attribute in self.may.values()],
            self.errors)


class BaseServerInfo(object):
    def __init__(self, raw_attributes):
        self.raw = dict(raw_attributes)

    @classmethod
    def from_json(cls, json_definition, schema=None, custom_formatter=None):
        conf_case_insensitive_schema = get_config_parameter('CASE_INSENSITIVE_SCHEMA_NAMES')
        definition = json.loads(json_definition, object_hook=json_hook)
        if 'raw' not in definition or 'type' not in definition:
            raise LDAPDefinitionError('invalid JSON definition')

        if conf_case_insensitive_schema:
            attributes = CaseInsensitiveWithAliasDict()
        else:
            attributes = dict()

        if schema:
            for attribute in definition['raw']:
                # attributes[attribute] = format_attribute_values(schema, check_escape(attribute), [check_escape(value) for value in definition['raw'][attribute]], custom_formatter)
                attributes[attribute] = format_attribute_values(schema, attribute, [value for value in definition['raw'][attribute]], custom_formatter)
        else:
            for attribute in definition['raw']:
                # attributes[attribute] = [check_escape(value) for value in definition['raw'][attribute]]
                attributes[attribute] = [value for value in definition['raw'][attribute]]

        if cls.__name__ != definition['type']:
            raise LDAPDefinitionError('JSON info not of type ' + cls.__name__)

        if definition['type'] == 'DsaInfo':
            return DsaInfo(attributes, definition['raw'])
        elif definition['type'] == 'SchemaInfo':
            if 'schema_entry' not in definition:
                raise LDAPDefinitionError('invalid schema in JSON')
            return SchemaInfo(definition['schema_entry'], attributes, definition['raw'])

        raise LDAPDefinitionError('invalid Info type ' + str(definition['type']) + ' in JSON definition')

    @classmethod
    def from_file(cls, target, schema=None, custom_formatter=None):
        if isinstance(target, STRING_TYPES):
            target = open(target, 'r')

        new = cls.from_json(target.read(), schema=schema, custom_formatter=custom_formatter)
        target.close()
        return new

    def to_file(self,
                target,
                indent=4,
                sort=True):
        if isinstance(target, STRING_TYPES):
            target = open(target, 'w+')

        target.writelines(self.to_json(indent=indent, sort=sort))
        target.close()

    def __str__(self):
        return self.__repr__()

    def to_json(self,
                indent=4,
                sort=True):
        json_dict = dict()
        json_dict['type'] = self.__class__.__name__
        json_dict['raw'] = self.raw

        if isinstance(self, SchemaInfo):
            json_dict['schema_entry'] = self.schema_entry
        elif isinstance(self, DsaInfo):
            pass
        else:
            raise LDAPDefinitionError('unable to convert ' + str(self) + ' to JSON')

        if str is bytes:  # Python 2
            check_json_dict(json_dict)

        return json.dumps(json_dict, ensure_ascii=False, sort_keys=sort, indent=indent, check_circular=True, default=format_json, separators=(',', ': '))


class DsaInfo(BaseServerInfo):
    """
    This class contains info about the ldap server (DSA) read from DSE
    as defined in RFC4512 and RFC3045. Unknown attributes are stored in the "other" dict
    """

    def __init__(self, attributes, raw_attributes):
        BaseServerInfo.__init__(self, raw_attributes)
        self.alt_servers = attributes.pop('altServer', None)
        self.naming_contexts = attributes.pop('namingContexts', None)
        self.supported_controls = decode_oids(attributes.pop('supportedControl', None))
        self.supported_extensions = decode_oids(attributes.pop('supportedExtension', None))
        self.supported_features = decode_oids(attributes.pop('supportedFeatures', None)) + decode_oids(attributes.pop('supportedCapabilities', None))
        self.supported_ldap_versions = attributes.pop('supportedLDAPVersion', None)
        self.supported_sasl_mechanisms = attributes.pop('supportedSASLMechanisms', None)
        self.vendor_name = attributes.pop('vendorName', None)
        self.vendor_version = attributes.pop('vendorVersion', None)
        self.schema_entry = attributes.pop('subschemaSubentry', None)
        self.other = attributes  # remaining schema definition attributes not in RFC4512

    def __repr__(self):
        r = 'DSA info (from DSE):' + linesep
        if self.supported_ldap_versions:
            if isinstance(self.supported_ldap_versions, SEQUENCE_TYPES):
                r += ('  Supported LDAP versions: ' + ', '.join([str(s) for s in self.supported_ldap_versions])) if self.supported_ldap_versions else ''
            else:
                r += ('  Supported LDAP versions: ' + str(self.supported_ldap_versions))
            r += linesep
        if self.naming_contexts:
            if isinstance(self.naming_contexts, SEQUENCE_TYPES):
                r += ('  Naming contexts: ' + linesep + linesep.join(['    ' + str(s) for s in self.naming_contexts])) if self.naming_contexts else ''
            else:
                r += ('  Naming contexts: ' + str(self.naming_contexts))
            r += linesep
        if self.alt_servers:
            if isinstance(self.alt_servers, SEQUENCE_TYPES):
                r += ('  Alternative servers: ' + linesep + linesep.join(['    ' + str(s) for s in self.alt_servers])) if self.alt_servers else ''
            else:
                r += ('  Alternative servers: ' + str(self.alt_servers))
            r += linesep
        if self.supported_controls:
            if isinstance(self.supported_controls, SEQUENCE_TYPES):
                r += ('  Supported controls: ' + linesep + linesep.join(['    ' + oid_to_string(s) for s in self.supported_controls])) if self.supported_controls else ''
            else:
                r += ('  Supported controls: ' + str(self.supported_controls))
            r += linesep
        if self.supported_extensions:
            if isinstance(self.supported_extensions, SEQUENCE_TYPES):
                r += ('  Supported extensions: ' + linesep + linesep.join(['    ' + oid_to_string(s) for s in self.supported_extensions])) if self.supported_extensions else ''
            else:
                r += ('  Supported extensions: ' + str(self.supported_extensions))
            r += linesep
        if self.supported_features:
            if self.supported_features:
                if isinstance(self.supported_features, SEQUENCE_TYPES):
                    r += ('  Supported features: ' + linesep + linesep.join(['    ' + oid_to_string(s) for s in self.supported_features])) if self.supported_features else ''
                else:
                    r += ('  Supported features: ' + str(self.supported_features))
                r += linesep
        if self.supported_sasl_mechanisms:
            if isinstance(self.supported_sasl_mechanisms, SEQUENCE_TYPES):
                r += ('  Supported SASL mechanisms: ' + linesep + '    ' + ', '.join([str(s) for s in self.supported_sasl_mechanisms])) if self.supported_sasl_mechanisms else ''
            else:
                r += ('  Supported SASL mechanisms: ' + str(self.supported_sasl_mechanisms))
            r += linesep
        if self.schema_entry:
            if isinstance(self.schema_entry, SEQUENCE_TYPES):
                r += ('  Schema entry: ' + linesep + linesep.join(['    ' + str(s) for s in self.schema_entry])) if self.schema_entry else ''
            else:
                r += ('  Schema entry: ' + str(self.schema_entry))
            r += linesep
        if self.vendor_name:
            if isinstance(self.vendor_name, SEQUENCE_TYPES) and len(self.vendor_name) == 1:
                r += 'Vendor name: ' + self.vendor_name[0]
            else:
                r += 'Vendor name: ' + str(self.vendor_name)
            r += linesep
        if self.vendor_version:
            if isinstance(self.vendor_version, SEQUENCE_TYPES) and len(self.vendor_version) == 1:
                r += 'Vendor version: ' + self.vendor_version[0]
            else:
                r += 'Vendor version: ' + str(self.vendor_version)
            r += linesep
        r += 'Other:' + linesep
        for k, v in self.other.items():
            r += '  ' + str(k) + ': ' + linesep
            try:
                r += (linesep.join(['    ' + str(s) for s in v])) if isinstance(v, SEQUENCE_TYPES) else str(v)
            except UnicodeDecodeError:
                r += (linesep.join(['    ' + str(escape_bytes(s)) for s in v])) if isinstance(v, SEQUENCE_TYPES) else str(escape_bytes(v))
            r += linesep
        return r


class SchemaInfo(BaseServerInfo):
    """
    This class contains info about the ldap server schema read from an entry (default entry is DSE)
    as defined in RFC4512. Unknown attributes are stored in the "other" dict
    """

    def __init__(self, schema_entry, attributes, raw_attributes):
        BaseServerInfo.__init__(self, raw_attributes)
        self.schema_entry = schema_entry
        self.create_time_stamp = attributes.pop('createTimestamp', None)
        self.modify_time_stamp = attributes.pop('modifyTimestamp', None)
        self.attribute_types = AttributeTypeInfo.from_definition(attributes.pop('attributeTypes', []))
        self.object_classes = ObjectClassInfo.from_definition(attributes.pop('objectClasses', []))
        self.matching_rules = MatchingRuleInfo.from_definition(attributes.pop('matchingRules', []))
        self.matching_rule_uses = MatchingRuleUseInfo.from_definition(attributes.pop('matchingRuleUse', []))
        self.dit_content_rules = DitContentRuleInfo.from_definition(attributes.pop('dITContentRules', []))
        self.dit_structure_rules = DitStructureRuleInfo.from_definition(attributes.pop('dITStructureRules', []))
        self.name_forms = NameFormInfo.from_definition(attributes.pop('nameForms', []))
        self.ldap_syntaxes = LdapSyntaxInfo.from_definition(attributes.pop('ldapSyntaxes', []))
        self.other = attributes  # remaining schema definition attributes not in RFC4512

        # links attributes to class objects
        if self.object_classes and self.attribute_types:
            for object_class in self.object_classes:  # CaseInsensitiveDict return keys while iterating
                for attribute in self.object_classes[object_class].must_contain:
                    try:
                        self.attribute_types[attribute].mandatory_in.append(object_class)
                    except KeyError:
                        pass
                for attribute in self.object_classes[object_class].may_contain:
                    try:
                        self.attribute_types[attribute].optional_in.append(object_class)
                    except KeyError:
                        pass

    @staticmethod
    def _as_name_list(values):
        if values is None:
            return []
        if not isinstance(values, SEQUENCE_TYPES):
            return [values]
        return list(values)

    @staticmethod
    def _extend_unique(target, values):
        for value in values:
            if value not in target:
                target.append(value)

    def _schema_index(self, definitions, include_attribute_properties=False):
        index = dict()
        seen = set()
        for definition in definitions.values():
            definition_id = id(definition)
            if definition_id in seen:
                continue
            seen.add(definition_id)
            entry = index.get(definition.oid)
            if entry is None:
                entry = dict(oid=definition.oid,
                             names=list(definition.name or []),
                             superior=list(definition.superior or []))
                if include_attribute_properties:
                    entry['single_value'] = bool(definition.single_value)
                    entry['syntax'] = definition.syntax
                else:
                    entry['kind'] = definition.kind
                    entry['must'] = list(definition.must_contain or [])
                    entry['may'] = list(definition.may_contain or [])
                index[definition.oid] = entry
            else:
                self._extend_unique(entry['names'], definition.name or [])
                self._extend_unique(entry['superior'], definition.superior or [])
                if include_attribute_properties:
                    entry['single_value'] = entry.get('single_value', False) or bool(definition.single_value)
                    if not entry.get('syntax') and definition.syntax:
                        entry['syntax'] = definition.syntax
                else:
                    if entry.get('kind') is None:
                        entry['kind'] = definition.kind
                    self._extend_unique(entry['must'], definition.must_contain or [])
                    self._extend_unique(entry['may'], definition.may_contain or [])
        return index

    @staticmethod
    def _resolve_reference(reference, definitions, index):
        if reference in definitions:
            definition = definitions[reference]
            return index.get(definition.oid)
        return index.get(reference)

    @staticmethod
    def _display_name(definition, reference):
        if definition and definition.get('names'):
            return definition['names'][0]
        return reference

    def _class_paths(self, reference, class_index, path=None):
        if path is None:
            path = []
        definition = class_index.get(reference)
        if definition is None or not isinstance(definition, dict):
            definition = self._resolve_reference(reference, self.object_classes, class_index)
        name = self._display_name(definition, reference)
        current_path = path + [name]
        if definition is None:
            return [current_path]
        if name in path:
            return [current_path]

        superior_paths = []
        for superior in definition['superior']:
            superior_paths.extend(self._class_paths(superior, class_index, current_path))
        return [current_path] + superior_paths

    def _structural_error(self, structural_classes, class_index):
        resolved = []
        for reference in structural_classes:
            definition = class_index.get(reference)
            if definition is None or not isinstance(definition, dict):
                definition = self._resolve_reference(reference, self.object_classes, class_index)
            resolved.append((reference, definition))
        resolved = [(reference, definition) for reference, definition in resolved
                    if definition and definition['kind'] == CLASS_STRUCTURAL]

        unique = []
        seen = set()
        for reference, definition in resolved:
            if definition['oid'] not in seen:
                seen.add(definition['oid'])
                unique.append((reference, definition))

        if len(unique) < 2:
            return None

        def reachable_oids(definition):
            oids = set()
            stack = [self._resolve_reference(superior, self.object_classes, class_index)
                     for superior in definition['superior']]
            visited = set()
            while stack:
                superior_definition = stack.pop()
                if superior_definition is None or superior_definition['oid'] in visited:
                    continue
                visited.add(superior_definition['oid'])
                oids.add(superior_definition['oid'])
                stack.extend([self._resolve_reference(candidate, self.object_classes, class_index)
                              for candidate in superior_definition['superior']])
            return oids

        candidates = []
        for pos, (reference, definition) in enumerate(unique):
            is_superior_of_another = False
            for other_pos, (_, other) in enumerate(unique):
                if pos != other_pos and definition['oid'] in reachable_oids(other):
                    is_superior_of_another = True
                    break
            if not is_superior_of_another:
                candidates.append((reference, definition))

        if len(candidates) < 2:
            return None

        return dict(type='incompatible_structural_classes',
                    object_classes=[self._display_name(definition, reference)
                                    for reference, definition in candidates],
                    paths=sum([self._class_paths(reference, class_index)
                               for reference, _ in candidates], []))

    def _resolve_attribute(self, reference, attribute_index, errors, seen_errors=None):
        if seen_errors is None:
            seen_errors = set()
        current = self._resolve_reference(reference, self.attribute_types, attribute_index)
        if current is None:
            return None

        current = current['oid']
        oid = current
        names = []
        single_value = False
        syntax = None
        path = []
        active = set()
        reported_errors = set()

        def add_attribute_error(error_type, **values):
            key = (error_type, values.get('superior'), tuple(values.get('path', [])))
            if key not in seen_errors and key not in reported_errors:
                reported_errors.add(key)
                error = dict(type=error_type)
                error.update(values)
                errors.append(error)

        while current:
            current_definition = attribute_index.get(current)
            if current_definition is None:
                add_attribute_error('unknown_attribute_superior',
                                    attribute=reference,
                                    superior=current,
                                    path=path + [current])
                break

            name = self._display_name(current_definition, current)
            if current_definition['oid'] in active:
                add_attribute_error('attribute_inheritance_cycle',
                                    attribute=reference,
                                    path=path + [name])
                break

            active.add(current_definition['oid'])
            path.append(name)
            if not names:
                names.extend(current_definition['names'] or [current_definition['oid']])
            single_value = single_value or current_definition['single_value']
            if syntax is None and current_definition.get('syntax'):
                syntax = current_definition['syntax']
            superior = current_definition['superior'][0] if current_definition['superior'] else None
            if superior:
                superior_definition = self._resolve_reference(superior, self.attribute_types, attribute_index)
                if superior_definition is None:
                    add_attribute_error('unknown_attribute_superior',
                                        attribute=reference,
                                        superior=superior,
                                        path=path + [superior])
                    break
                current = superior_definition['oid']
            else:
                current = None

        return dict(oid=oid, names=names, single_value=single_value, syntax=syntax)

    @staticmethod
    def _add_alias_dictionary(target, name, aliases, value):
        if name not in target:
            target[name] = value
            valid_aliases = []
            for alias in aliases:
                if alias != name and alias not in target and alias not in valid_aliases:
                    valid_aliases.append(alias)
            if valid_aliases:
                target.set_alias(name, valid_aliases, ignore_duplicates=True)

    def _add_effective_attribute(self, result, attributes, reference, requirement, class_definition, path):
        resolved = self._resolve_attribute(reference, attributes, result.errors)
        class_name = self._display_name(class_definition, class_definition['oid'])
        if resolved is None:
            result.errors.append(dict(type='unknown_attribute',
                                      attribute=reference,
                                      requirement=requirement,
                                      object_class=class_name,
                                      path=path + [class_name]))
            return

        name = resolved['names'][0]
        attribute = None
        for candidate in result.attributes.values():
            if candidate.oid == resolved['oid']:
                attribute = candidate
                break

        if attribute is not None:
            self._extend_unique(attribute.names, resolved['names'])
            attribute.aliases = attribute.names[1:]
            attribute.single_value = attribute.single_value or resolved['single_value']
            if attribute.syntax is None:
                attribute.syntax = resolved['syntax']
            if attribute.definition is None:
                attribute.definition = resolved
        else:
            attribute = EffectiveSchemaAttribute(resolved['oid'],
                                                 resolved['names'],
                                                 resolved['single_value'],
                                                 resolved['syntax'],
                                                 resolved)

        source = EffectiveSchemaSource(requirement, class_name, list(path) + [class_name], reference)
        source.object_class_oid = class_definition['oid']
        source.attribute_oid = resolved['oid']
        attribute.sources.append(source)
        self._add_alias_dictionary(result.attributes, name, attribute.aliases + [attribute.oid], attribute)

    def _collect_effective_class(self, reference, class_index, attribute_index, result, path=None, active=None):
        if path is None:
            path = []
        if active is None:
            active = set()

        definition = class_index.get(reference)
        if definition is None or not isinstance(definition, dict):
            definition = self._resolve_reference(reference, self.object_classes, class_index)

        if definition is None:
            error_type = 'unknown_object_class' if not path else 'unknown_superior'
            error = dict(type=error_type, path=path + [reference], reference=reference)
            if path:
                error['superior'] = reference
                error['object_class'] = path[-1]
            else:
                error['object_class'] = reference
            result.errors.append(error)
            return

        name = self._display_name(definition, reference)
        current_path = path + [name]
        if name in path:
            result.errors.append(dict(type='object_class_inheritance_cycle',
                                      object_class=path[0] if path else name,
                                      path=current_path))
            return

        if definition['oid'] in active:
            result.errors.append(dict(type='object_class_inheritance_cycle',
                                      object_class=name,
                                      path=current_path + [name]))
        else:
            active.add(definition['oid'])
            for superior in definition['superior']:
                self._collect_effective_class(superior, class_index, attribute_index, result,
                                              current_path, set(active))

        for attribute in definition['must']:
            self._add_effective_attribute(result, attribute_index, attribute, 'MUST', definition, current_path[:-1])
        for attribute in definition['may']:
            self._add_effective_attribute(result, attribute_index, attribute, 'MAY', definition, current_path[:-1])

    def get_effective_definition(self, object_classes=None, auxiliary_classes=None, strict=False):
        """Merge MUST/MAY constraints through object class and attribute inheritance.

        Returns an EffectiveSchemaDefinition even when the schema references unknown
        parents or contains cycles. Set strict to True to raise LDAPSchemaError after
        collecting all attributes and complete error paths.
        """
        object_classes = self._as_name_list(object_classes)
        auxiliary_classes = self._as_name_list(auxiliary_classes)
        class_index = self._schema_index(self.object_classes)
        attribute_index = self._schema_index(self.attribute_types, include_attribute_properties=True)
        result = EffectiveSchemaDefinition()

        structural_error = self._structural_error(object_classes, class_index)
        if structural_error:
            result.errors.append(structural_error)

        included_object_classes = []
        included_auxiliary_classes = []
        included_oids = set()
        for references in (object_classes, auxiliary_classes):
            included_classes = included_object_classes if references is object_classes else included_auxiliary_classes
            for reference in references:
                definition = self._resolve_reference(reference, self.object_classes, class_index)
                if definition is None:
                    included_classes.append(reference)
                    continue
                if definition['oid'] not in included_oids:
                    included_oids.add(definition['oid'])
                    included_classes.append(self._display_name(definition, reference))

        result.object_classes = included_object_classes
        result.auxiliary_classes = included_auxiliary_classes

        for object_class in object_classes:
            self._collect_effective_class(object_class, class_index, attribute_index, result)
        for auxiliary_class in auxiliary_classes:
            self._collect_effective_class(auxiliary_class, class_index, attribute_index, result)

        for attribute in result.attributes.values():
            target = result.must if attribute.mandatory else result.may
            name = attribute.names[0]
            self._add_alias_dictionary(target, name, attribute.aliases + [attribute.oid], attribute)

        if strict and result.errors:
            error = LDAPSchemaError('invalid effective schema definition: ' + json.dumps(result.errors, sort_keys=True))
            error.effective_schema = result
            raise error
        return result

    def get_effective_attributes(self, object_classes=None, auxiliary_classes=None, strict=False):
        return self.get_effective_definition(object_classes, auxiliary_classes, strict)

    def get_allowed_attributes(self, object_classes=None, auxiliary_classes=None, strict=False):
        return self.get_effective_definition(object_classes, auxiliary_classes, strict)

    def effective_definition(self, object_classes=None, auxiliary_classes=None, strict=False):
        return self.get_effective_definition(object_classes, auxiliary_classes, strict)

    def effective_object_class(self, object_classes=None, auxiliary_classes=None, strict=False):
        return self.get_effective_definition(object_classes, auxiliary_classes, strict)

    def is_valid(self):
        if self.object_classes or self.attribute_types or self.matching_rules or self.matching_rule_uses or self.dit_content_rules or self.dit_structure_rules or self.name_forms or self.ldap_syntaxes:
            return True
        return False

    def __repr__(self):
        r = 'DSA Schema from: ' + self.schema_entry
        r += linesep
        if isinstance(self.attribute_types, SEQUENCE_TYPES):
            r += ('  Attribute types:' + linesep + '    ' + ', '.join([str(self.attribute_types[s]) for s in self.attribute_types])) if self.attribute_types else ''
        else:
            r += ('  Attribute types:' + str(self.attribute_types))
        r += linesep
        if isinstance(self.object_classes, SEQUENCE_TYPES):
            r += ('  Object classes:' + linesep + '    ' + ', '.join([str(self.object_classes[s]) for s in self.object_classes])) if self.object_classes else ''
        else:
            r += ('  Object classes:' + str(self.object_classes))
        r += linesep
        if isinstance(self.matching_rules, SEQUENCE_TYPES):
            r += ('  Matching rules:' + linesep + '    ' + ', '.join([str(self.matching_rules[s]) for s in self.matching_rules])) if self.matching_rules else ''
        else:
            r += ('  Matching rules:' + str(self.matching_rules))
        r += linesep
        if isinstance(self.matching_rule_uses, SEQUENCE_TYPES):
            r += ('  Matching rule uses:' + linesep + '    ' + ', '.join([str(self.matching_rule_uses[s]) for s in self.matching_rule_uses])) if self.matching_rule_uses else ''
        else:
            r += ('  Matching rule uses:' + str(self.matching_rule_uses))
        r += linesep
        if isinstance(self.dit_content_rules, SEQUENCE_TYPES):
            r += ('  DIT content rules:' + linesep + '    ' + ', '.join([str(self.dit_content_rules[s]) for s in self.dit_content_rules])) if self.dit_content_rules else ''
        else:
            r += ('  DIT content rules:' + str(self.dit_content_rules))
        r += linesep
        if isinstance(self.dit_structure_rules, SEQUENCE_TYPES):
            r += ('  DIT structure rules:' + linesep + '    ' + ', '.join([str(self.dit_structure_rules[s]) for s in self.dit_structure_rules])) if self.dit_structure_rules else ''
        else:
            r += ('  DIT structure rules:' + str(self.dit_structure_rules))
        r += linesep
        if isinstance(self.name_forms, SEQUENCE_TYPES):
            r += ('  Name forms:' + linesep + '    ' + ', '.join([str(self.name_forms[s]) for s in self.name_forms])) if self.name_forms else ''
        else:
            r += ('  Name forms:' + str(self.name_forms))
        r += linesep
        if isinstance(self.ldap_syntaxes, SEQUENCE_TYPES):
            r += ('  LDAP syntaxes:' + linesep + '    ' + ', '.join([str(self.ldap_syntaxes[s]) for s in self.ldap_syntaxes])) if self.ldap_syntaxes else ''
        else:
            r += ('  LDAP syntaxes:' + str(self.ldap_syntaxes))
        r += linesep
        r += 'Other:' + linesep

        for k, v in self.other.items():
            r += '  ' + str(k) + ': ' + linesep
            try:
                r += (linesep.join(['    ' + str(s) for s in v])) if isinstance(v, SEQUENCE_TYPES) else str(v)
            except UnicodeDecodeError:
                r += (linesep.join(['    ' + str(escape_bytes(s)) for s in v])) if isinstance(v, SEQUENCE_TYPES) else str(escape_bytes(v))
            r += linesep
        return r


class BaseObjectInfo(object):
    """
    Base class for objects defined in the schema as per RFC4512
    """

    def __init__(self,
                 oid=None,
                 name=None,
                 description=None,
                 obsolete=False,
                 extensions=None,
                 experimental=None,
                 definition=None):

        self.oid = oid
        self.name = name
        self.description = description
        self.obsolete = obsolete
        self.extensions = extensions
        self.experimental = experimental
        self.raw_definition = definition
        self._oid_info = None

    @property
    def oid_info(self):
        if self._oid_info is None and self.oid:
            self._oid_info = Oids.get(self.oid, '')

        return self._oid_info if self._oid_info else None

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        r = ': ' + self.oid
        r += ' [OBSOLETE]' if self.obsolete else ''
        r += (linesep + '  Short name: ' + list_to_string(self.name)) if self.name else ''
        r += (linesep + '  Description: ' + self.description) if self.description else ''
        r += '<__desc__>'
        r += (linesep + '  Extensions:' + linesep + linesep.join(['    ' + s[0] + ': ' + list_to_string(s[1]) for s in self.extensions])) if self.extensions else ''
        r += (linesep + '  Experimental:' + linesep + linesep.join(['    ' + s[0] + ': ' + list_to_string(s[1]) for s in self.experimental])) if self.experimental else ''
        r += (linesep + '  OidInfo: ' + str(self.oid_info)) if self.oid_info else ''
        r += linesep
        return r

    @classmethod
    def from_definition(cls, definitions):
        conf_case_insensitive_schema = get_config_parameter('CASE_INSENSITIVE_SCHEMA_NAMES')
        conf_ignore_malformed_schema = get_config_parameter('IGNORE_MALFORMED_SCHEMA')

        ret_dict = CaseInsensitiveWithAliasDict() if conf_case_insensitive_schema else dict()

        if not definitions:
            return ret_dict

        for object_definition in definitions:
            object_definition = to_unicode(object_definition.strip(), from_server=True)
            if object_definition[0] == '(' and object_definition[-1] == ')':
                if cls is MatchingRuleInfo:
                    pattern = '| SYNTAX '
                elif cls is ObjectClassInfo:
                    pattern = '| SUP | ABSTRACT| STRUCTURAL| AUXILIARY| MUST | MAY '
                elif cls is AttributeTypeInfo:
                    pattern = '| SUP | EQUALITY | ORDERING | SUBSTR | SYNTAX | SINGLE-VALUE| COLLECTIVE| NO-USER-MODIFICATION| USAGE '
                elif cls is MatchingRuleUseInfo:
                    pattern = '| APPLIES '
                elif cls is LdapSyntaxInfo:
                    pattern = ''
                elif cls is DitContentRuleInfo:
                    pattern = '| AUX | MUST | MAY | NOT '
                elif cls is DitStructureRuleInfo:
                    pattern = '| FORM | SUP '
                elif cls is NameFormInfo:
                    pattern = '| OC | MUST | MAY '
                else:
                    raise LDAPSchemaError('unknown schema definition class')

                splitted = re.split('( NAME | DESC | OBSOLETE| X-| E-' + pattern + ')', object_definition[1:-1])
                values = splitted[::2]
                separators = splitted[1::2]
                separators.insert(0, 'OID')
                defs = list(zip(separators, values))
                object_def = cls()
                for d in defs:
                    key = d[0].strip()
                    value = d[1].strip()
                    if key == 'OID':
                        object_def.oid = value
                    elif key == 'NAME':
                        object_def.name = quoted_string_to_list(value)
                    elif key == 'DESC':
                        object_def.description = value.strip("'")
                    elif key == 'OBSOLETE':
                        object_def.obsolete = True
                    elif key == 'SYNTAX':
                        object_def.syntax = oids_string_to_list(value)
                    elif key == 'SUP':
                        object_def.superior = oids_string_to_list(value)
                    elif key == 'ABSTRACT':
                        object_def.kind = CLASS_ABSTRACT
                    elif key == 'STRUCTURAL':
                        object_def.kind = CLASS_STRUCTURAL
                    elif key == 'AUXILIARY':
                        object_def.kind = CLASS_AUXILIARY
                    elif key == 'MUST':
                        object_def.must_contain = oids_string_to_list(value)
                    elif key == 'MAY':
                        object_def.may_contain = oids_string_to_list(value)
                    elif key == 'EQUALITY':
                        object_def.equality = oids_string_to_list(value)
                    elif key == 'ORDERING':
                        object_def.ordering = oids_string_to_list(value)
                    elif key == 'SUBSTR':
                        object_def.substr = oids_string_to_list(value)
                    elif key == 'SINGLE-VALUE':
                        object_def.single_value = True
                    elif key == 'COLLECTIVE':
                        object_def.collective = True
                    elif key == 'NO-USER-MODIFICATION':
                        object_def.no_user_modification = True
                    elif key == 'USAGE':
                        object_def.usage = attribute_usage_to_constant(value)
                    elif key == 'APPLIES':
                        object_def.apply_to = oids_string_to_list(value)
                    elif key == 'AUX':
                        object_def.auxiliary_classes = oids_string_to_list(value)
                    elif key == 'FORM':
                        object_def.name_form = oids_string_to_list(value)
                    elif key == 'OC':
                        object_def.object_class = oids_string_to_list(value)
                    elif key == 'NOT':
                        object_def.not_contains = oids_string_to_list(value)
                    elif key == 'X-':
                        if not object_def.extensions:
                            object_def.extensions = []
                        object_def.extensions.append(extension_to_tuple('X-' + value))
                    elif key == 'E-':
                        if not object_def.experimental:
                            object_def.experimental = []
                        object_def.experimental.append(extension_to_tuple('E-' + value))
                    else:
                        if not conf_ignore_malformed_schema:
                            raise LDAPSchemaError('malformed schema definition key:' + key + ' - use get_info=NONE in Server definition')
                        else:
                            return CaseInsensitiveWithAliasDict() if conf_case_insensitive_schema else dict()
                object_def.raw_definition = object_definition
                if hasattr(object_def, 'syntax') and object_def.syntax and len(object_def.syntax) == 1:
                    object_def.min_length = None
                    if object_def.syntax[0].endswith('}'):
                        try:
                            object_def.min_length = int(object_def.syntax[0][object_def.syntax[0].index('{') + 1:-1])
                            object_def.syntax[0] = object_def.syntax[0][:object_def.syntax[0].index('{')]
                        except Exception:
                            pass
                    else:
                        object_def.min_length = None
                    object_def.syntax[0] = object_def.syntax[0].strip("'")
                    object_def.syntax = object_def.syntax[0]
                if hasattr(object_def, 'name') and object_def.name:
                    if conf_case_insensitive_schema:
                        ret_dict[object_def.name[0]] = object_def
                        ret_dict.set_alias(object_def.name[0], object_def.name[1:] + [object_def.oid], ignore_duplicates=True)
                    else:
                        for name in object_def.name:
                            ret_dict[name] = object_def
                else:
                    ret_dict[object_def.oid] = object_def

            else:
                if not conf_ignore_malformed_schema:
                    raise LDAPSchemaError('malformed schema definition, use get_info=NONE in Server definition')
                else:
                    return CaseInsensitiveWithAliasDict() if conf_case_insensitive_schema else dict()
        return ret_dict


class MatchingRuleInfo(BaseObjectInfo):
    """
    As per RFC 4512 (4.1.3)
    """

    def __init__(self,
                 oid=None,
                 name=None,
                 description=None,
                 obsolete=False,
                 syntax=None,
                 extensions=None,
                 experimental=None,
                 definition=None):

        BaseObjectInfo.__init__(self,
                                oid=oid,
                                name=name,
                                description=description,
                                obsolete=obsolete,
                                extensions=extensions,
                                experimental=experimental,
                                definition=definition)
        self.syntax = syntax

    def __repr__(self):
        r = (linesep + '  Syntax: ' + list_to_string(self.syntax)) if self.syntax else ''
        return 'Matching rule' + BaseObjectInfo.__repr__(self).replace('<__desc__>', r)


class MatchingRuleUseInfo(BaseObjectInfo):
    """
    As per RFC 4512 (4.1.4)
    """

    def __init__(self,
                 oid=None,
                 name=None,
                 description=None,
                 obsolete=False,
                 apply_to=None,
                 extensions=None,
                 experimental=None,
                 definition=None):
        BaseObjectInfo.__init__(self,
                                oid=oid,
                                name=name,
                                description=description,
                                obsolete=obsolete,
                                extensions=extensions,
                                experimental=experimental,
                                definition=definition)
        self.apply_to = apply_to

    def __repr__(self):
        r = (linesep + '  Apply to: ' + list_to_string(self.apply_to)) if self.apply_to else ''
        return 'Matching rule use' + BaseObjectInfo.__repr__(self).replace('<__desc__>', r)


class ObjectClassInfo(BaseObjectInfo):
    """
    As per RFC 4512 (4.1.1)
    """

    def __init__(self,
                 oid=None,
                 name=None,
                 description=None,
                 obsolete=False,
                 superior=None,
                 kind=None,
                 must_contain=None,
                 may_contain=None,
                 extensions=None,
                 experimental=None,
                 definition=None):

        BaseObjectInfo.__init__(self,
                                oid=oid,
                                name=name,
                                description=description,
                                obsolete=obsolete,
                                extensions=extensions,
                                experimental=experimental,
                                definition=definition)
        self.superior = superior
        self.kind = kind
        self.must_contain = must_contain or []
        self.may_contain = may_contain or []

    def __repr__(self):
        r = ''
        r += (linesep + '  Type: ' + constant_to_class_kind(self.kind)) if self.kind else ''
        r += (linesep + '  Superior: ' + list_to_string(self.superior)) if self.superior else ''
        r += (linesep + '  Must contain attributes: ' + list_to_string(self.must_contain)) if self.must_contain else ''
        r += (linesep + '  May contain attributes: ' + list_to_string(self.may_contain)) if self.may_contain else ''
        return 'Object class' + BaseObjectInfo.__repr__(self).replace('<__desc__>', r)


class AttributeTypeInfo(BaseObjectInfo):
    """
    As per RFC 4512 (4.1.2)
    """

    def __init__(self,
                 oid=None,
                 name=None,
                 description=None,
                 obsolete=False,
                 superior=None,
                 equality=None,
                 ordering=None,
                 substring=None,
                 syntax=None,
                 min_length=None,
                 single_value=False,
                 collective=False,
                 no_user_modification=False,
                 usage=None,
                 extensions=None,
                 experimental=None,
                 definition=None):

        BaseObjectInfo.__init__(self,
                                oid=oid,
                                name=name,
                                description=description,
                                obsolete=obsolete,
                                extensions=extensions,
                                experimental=experimental,
                                definition=definition)
        self.superior = superior
        self.equality = equality
        self.ordering = ordering
        self.substring = substring
        self.syntax = syntax
        self.min_length = min_length
        self.single_value = single_value
        self.collective = collective
        self.no_user_modification = no_user_modification
        self.usage = usage
        self.mandatory_in = []
        self.optional_in = []

    def __repr__(self):
        r = ''
        r += linesep + '  Single value: ' + str(self.single_value)
        r += linesep + '  Collective: True' if self.collective else ''
        r += (linesep + '  Superior: ' + list_to_string(self.superior)) if self.superior else ''
        r += linesep + '  No user modification: True' if self.no_user_modification else ''
        r += (linesep + '  Usage: ' + constant_to_attribute_usage(self.usage)) if self.usage else ''
        r += (linesep + '  Equality rule: ' + list_to_string(self.equality)) if self.equality else ''
        r += (linesep + '  Ordering rule: ' + list_to_string(self.ordering)) if self.ordering else ''
        r += (linesep + '  Substring rule: ' + list_to_string(self.substring)) if self.substring else ''
        r += (linesep + '  Syntax: ' + (self.syntax + (' [' + str(decode_syntax(self.syntax)))) + ']') if self.syntax else ''
        r += (linesep + '  Minimum length: ' + str(self.min_length)) if isinstance(self.min_length, int) else ''
        r += linesep + '  Mandatory in: ' + list_to_string(self.mandatory_in) if self.mandatory_in else ''
        r += linesep + '  Optional in: ' + list_to_string(self.optional_in) if self.optional_in else ''
        return 'Attribute type' + BaseObjectInfo.__repr__(self).replace('<__desc__>', r)


class LdapSyntaxInfo(BaseObjectInfo):
    """
    As per RFC 4512 (4.1.5)
    """

    def __init__(self,
                 oid=None,
                 description=None,
                 extensions=None,
                 experimental=None,
                 definition=None):

        BaseObjectInfo.__init__(self,
                                oid=oid,
                                name=None,
                                description=description,
                                obsolete=False,
                                extensions=extensions,
                                experimental=experimental,
                                definition=definition)

    def __repr__(self):
        return 'LDAP syntax' + BaseObjectInfo.__repr__(self).replace('<__desc__>', '')


class DitContentRuleInfo(BaseObjectInfo):
    """
    As per RFC 4512 (4.1.6)
    """

    def __init__(self,
                 oid=None,
                 name=None,
                 description=None,
                 obsolete=False,
                 auxiliary_classes=None,
                 must_contain=None,
                 may_contain=None,
                 not_contains=None,
                 extensions=None,
                 experimental=None,
                 definition=None):

        BaseObjectInfo.__init__(self,
                                oid=oid,
                                name=name,
                                description=description,
                                obsolete=obsolete,
                                extensions=extensions,
                                experimental=experimental,
                                definition=definition)

        self.auxiliary_classes = auxiliary_classes
        self.must_contain = must_contain
        self.may_contain = may_contain
        self.not_contains = not_contains

    def __repr__(self):
        r = (linesep + '  Auxiliary classes: ' + list_to_string(self.auxiliary_classes)) if self.auxiliary_classes else ''
        r += (linesep + '  Must contain: ' + list_to_string(self.must_contain)) if self.must_contain else ''
        r += (linesep + '  May contain: ' + list_to_string(self.may_contain)) if self.may_contain else ''
        r += (linesep + '  Not contains: ' + list_to_string(self.not_contains)) if self.not_contains else ''
        return 'DIT content rule' + BaseObjectInfo.__repr__(self).replace('<__desc__>', r)


class DitStructureRuleInfo(BaseObjectInfo):
    """
    As per RFC 4512 (4.1.7.1)
    """

    def __init__(self,
                 oid=None,
                 name=None,
                 description=None,
                 obsolete=False,
                 name_form=None,
                 superior=None,
                 extensions=None,
                 experimental=None,
                 definition=None):

        BaseObjectInfo.__init__(self,
                                oid=oid,
                                name=name,
                                description=description,
                                obsolete=obsolete,
                                extensions=extensions,
                                experimental=experimental,
                                definition=definition)
        self.superior = superior
        self.name_form = name_form

    def __repr__(self):
        r = (linesep + '  Superior rules: ' + list_to_string(self.superior)) if self.superior else ''
        r += (linesep + '  Name form: ' + list_to_string(self.name_form)) if self.name_form else ''
        return 'DIT content rule' + BaseObjectInfo.__repr__(self).replace('<__desc__>', r)


class NameFormInfo(BaseObjectInfo):
    """
    As per RFC 4512 (4.1.7.2)
    """

    def __init__(self,
                 oid=None,
                 name=None,
                 description=None,
                 obsolete=False,
                 object_class=None,
                 must_contain=None,
                 may_contain=None,
                 extensions=None,
                 experimental=None,
                 definition=None):

        BaseObjectInfo.__init__(self,
                                oid=oid,
                                name=name,
                                description=description,
                                obsolete=obsolete,
                                extensions=extensions,
                                experimental=experimental,
                                definition=definition)
        self.object_class = object_class
        self.must_contain = must_contain
        self.may_contain = may_contain

    def __repr__(self):
        r = (linesep + '  Object class: ' + list_to_string(self.object_class)) if self.object_class else ''
        r += (linesep + '  Must contain: ' + list_to_string(self.must_contain)) if self.must_contain else ''
        r += (linesep + '  May contain: ' + list_to_string(self.may_contain)) if self.may_contain else ''
        return 'DIT content rule' + BaseObjectInfo.__repr__(self).replace('<__desc__>', r)
