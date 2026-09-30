"""
Effective LDAP schema computation.

Given a set of object classes (structural/abstract plus auxiliary) compute the
effective set of attributes that an entry is allowed to contain, as per
RFC 4512 / X.501: MUST/MAY are merged along the whole SUP inheritance chain,
attribute aliases and OIDs pointing to the same attribute type are merged and
attribute type properties (SINGLE-VALUE, syntax, ...) are resolved through the
attribute type SUP chain. Every problem (unknown parent, inheritance cycle,
incompatible structural classes, unknown attribute) is reported with the full
path involved instead of silently dropping part of the inheritance tree.
"""

from os import linesep

from .. import STRING_TYPES
from ..core.exceptions import LDAPSchemaError
from ..protocol.rfc4512 import constant_to_attribute_usage
from ..protocol.oid import CLASS_STRUCTURAL, CLASS_ABSTRACT, CLASS_AUXILIARY
from ..utils.ciDict import CaseInsensitiveWithAliasDict

UNKNOWN_OBJECT_CLASS = 'unknownObjectClass'
UNKNOWN_SUPERIOR_CLASS = 'unknownSuperiorClass'
OBJECT_CLASS_CYCLE = 'objectClassCycle'
INCOMPATIBLE_STRUCTURAL_CLASSES = 'incompatibleStructuralClasses'
UNKNOWN_ATTRIBUTE_TYPE = 'unknownAttributeType'
UNKNOWN_SUPERIOR_ATTRIBUTE = 'unknownSuperiorAttribute'
ATTRIBUTE_TYPE_CYCLE = 'attributeTypeCycle'

MUST = 'must'
MAY = 'may'


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, STRING_TYPES):
        return [value]
    return list(value)


def _key(value):
    return value.strip().lower() if isinstance(value, STRING_TYPES) else value


def _primary_name(info):
    return info.name[0] if getattr(info, 'name', None) else info.oid


class SchemaIssue(object):
    """A single schema problem found while computing the effective definition."""

    def __init__(self, code, message, paths=None, references=None):
        self.code = code
        self.message = message
        self.paths = [list(path) for path in paths] if paths else []
        self.references = list(references) if references else []

    def __repr__(self):
        text = self.code + ': ' + self.message
        for path in self.paths:
            text += linesep + '  path: ' + ' -> '.join(path)
        if self.references:
            text += linesep + '  references: ' + ', '.join(self.references)
        return text

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        return isinstance(other, SchemaIssue) and self.code == other.code and self.message == other.message and self.paths == other.paths and self.references == other.references


class EffectiveAttributeDefinition(object):
    """Effective definition of one attribute after alias/OID merging and SUP chain resolution."""

    def __init__(self, oid, names=None, single_value=False, syntax=None,
                 min_length=None, equality=None, ordering=None, substring=None,
                 usage=None, collective=False, no_user_modification=False,
                 obsolete=False, description=None, mandatory=False, known=True,
                 definition=None, sources=None, single_value_source=None):
        self.oid = oid
        self.names = list(names) if names else []
        self.single_value = single_value
        self.syntax = syntax
        self.min_length = min_length
        self.equality = equality
        self.ordering = ordering
        self.substring = substring
        self.usage = usage
        self.collective = collective
        self.no_user_modification = no_user_modification
        self.obsolete = obsolete
        self.description = description
        self.mandatory = mandatory
        self.known = known
        self.definition = definition
        self.sources = list(sources) if sources else []
        self.single_value_source = single_value_source

    @property
    def name(self):
        return self.names[0] if self.names else self.oid

    def __repr__(self):
        r = 'Effective attribute: ' + self.name
        if self.oid != self.name:
            r += ' (' + str(self.oid) + ')'
        r += linesep + '  Requirement: ' + ('MUST' if self.mandatory else 'MAY')
        if not self.known:
            r += linesep + '  Defined in schema: False'
        r += linesep + '  Single value: ' + str(self.single_value)
        if self.single_value and self.single_value_source:
            r += linesep + '  Single value source: ' + self.single_value_source
        if len(self.names) > 1:
            r += linesep + '  Aliases: ' + ', '.join(self.names[1:])
        if self.syntax:
            r += linesep + '  Syntax: ' + self.syntax
        if isinstance(self.min_length, int):
            r += linesep + '  Minimum length: ' + str(self.min_length)
        if self.equality:
            r += linesep + '  Equality rule: ' + self.equality
        if self.ordering:
            r += linesep + '  Ordering rule: ' + self.ordering
        if self.substring:
            r += linesep + '  Substring rule: ' + self.substring
        if self.usage is not None:
            r += linesep + '  Usage: ' + constant_to_attribute_usage(self.usage)
        if self.collective:
            r += linesep + '  Collective: True'
        if self.no_user_modification:
            r += linesep + '  No user modification: True'
        if self.obsolete:
            r += linesep + '  Obsolete: True'
        if self.description:
            r += linesep + '  Description: ' + self.description
        if self.sources:
            r += linesep + '  Sources:'
            for source in self.sources:
                r += linesep + '    ' + source['object_class'] + ' (' + source['requirement'].upper() + ', ' + ' -> '.join(source['path']) + ')'
        return r

    def __str__(self):
        return self.__repr__()


class EffectiveSchemaDefinition(object):
    """The effective, explainable definition of a set of object classes."""

    def __init__(self, object_classes=None, auxiliary_classes=None,
                 structural_classes=None, abstract_classes=None,
                 attributes=None, issues=None):
        self.object_classes = list(object_classes) if object_classes else []
        self.auxiliary_classes = list(auxiliary_classes) if auxiliary_classes else []
        self.structural_classes = list(structural_classes) if structural_classes else []
        self.abstract_classes = list(abstract_classes) if abstract_classes else []
        self.attributes = attributes if attributes is not None else CaseInsensitiveWithAliasDict()
        self.issues = list(issues) if issues else []

    @property
    def is_valid(self):
        return not self.issues

    @property
    def mandatory_attributes(self):
        return CaseInsensitiveWithAliasDict({name: attr for name, attr in self.attributes.items() if attr.mandatory})

    @property
    def optional_attributes(self):
        return CaseInsensitiveWithAliasDict({name: attr for name, attr in self.attributes.items() if not attr.mandatory})

    @property
    def must(self):
        return self.mandatory_attributes

    @property
    def may(self):
        return self.optional_attributes

    def __contains__(self, item):
        return item in self.attributes

    def __getitem__(self, item):
        return self.attributes[item]

    def __iter__(self):
        for name in self.attributes:
            yield self.attributes[name]

    def __len__(self):
        return len(self.attributes)

    def __repr__(self):
        r = 'Effective schema for object classes: ' + ', '.join(self.object_classes)
        if self.auxiliary_classes:
            r += linesep + 'Auxiliary classes: ' + ', '.join(self.auxiliary_classes)
        r += linesep + 'MUST attributes: ' + (', '.join(sorted(a.name for a in self.attributes.values() if a.mandatory)) or '<none>')
        r += linesep + 'MAY attributes: ' + (', '.join(sorted(a.name for a in self.attributes.values() if not a.mandatory)) or '<none>')
        if self.issues:
            r += linesep + 'Issues (' + str(len(self.issues)) + '):'
            for issue in self.issues:
                r += linesep + '  ' + str(issue).replace(linesep, linesep + '  ')
        return r

    def __str__(self):
        return self.__repr__()


class LDAPEffectiveSchemaError(LDAPSchemaError):
    """Raised in strict mode; carries every detected issue and the partial definition."""

    def __init__(self, message, issues=None, effective_schema=None):
        LDAPSchemaError.__init__(self, message)
        self.issues = list(issues) if issues else []
        self.effective_schema = effective_schema

    def __str__(self):
        text = LDAPSchemaError.__str__(self)
        for issue in self.issues:
            text += linesep + str(issue)
        return text


class _ClassExpansion(object):
    """Result of expanding one requested root class along its SUP chain."""

    def __init__(self, root_oid, contributions, structural, abstract, auxiliary):
        self.root_oid = root_oid
        # list of dicts: identifier, requirement, class_label, class_path
        self.contributions = contributions
        # structural/abstract/auxiliary classes touched, each as (oid, label_path_from_root)
        self.structural = structural
        self.abstract = abstract
        self.auxiliary = auxiliary


class _EffectiveSchemaBuilder(object):
    def __init__(self, schema, strict=True):
        self.schema = schema
        self.strict = strict
        self.issues = []

        self.class_by_oid = {}   # canonical oid -> ObjectClassInfo
        self.class_index = {}    # canonical oid/name -> canonical oid
        self.attr_by_oid = {}    # canonical oid -> AttributeTypeInfo (duplicate oids merged)
        self.attr_index = {}     # canonical oid/name -> canonical oid
        self._index_object_classes()
        self._index_attribute_types()

        self._resolved_attrs = {}  # canonical oid -> EffectiveAttributeDefinition

    def _index_object_classes(self):
        for info in self.schema.object_classes.values():
            oid = _key(info.oid)
            existing = self.class_by_oid.get(oid)
            if existing is None:
                self.class_by_oid[oid] = info
            else:
                for name in info.name or []:
                    if name not in (existing.name or []):
                        existing.name = list(existing.name or []) + [name]
            self.class_index[oid] = oid
            for name in info.name or []:
                self.class_index.setdefault(_key(name), oid)

    def _index_attribute_types(self):
        for info in self.schema.attribute_types.values():
            oid = _key(info.oid)
            existing = self.attr_by_oid.get(oid)
            if existing is None:
                self.attr_by_oid[oid] = info
            else:
                # same OID exposed under different aliases/definitions: merge into one attribute
                for name in info.name or []:
                    if name not in (existing.name or []):
                        existing.name = list(existing.name or []) + [name]
                # complete missing properties from the duplicate definition
                for attr_name in ('syntax', 'min_length', 'equality', 'ordering', 'substring', 'usage'):
                    if not getattr(existing, attr_name, None) and getattr(info, attr_name, None):
                        setattr(existing, attr_name, getattr(info, attr_name))
                if info.single_value:
                    existing.single_value = True
            self.attr_index[oid] = oid
            for name in info.name or []:
                self.attr_index.setdefault(_key(name), oid)

    def _class_label(self, oid):
        return _primary_name(self.class_by_oid[oid])

    def _attr_label(self, oid):
        info = self.attr_by_oid.get(oid)
        return _primary_name(info) if info is not None else oid

    # -- attribute types ----------------------------------------------------------

    def _resolve_attribute_ref(self, identifier, class_path):
        """Resolve an attribute identifier referenced by an object class."""
        oid = self.attr_index.get(_key(identifier))
        if oid is None:
            self.issues.append(SchemaIssue(
                UNKNOWN_ATTRIBUTE_TYPE,
                "attribute type '%s' referenced in object class '%s' is not defined in the schema" % (identifier, class_path[-1]),
                paths=[list(class_path)],
                references=[identifier]))
            return None, oid if oid else None, identifier
        return self._resolve_known_attribute(oid, []), oid, identifier

    def _resolve_known_attribute(self, oid, chain):
        if oid in self._resolved_attrs:
            return self._resolved_attrs[oid]

        if oid in chain:
            cycle = chain[chain.index(oid):] + [oid]
            labels = [self._attr_label(part) for part in cycle]
            self.issues.append(SchemaIssue(ATTRIBUTE_TYPE_CYCLE,
                                           "inheritance cycle detected in attribute type SUP chain",
                                           paths=[labels],
                                           references=labels))
            info = self.attr_by_oid.get(oid)
            partial = EffectiveAttributeDefinition(
                oid=info.oid if info else oid,
                names=list(info.name or [oid]) if info else [oid],
                known=True)
            return partial

        info = self.attr_by_oid[oid]
        chain = chain + [oid]

        superior = None
        if getattr(info, 'superior', None):
            sup_ref = info.superior[0]
            sup_oid = self.attr_index.get(_key(sup_ref))
            if sup_oid is None:
                self.issues.append(SchemaIssue(
                    UNKNOWN_SUPERIOR_ATTRIBUTE,
                    "attribute type '%s' has SUP '%s' not defined in the schema" % (_primary_name(info), sup_ref),
                    paths=[[_primary_name(info), sup_ref]],
                    references=[sup_ref]))
            else:
                superior = self._resolve_known_attribute(sup_oid, chain)

        single_value = bool(info.single_value)
        single_value_source = _primary_name(info) if single_value else None
        if not single_value and superior is not None and superior.single_value:
            single_value = True
            single_value_source = superior.single_value_source or superior.name

        effective = EffectiveAttributeDefinition(
            oid=info.oid,
            names=list(info.name or [info.oid]),
            single_value=single_value,
            syntax=info.syntax if info.syntax is not None else (superior.syntax if superior is not None else None),
            min_length=info.min_length if info.min_length is not None else (superior.min_length if superior is not None else None),
            equality=(info.equality[0] if info.equality else None) or (superior.equality if superior is not None else None),
            ordering=(info.ordering[0] if info.ordering else None) or (superior.ordering if superior is not None else None),
            substring=(info.substring[0] if info.substring else None) or (superior.substring if superior is not None else None),
            usage=info.usage if info.usage is not None else (superior.usage if superior is not None else None),
            collective=bool(info.collective) or (superior.collective if superior is not None else False),
            no_user_modification=bool(info.no_user_modification) or (superior.no_user_modification if superior is not None else False),
            obsolete=bool(info.obsolete),
            description=info.description,
            known=True,
            definition=info,
            single_value_source=single_value_source)

        self._resolved_attrs[oid] = effective
        return effective

    # -- object class expansion ---------------------------------------------------

    def _expand_root(self, root_oid):
        contributions = []
        structural = []
        abstract = []
        auxiliary = []

        root_label = self._class_label(root_oid)

        def walk(oid, label_path, active):
            if oid in active:
                start = active.index(oid)
                cycle = active[start:] + [oid]
                labels = [self._class_label(part) for part in cycle]
                self.issues.append(SchemaIssue(
                    OBJECT_CLASS_CYCLE,
                    "inheritance cycle detected in object class SUP chain",
                    paths=[list(labels)],
                    references=labels))
                return
            label = self._class_label(oid)
            label_path = label_path + [label]
            info = self.class_by_oid[oid]

            if info.kind == CLASS_STRUCTURAL:
                structural.append((oid, list(label_path)))
            elif info.kind == CLASS_ABSTRACT:
                abstract.append((oid, list(label_path)))
            elif info.kind == CLASS_AUXILIARY:
                auxiliary.append((oid, list(label_path)))

            for sup_ref in info.superior or []:
                sup_oid = self.class_index.get(_key(sup_ref))
                if sup_oid is None:
                    self.issues.append(SchemaIssue(
                        UNKNOWN_SUPERIOR_CLASS,
                        "object class '%s' has SUP '%s' not defined in the schema" % (label, sup_ref),
                        paths=[list(label_path) + [sup_ref]],
                        references=[sup_ref]))
                    continue
                walk(sup_oid, label_path, active + [oid])

            # attributes collected after traversing superiors; path documents the full chain
            for identifier in info.must_contain:
                contributions.append({'identifier': identifier, 'requirement': MUST,
                                      'class_label': label, 'class_path': list(label_path)})
            for identifier in info.may_contain:
                contributions.append({'identifier': identifier, 'requirement': MAY,
                                      'class_label': label, 'class_path': list(label_path)})

        walk(root_oid, [], [])
        return _ClassExpansion(root_oid, contributions, structural, abstract, auxiliary)

    def _structural_ancestors(self, oid):
        ancestors = []
        seen = set()
        pending = list(self.class_by_oid[oid].superior or [])
        while pending:
            ref = pending.pop()
            sup_oid = self.class_index.get(_key(ref))
            if sup_oid is None or sup_oid in seen:
                continue
            seen.add(sup_oid)
            if self.class_by_oid[sup_oid].kind == CLASS_STRUCTURAL and sup_oid not in ancestors:
                ancestors.append(sup_oid)
            pending.extend(self.class_by_oid[sup_oid].superior or [])
        return ancestors

    # -- main ---------------------------------------------------------------------

    def build(self, object_classes, auxiliary_classes):
        requested_roots = []
        requested_labels = []
        auxiliary_roots = []
        for identifier in _as_list(object_classes):
            oid = self.class_index.get(_key(identifier))
            if oid is None:
                self.issues.append(SchemaIssue(UNKNOWN_OBJECT_CLASS,
                                               "object class '%s' is not defined in the schema" % identifier,
                                               paths=[[identifier]], references=[identifier]))
            else:
                requested_roots.append(oid)
                requested_labels.append(self._class_label(oid))
        for identifier in _as_list(auxiliary_classes):
            oid = self.class_index.get(_key(identifier))
            if oid is None:
                self.issues.append(SchemaIssue(UNKNOWN_OBJECT_CLASS,
                                               "auxiliary object class '%s' is not defined in the schema" % identifier,
                                               paths=[[identifier]], references=[identifier]))
            else:
                auxiliary_roots.append(oid)

        # every distinct class is expanded exactly once, even if it is both
        # explicitly requested and passed as auxiliary
        all_roots = list(dict.fromkeys(requested_roots + auxiliary_roots))
        expansions = [self._expand_root(oid) for oid in all_roots]

        # gather class kinds across all roots, preserving order
        structural_seen = []
        abstract_seen = []
        auxiliary_seen = []
        # parent map of structural classes restricted to structural lineage
        structural_parents = {}
        # oid -> one representative full path for error reporting
        structural_paths = {}

        for expansion in expansions:
            for oid, path in expansion.structural:
                if oid not in structural_seen:
                    structural_seen.append(oid)
                structural_paths.setdefault(oid, path)

            for oid, _path in expansion.abstract:
                if oid not in abstract_seen:
                    abstract_seen.append(oid)
            for oid, _path in expansion.auxiliary:
                if oid not in auxiliary_seen:
                    auxiliary_seen.append(oid)

        # build the structural lineage: collect every structural ancestor by
        # climbing the full raw SUP chain (not only immediate superiors)
        for oid in structural_seen:
            structural_parents[oid] = self._structural_ancestors(oid)

        # incompatibility: only the most general structural classes (the ones
        # without any structural ancestor) can conflict. A single structural
        # lineage has exactly one such root; multiple roots belong to
        # incompatible branches.
        structural_roots = [oid for oid in structural_seen if not structural_parents[oid]]
        # keep the first root as the lineage in use and report the others
        if structural_roots:
            lineage_root = structural_roots[0]
            for extra_root in structural_roots[1:]:
                self.issues.append(SchemaIssue(
                    INCOMPATIBLE_STRUCTURAL_CLASSES,
                    "structural object classes '%s' and '%s' are incompatible: they belong to different structural inheritance branches" % (
                        self._class_label(lineage_root), self._class_label(extra_root)),
                    paths=[structural_paths[lineage_root], structural_paths[extra_root]],
                    references=[self.class_by_oid[lineage_root].oid, self.class_by_oid[extra_root].oid]))

        # merge attributes across every expansion, keyed by canonical oid
        merged = {}
        for expansion in expansions:
            for contribution in expansion.contributions:
                effective, canonical, reference = self._resolve_attribute_ref(contribution['identifier'],
                                                                              contribution['class_path'])
                if canonical is None:
                    canonical = _key(reference)
                payload = merged.get(canonical)
                source = {'object_class': contribution['class_label'],
                          'requirement': contribution['requirement'],
                          'path': contribution['class_path'],
                          'reference': reference}
                if payload is None:
                    if effective is None:
                        effective = EffectiveAttributeDefinition(oid=reference, names=[reference], known=False)
                    merged[canonical] = {'attribute': effective,
                                         'must': contribution['requirement'] == MUST,
                                         'sources': [source]}
                else:
                    if contribution['requirement'] == MUST:
                        payload['must'] = True
                    payload['sources'].append(source)

        attributes = CaseInsensitiveWithAliasDict()
        for canonical, payload in merged.items():
            effective = payload['attribute']
            effective.mandatory = payload['must']
            effective.sources = payload['sources']
            primary = effective.name
            attributes[primary] = effective
            aliases = [name for name in effective.names if _key(name) != _key(primary)]
            if aliases:
                attributes.set_alias(primary, aliases)
            if effective.known and _key(effective.oid) != _key(primary):
                attributes.set_alias(primary, effective.oid)

        result = EffectiveSchemaDefinition(
            object_classes=list(dict.fromkeys(requested_labels)),
            auxiliary_classes=[self._class_label(oid) for oid in auxiliary_seen],
            structural_classes=[self._class_label(oid) for oid in structural_seen],
            abstract_classes=[self._class_label(oid) for oid in abstract_seen],
            attributes=attributes,
            issues=list(self.issues))

        if self.strict and self.issues:
            raise LDAPEffectiveSchemaError(
                "invalid effective schema definition: %d issue(s) found" % len(self.issues),
                issues=self.issues, effective_schema=result)
        return result


def _coerce_schema(schema):
    from ..protocol.rfc4512 import SchemaInfo
    if isinstance(schema, SchemaInfo):
        return schema
    from ..core.server import Server
    from ..core.connection import Connection
    if isinstance(schema, Connection):
        if getattr(schema, 'server', None) is None or schema.server.schema is None:
            raise LDAPSchemaError('schema not present in connection server')
        return schema.server.schema
    if isinstance(schema, Server):
        if schema.schema is None:
            raise LDAPSchemaError('schema not present in server')
        return schema.schema
    raise LDAPSchemaError('expected a SchemaInfo, Server or Connection instance')


def get_effective_schema(schema, object_classes, auxiliary_classes=None, strict=True):
    """Compute the effective attribute set allowed for a set of object classes.

    Merges MUST/MAY of the requested structural/abstract and auxiliary classes
    along their whole SUP inheritance chains. Aliases and OIDs referring to the
    same attribute type are merged; SINGLE-VALUE and other attribute properties
    are resolved through the attribute type SUP chain. Works fully offline on a
    SchemaInfo parsed from a standard schema or JSON.

    :param schema: SchemaInfo (or Server/Connection carrying one), no directory access
    :param object_classes: name(s) or OID(s) of structural/abstract object classes
    :param auxiliary_classes: optional auxiliary object class name(s)/OID(s)
    :param strict: raise :class:`LDAPEffectiveSchemaError` (aggregating all issues)
        when True; when False issues are returned on the result object
    :returns: :class:`EffectiveSchemaDefinition`
    """
    schema_info = _coerce_schema(schema)
    builder = _EffectiveSchemaBuilder(schema_info, strict=strict)
    return builder.build(_as_list(object_classes), _as_list(auxiliary_classes))
