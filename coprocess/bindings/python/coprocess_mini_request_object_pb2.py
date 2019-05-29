# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: coprocess_mini_request_object.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import coprocess_return_overrides_pb2 as coprocess__return__overrides__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='coprocess_mini_request_object.proto',
  package='coprocess',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n#coprocess_mini_request_object.proto\x12\tcoprocess\x1a coprocess_return_overrides.proto\"\x9a\x06\n\x11MiniRequestObject\x12:\n\x07headers\x18\x01 \x03(\x0b\x32).coprocess.MiniRequestObject.HeadersEntry\x12\x41\n\x0bset_headers\x18\x02 \x03(\x0b\x32,.coprocess.MiniRequestObject.SetHeadersEntry\x12\x16\n\x0e\x64\x65lete_headers\x18\x03 \x03(\t\x12\x0c\n\x04\x62ody\x18\x04 \x01(\t\x12\x0b\n\x03url\x18\x05 \x01(\t\x12\x38\n\x06params\x18\x06 \x03(\x0b\x32(.coprocess.MiniRequestObject.ParamsEntry\x12?\n\nadd_params\x18\x07 \x03(\x0b\x32+.coprocess.MiniRequestObject.AddParamsEntry\x12I\n\x0f\x65xtended_params\x18\x08 \x03(\x0b\x32\x30.coprocess.MiniRequestObject.ExtendedParamsEntry\x12\x15\n\rdelete_params\x18\t \x03(\t\x12\x34\n\x10return_overrides\x18\n \x01(\x0b\x32\x1a.coprocess.ReturnOverrides\x12\x0e\n\x06method\x18\x0b \x01(\t\x12\x13\n\x0brequest_uri\x18\x0c \x01(\t\x12\x0e\n\x06scheme\x18\r \x01(\t\x12\x10\n\x08raw_body\x18\x0e \x01(\x0c\x1a.\n\x0cHeadersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x31\n\x0fSetHeadersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a-\n\x0bParamsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x30\n\x0e\x41\x64\x64ParamsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x35\n\x13\x45xtendedParamsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x62\x06proto3')
  ,
  dependencies=[coprocess__return__overrides__pb2.DESCRIPTOR,])




_MINIREQUESTOBJECT_HEADERSENTRY = _descriptor.Descriptor(
  name='HeadersEntry',
  full_name='coprocess.MiniRequestObject.HeadersEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='coprocess.MiniRequestObject.HeadersEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='coprocess.MiniRequestObject.HeadersEntry.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=_b('8\001'),
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=630,
  serialized_end=676,
)

_MINIREQUESTOBJECT_SETHEADERSENTRY = _descriptor.Descriptor(
  name='SetHeadersEntry',
  full_name='coprocess.MiniRequestObject.SetHeadersEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='coprocess.MiniRequestObject.SetHeadersEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='coprocess.MiniRequestObject.SetHeadersEntry.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=_b('8\001'),
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=678,
  serialized_end=727,
)

_MINIREQUESTOBJECT_PARAMSENTRY = _descriptor.Descriptor(
  name='ParamsEntry',
  full_name='coprocess.MiniRequestObject.ParamsEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='coprocess.MiniRequestObject.ParamsEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='coprocess.MiniRequestObject.ParamsEntry.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=_b('8\001'),
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=729,
  serialized_end=774,
)

_MINIREQUESTOBJECT_ADDPARAMSENTRY = _descriptor.Descriptor(
  name='AddParamsEntry',
  full_name='coprocess.MiniRequestObject.AddParamsEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='coprocess.MiniRequestObject.AddParamsEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='coprocess.MiniRequestObject.AddParamsEntry.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=_b('8\001'),
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=776,
  serialized_end=824,
)

_MINIREQUESTOBJECT_EXTENDEDPARAMSENTRY = _descriptor.Descriptor(
  name='ExtendedParamsEntry',
  full_name='coprocess.MiniRequestObject.ExtendedParamsEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='coprocess.MiniRequestObject.ExtendedParamsEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='coprocess.MiniRequestObject.ExtendedParamsEntry.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=_b('8\001'),
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=826,
  serialized_end=879,
)

_MINIREQUESTOBJECT = _descriptor.Descriptor(
  name='MiniRequestObject',
  full_name='coprocess.MiniRequestObject',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='headers', full_name='coprocess.MiniRequestObject.headers', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='set_headers', full_name='coprocess.MiniRequestObject.set_headers', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='delete_headers', full_name='coprocess.MiniRequestObject.delete_headers', index=2,
      number=3, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='body', full_name='coprocess.MiniRequestObject.body', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='url', full_name='coprocess.MiniRequestObject.url', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='params', full_name='coprocess.MiniRequestObject.params', index=5,
      number=6, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='add_params', full_name='coprocess.MiniRequestObject.add_params', index=6,
      number=7, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='extended_params', full_name='coprocess.MiniRequestObject.extended_params', index=7,
      number=8, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='delete_params', full_name='coprocess.MiniRequestObject.delete_params', index=8,
      number=9, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='return_overrides', full_name='coprocess.MiniRequestObject.return_overrides', index=9,
      number=10, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='method', full_name='coprocess.MiniRequestObject.method', index=10,
      number=11, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='request_uri', full_name='coprocess.MiniRequestObject.request_uri', index=11,
      number=12, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='scheme', full_name='coprocess.MiniRequestObject.scheme', index=12,
      number=13, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='raw_body', full_name='coprocess.MiniRequestObject.raw_body', index=13,
      number=14, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[_MINIREQUESTOBJECT_HEADERSENTRY, _MINIREQUESTOBJECT_SETHEADERSENTRY, _MINIREQUESTOBJECT_PARAMSENTRY, _MINIREQUESTOBJECT_ADDPARAMSENTRY, _MINIREQUESTOBJECT_EXTENDEDPARAMSENTRY, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=85,
  serialized_end=879,
)

_MINIREQUESTOBJECT_HEADERSENTRY.containing_type = _MINIREQUESTOBJECT
_MINIREQUESTOBJECT_SETHEADERSENTRY.containing_type = _MINIREQUESTOBJECT
_MINIREQUESTOBJECT_PARAMSENTRY.containing_type = _MINIREQUESTOBJECT
_MINIREQUESTOBJECT_ADDPARAMSENTRY.containing_type = _MINIREQUESTOBJECT
_MINIREQUESTOBJECT_EXTENDEDPARAMSENTRY.containing_type = _MINIREQUESTOBJECT
_MINIREQUESTOBJECT.fields_by_name['headers'].message_type = _MINIREQUESTOBJECT_HEADERSENTRY
_MINIREQUESTOBJECT.fields_by_name['set_headers'].message_type = _MINIREQUESTOBJECT_SETHEADERSENTRY
_MINIREQUESTOBJECT.fields_by_name['params'].message_type = _MINIREQUESTOBJECT_PARAMSENTRY
_MINIREQUESTOBJECT.fields_by_name['add_params'].message_type = _MINIREQUESTOBJECT_ADDPARAMSENTRY
_MINIREQUESTOBJECT.fields_by_name['extended_params'].message_type = _MINIREQUESTOBJECT_EXTENDEDPARAMSENTRY
_MINIREQUESTOBJECT.fields_by_name['return_overrides'].message_type = coprocess__return__overrides__pb2._RETURNOVERRIDES
DESCRIPTOR.message_types_by_name['MiniRequestObject'] = _MINIREQUESTOBJECT
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

MiniRequestObject = _reflection.GeneratedProtocolMessageType('MiniRequestObject', (_message.Message,), dict(

  HeadersEntry = _reflection.GeneratedProtocolMessageType('HeadersEntry', (_message.Message,), dict(
    DESCRIPTOR = _MINIREQUESTOBJECT_HEADERSENTRY,
    __module__ = 'coprocess_mini_request_object_pb2'
    # @@protoc_insertion_point(class_scope:coprocess.MiniRequestObject.HeadersEntry)
    ))
  ,

  SetHeadersEntry = _reflection.GeneratedProtocolMessageType('SetHeadersEntry', (_message.Message,), dict(
    DESCRIPTOR = _MINIREQUESTOBJECT_SETHEADERSENTRY,
    __module__ = 'coprocess_mini_request_object_pb2'
    # @@protoc_insertion_point(class_scope:coprocess.MiniRequestObject.SetHeadersEntry)
    ))
  ,

  ParamsEntry = _reflection.GeneratedProtocolMessageType('ParamsEntry', (_message.Message,), dict(
    DESCRIPTOR = _MINIREQUESTOBJECT_PARAMSENTRY,
    __module__ = 'coprocess_mini_request_object_pb2'
    # @@protoc_insertion_point(class_scope:coprocess.MiniRequestObject.ParamsEntry)
    ))
  ,

  AddParamsEntry = _reflection.GeneratedProtocolMessageType('AddParamsEntry', (_message.Message,), dict(
    DESCRIPTOR = _MINIREQUESTOBJECT_ADDPARAMSENTRY,
    __module__ = 'coprocess_mini_request_object_pb2'
    # @@protoc_insertion_point(class_scope:coprocess.MiniRequestObject.AddParamsEntry)
    ))
  ,

  ExtendedParamsEntry = _reflection.GeneratedProtocolMessageType('ExtendedParamsEntry', (_message.Message,), dict(
    DESCRIPTOR = _MINIREQUESTOBJECT_EXTENDEDPARAMSENTRY,
    __module__ = 'coprocess_mini_request_object_pb2'
    # @@protoc_insertion_point(class_scope:coprocess.MiniRequestObject.ExtendedParamsEntry)
    ))
  ,
  DESCRIPTOR = _MINIREQUESTOBJECT,
  __module__ = 'coprocess_mini_request_object_pb2'
  # @@protoc_insertion_point(class_scope:coprocess.MiniRequestObject)
  ))
_sym_db.RegisterMessage(MiniRequestObject)
_sym_db.RegisterMessage(MiniRequestObject.HeadersEntry)
_sym_db.RegisterMessage(MiniRequestObject.SetHeadersEntry)
_sym_db.RegisterMessage(MiniRequestObject.ParamsEntry)
_sym_db.RegisterMessage(MiniRequestObject.AddParamsEntry)
_sym_db.RegisterMessage(MiniRequestObject.ExtendedParamsEntry)


_MINIREQUESTOBJECT_HEADERSENTRY._options = None
_MINIREQUESTOBJECT_SETHEADERSENTRY._options = None
_MINIREQUESTOBJECT_PARAMSENTRY._options = None
_MINIREQUESTOBJECT_ADDPARAMSENTRY._options = None
_MINIREQUESTOBJECT_EXTENDEDPARAMSENTRY._options = None
# @@protoc_insertion_point(module_scope)
