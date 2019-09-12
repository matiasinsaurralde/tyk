# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: coprocess_response_object.proto

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
  name='coprocess_response_object.proto',
  package='coprocess',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\x1f\x63oprocess_response_object.proto\x12\tcoprocess\x1a coprocess_return_overrides.proto\"\xae\x01\n\x0eResponseObject\x12\x13\n\x0bstatus_code\x18\x01 \x01(\x05\x12\x10\n\x08raw_body\x18\x02 \x01(\x0c\x12\x0c\n\x04\x62ody\x18\x03 \x01(\t\x12\x37\n\x07headers\x18\x04 \x03(\x0b\x32&.coprocess.ResponseObject.HeadersEntry\x1a.\n\x0cHeadersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x62\x06proto3')
  ,
  dependencies=[coprocess__return__overrides__pb2.DESCRIPTOR,])




_RESPONSEOBJECT_HEADERSENTRY = _descriptor.Descriptor(
  name='HeadersEntry',
  full_name='coprocess.ResponseObject.HeadersEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='coprocess.ResponseObject.HeadersEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='coprocess.ResponseObject.HeadersEntry.value', index=1,
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
  serialized_start=209,
  serialized_end=255,
)

_RESPONSEOBJECT = _descriptor.Descriptor(
  name='ResponseObject',
  full_name='coprocess.ResponseObject',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='status_code', full_name='coprocess.ResponseObject.status_code', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='raw_body', full_name='coprocess.ResponseObject.raw_body', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='body', full_name='coprocess.ResponseObject.body', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='headers', full_name='coprocess.ResponseObject.headers', index=3,
      number=4, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[_RESPONSEOBJECT_HEADERSENTRY, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=81,
  serialized_end=255,
)

_RESPONSEOBJECT_HEADERSENTRY.containing_type = _RESPONSEOBJECT
_RESPONSEOBJECT.fields_by_name['headers'].message_type = _RESPONSEOBJECT_HEADERSENTRY
DESCRIPTOR.message_types_by_name['ResponseObject'] = _RESPONSEOBJECT
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ResponseObject = _reflection.GeneratedProtocolMessageType('ResponseObject', (_message.Message,), dict(

  HeadersEntry = _reflection.GeneratedProtocolMessageType('HeadersEntry', (_message.Message,), dict(
    DESCRIPTOR = _RESPONSEOBJECT_HEADERSENTRY,
    __module__ = 'coprocess_response_object_pb2'
    # @@protoc_insertion_point(class_scope:coprocess.ResponseObject.HeadersEntry)
    ))
  ,
  DESCRIPTOR = _RESPONSEOBJECT,
  __module__ = 'coprocess_response_object_pb2'
  # @@protoc_insertion_point(class_scope:coprocess.ResponseObject)
  ))
_sym_db.RegisterMessage(ResponseObject)
_sym_db.RegisterMessage(ResponseObject.HeadersEntry)


_RESPONSEOBJECT_HEADERSENTRY._options = None
# @@protoc_insertion_point(module_scope)
