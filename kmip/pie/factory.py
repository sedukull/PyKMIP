# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from kmip.core import secrets

from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import CryptographicLength

from kmip.core.misc import KeyFormatType

from kmip.core.objects import KeyBlock
from kmip.core.objects import KeyMaterial
from kmip.core.objects import KeyValue

from kmip.pie import objects


class ObjectFactory:
    """
    A factory to convert between the Pie and core object hierarchies.
    """

    def __init__(self):
        """
        Construct an ObjectFactory.
        """
        pass

    def convert(self, obj):
        """
        Convert a Pie object into a core secret object and vice versa.

        Args:
            obj (various): A Pie or core secret object to convert into the
                opposite object space. Required.

        Raises:
            TypeError: if the object type is unrecognized or unsupported.
        """
        if isinstance(obj, objects.SymmetricKey):
            return self._build_core_key(obj, secrets.SymmetricKey)
        elif isinstance(obj, secrets.SymmetricKey):
            return self._build_pie_key(obj, objects.SymmetricKey)
        elif isinstance(obj, objects.PublicKey):
            return self._build_core_key(obj, secrets.PublicKey)
        elif isinstance(obj, secrets.PublicKey):
            return self._build_pie_key(obj, objects.PublicKey)
        elif isinstance(obj, objects.PrivateKey):
            return self._build_core_key(obj, secrets.PrivateKey)
        elif isinstance(obj, secrets.PrivateKey):
            return self._build_pie_key(obj, objects.PrivateKey)
        else:
            raise TypeError("object type unsupported and cannot be converted")

    def _build_pie_key(self, key, cls):
        algorithm = key.key_block.cryptographic_algorithm.enum
        length = key.key_block.cryptographic_length.value
        value = key.key_block.key_value.key_material.value
        format_type = key.key_block.key_format_type.enum

        return cls(algorithm, length, value, format_type)

    def _build_core_key(self, key, cls):
        algorithm = key.cryptographic_algorithm
        length = key.cryptographic_length
        value = key.value
        format_type = key.key_format_type

        key_material = KeyMaterial(value)
        key_value = KeyValue(key_material)
        key_block = KeyBlock(
            key_format_type=KeyFormatType(format_type),
            key_compression_type=None,
            key_value=key_value,
            cryptographic_algorithm=CryptographicAlgorithm(algorithm),
            cryptographic_length=CryptographicLength(length),
            key_wrapping_data=None)

        return cls(key_block)
