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

from abc import ABCMeta
from abc import abstractmethod

import binascii
import six

from kmip.core.enums import CryptographicAlgorithm
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import KeyFormatType
from kmip.core.enums import ObjectType


@six.add_metaclass(ABCMeta)
class ManagedObject:
    """
    The abstract base class of the simplified KMIP object hierarchy.

    A ManagedObject is a core KMIP object that is the subject of key
    management operations. It contains various attributes that are common to
    all types of ManagedObjects, including keys, certificates, and various
    types of secret or sensitive data.

    For more information, see Section 2.2 of the KMIP 1.1 specification.

    Attributes:
        value: The value of the ManagedObject. Type varies, usually bytes.
        unique_identifier: The string ID of the ManagedObject.
        names: A list of names associated with the ManagedObject.
        object_type: An enumeration associated with the type of ManagedObject.
    """

    @abstractmethod
    def __init__(self):
        """
        Create a ManagedObject.
        """
        self.value = None

        self.unique_identifier = None
        self.names = list()
        self._object_type = None

        # All remaining attributes are not considered part of the public API
        # and are subject to change.
        self._application_specific_informations = list()
        self._contact_information = None
        self._object_groups = list()
        self._operation_policy_name = None

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._archive_date = None
        self._initial_date = None
        self._last_change_date = None

    @property
    def object_type(self):
        """
        Accessor and property definition for the object type attribute.

        Returns:
            ObjectType: An ObjectType enumeration that corresponds to the
                class of the object.
        """
        return self._object_type

    @object_type.setter
    def object_type(self, value):
        """
        Set blocker for the object type attribute.

        Raises:
            AttributeError: Always raised to block setting of attribute.
        """
        raise AttributeError("object type cannot be set")

    @abstractmethod
    def validate(self):
        """
        Verify that the contents of the ManagedObject are valid.
        """
        pass

    @abstractmethod
    def __repr__(self):
        pass

    @abstractmethod
    def __str__(self):
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __ne__(self, other):
        pass


class CryptographicObject(ManagedObject):
    """
    The abstract base class of all ManagedObjects related to cryptography.

    A CryptographicObject is a core KMIP object that is the subject of key
    management operations. It contains various attributes that are common to
    all types of CryptographicObjects, including keys and certificates.

    For more information, see Section 2.2 of the KMIP 1.1 specification.

    Attributes:
        cryptographic_usage_masks: A list of usage mask enumerations
            describing how the CryptographicObject will be used.
    """

    @abstractmethod
    def __init__(self):
        """
        Create a CryptographicObject.
        """

        super(CryptographicObject, self).__init__()

        self.cryptographic_usage_masks = list()

        # All remaining attributes are not considered part of the public API
        # and are subject to change.
        self._digests = list()

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._activation_date = None
        self._compromise_date = None
        self._compromise_occurrence_date = None
        self._deactivation_date = None
        self._destroy_date = None
        self._fresh = None
        self._lease_time = None
        self._links = list()
        self._revocation_reason = None
        self._state = None


class Key(CryptographicObject):
    """
    The abstract base class of all ManagedObjects that are cryptographic keys.

    A Key is a core KMIP object that is the subject of key management
    operations. It contains various attributes that are common to all types of
    Keys, including symmetric and asymmetric keys.

    For more information, see Section 2.2 of the KMIP 1.1 specification.

    Attributes:
        cryptographic_algorithm: A CryptographicAlgorithm enumeration defining
            the algorithm the key should be used with.
        cryptographic_length: An int defining the length of the key in bits.
        key_format_type: A KeyFormatType enumeration defining the format of
            the key value.
    """

    @abstractmethod
    def __init__(self):
        """
        Create a Key object.
        """
        super(Key, self).__init__()

        self.cryptographic_algorithm = None
        self.cryptographic_length = None
        self.key_format_type = None

        # All remaining attributes are not considered part of the public API
        # and are subject to change.
        self._cryptographic_parameters = list()

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._usage_limits = None


class SymmetricKey(Key):
    """
    The SymmetricKey class of the simplified KMIP object hierarchy.

    A SymmetricKey is a core KMIP object that is the subject of key
    management operations. For more information, see Section 2.2 of the KMIP
    1.1 specification.

    Attributes:
        cryptographic_algorithm: The type of algorithm for the SymmetricKey.
        cryptographic_length: The length in bits of the SymmetricKey value.
        value: The bytes of the SymmetricKey.
        format_type: The format of the key value.
        cryptographic_usage_masks: The list of usage mask flags for
            SymmetricKey application.
        names: The string names of the SymmetricKey.
    """

    def __init__(self, algorithm, length, value, format_type, masks=None,
                 name='Symmetric Key'):
        """
        Create a SymmetricKey.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration identifying the
                type of algorithm for the key.
            length(int): The length in bits of the key.
            value(bytes): The bytes representing the key.
            format_type(KeyFormatType): An enumeration defining the format of
                the key value.
            masks(list): A list of CryptographicUsageMask enumerations defining
                how the key will be used.
            name(string): The string name of the key.
        """
        super(SymmetricKey, self).__init__()

        self._object_type = ObjectType.SYMMETRIC_KEY

        self.value = value
        self.cryptographic_algorithm = algorithm
        self.cryptographic_length = length
        self.key_format_type = format_type
        self.names = [name]

        if masks:
            self.cryptographic_usage_masks = masks
        else:
            self.cryptographic_usage_masks = list()

        # All remaining attributes are not considered part of the public API
        # and are subject to change.

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._process_start_date = None
        self._protect_stop_date = None

        self.validate()

    def validate(self):
        """
        Verify that the contents of the SymmetricKey object are valid.

        Raises:
            TypeError: if the types of any SymmetricKey attributes are invalid
            ValueError: if the key length and key value length do not match
        """
        if not isinstance(self.value, bytes):
            raise TypeError("key value must be bytes")
        elif not isinstance(self.cryptographic_algorithm,
                            CryptographicAlgorithm):
            raise TypeError("key algorithm must be a CryptographicAlgorithm "
                            "enumeration")
        elif not isinstance(self.cryptographic_length, six.integer_types):
            raise TypeError("key length must be an integer")
        elif not isinstance(self.key_format_type, KeyFormatType):
            raise TypeError("key format type must be a KeyFormatType "
                            "enumeration")
        elif not isinstance(self.cryptographic_usage_masks, list):
            raise TypeError("key usage masks must be a list")

        mask_count = len(self.cryptographic_usage_masks)
        for i in range(mask_count):
            mask = self.cryptographic_usage_masks[i]
            if not isinstance(mask, CryptographicUsageMask):
                position = "({0} in list)".format(i)
                raise TypeError(
                    "key mask {0} must be a CryptographicUsageMask "
                    "enumeration".format(position))

        name_count = len(self.names)
        for i in range(name_count):
            name = self.names[i]
            if not isinstance(name, six.string_types):
                position = "({0} in list)".format(i)
                raise TypeError("key name {0} must be a string".format(
                    position))

        if (len(self.value) * 8) != self.cryptographic_length:
            msg = "key length ({0}) not equal to key value length ({1})"
            msg = msg.format(self.cryptographic_length, len(self.value) * 8)
            raise ValueError(msg)

    def __repr__(self):
        algorithm = "algorithm={0}".format(self.cryptographic_algorithm)
        length = "length={0}".format(self.cryptographic_length)
        value = "value={0}".format(binascii.hexlify(self.value))
        format_type = "format_type={0}".format(self.key_format_type)

        return "SymmetricKey({0}, {1}, {2}, {3})".format(
            algorithm, length, value, format_type)

    def __str__(self):
        return str(binascii.hexlify(self.value))

    def __eq__(self, other):
        if isinstance(other, SymmetricKey):
            if self.value != other.value:
                return False
            elif self.key_format_type != other.key_format_type:
                return False
            elif self.cryptographic_algorithm != other.cryptographic_algorithm:
                return False
            elif self.cryptographic_length != other.cryptographic_length:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, SymmetricKey):
            return not (self == other)
        else:
            return NotImplemented


class PublicKey(Key):
    """
    The PublicKey class of the simplified KMIP object hierarchy.

    A PublicKey is a core KMIP object that is the subject of key management
    operations. For more information, see Section 2.2 of the KMIP 1.1
    specification.

    Attributes:
        cryptographic_algorithm: The type of algorithm for the PublicKey.
        cryptographic_length: The length in bits of the PublicKey.
        value: The bytes of the PublicKey.
        format_type: The format of the key value.
        cryptographic_usage_masks: The list of usage mask flags for PublicKey
            application.
        names: The list of string names of the PublicKey.
    """

    def __init__(self, algorithm, length, value, format_type, masks=None,
                 name='Public Key'):
        """
        Create a PublicKey.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration identifying the
                type of algorithm for the key.
            length(int): The length in bits of the key.
            value(bytes): The bytes representing the key.
            format_type(KeyFormatType): An enumeration defining the format of
                the key value.
            masks(list): A list of CryptographicUsageMask enumerations
                defining how the key will be used.
            name(string): The string name of the key.
        """
        super(PublicKey, self).__init__()

        self._object_type = ObjectType.PUBLIC_KEY

        self.value = value
        self.cryptographic_algorithm = algorithm
        self.cryptographic_length = length
        self.key_format_type = format_type
        self.names = [name]

        if masks:
            self.cryptographic_usage_masks = masks
        else:
            self.cryptographic_usage_masks = list()

        # All remaining attributes are not considered part of the public API
        # and are subject to change.

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._cryptographic_domain_parameters = list()

        self.validate()

    def validate(self):
        """
        Verify that the contents of the PublicKey object are valid.

        Raises:
            TypeError: if the types of any PublicKey attributes are invalid.
        """
        if not isinstance(self.value, bytes):
            raise TypeError("key value must be bytes")
        elif not isinstance(self.cryptographic_algorithm,
                            CryptographicAlgorithm):
            raise TypeError("key algorithm must be a CryptographicAlgorithm "
                            "enumeration")
        elif not isinstance(self.cryptographic_length, six.integer_types):
            raise TypeError("key length must be an integer")
        elif not isinstance(self.key_format_type, KeyFormatType):
            raise TypeError("key format type must be a KeyFormatType "
                            "enumeration")
        elif not isinstance(self.cryptographic_usage_masks, list):
            raise TypeError("key usage masks must be a list")

        mask_count = len(self.cryptographic_usage_masks)
        for i in range(mask_count):
            mask = self.cryptographic_usage_masks[i]
            if not isinstance(mask, CryptographicUsageMask):
                position = "({0} in list)".format(i)
                raise TypeError(
                    "key mask {0} must be a CryptographicUsageMask "
                    "enumeration".format(position))

        name_count = len(self.names)
        for i in range(name_count):
            name = self.names[i]
            if not isinstance(name, six.string_types):
                position = "({0} in list)".format(i)
                raise TypeError("key name {0} must be a string".format(
                    position))

    def __repr__(self):
        algorithm = "algorithm={0}".format(self.cryptographic_algorithm)
        length = "length={0}".format(self.cryptographic_length)
        value = "value={0}".format(binascii.hexlify(self.value))
        format_type = "format_type={0}".format(self.key_format_type)

        return "PublicKey({0}, {1}, {2}, {3})".format(
            algorithm, length, value, format_type)

    def __str__(self):
        return str(binascii.hexlify(self.value))

    def __eq__(self, other):
        if isinstance(other, PublicKey):
            if self.value != other.value:
                return False
            elif self.key_format_type != other.key_format_type:
                return False
            elif self.cryptographic_algorithm != other.cryptographic_algorithm:
                return False
            elif self.cryptographic_length != other.cryptographic_length:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, PublicKey):
            return not (self == other)
        else:
            return NotImplemented


class PrivateKey(Key):
    """
    The PrivateKey class of the simplified KMIP object hierarchy.

    A PrivateKey is a core KMIP object that is the subject of key management
    operations. For more information, see Section 2.2 of the KMIP 1.1
    specification.

    Attributes:
        cryptographic_algorithm: The type of algorithm for the PrivateKey.
        cryptographic_length: The length in bits of the PrivateKey.
        value: The bytes of the PrivateKey.
        format_type: The format of the key value.
        cryptographic_usage_masks: The list of usage mask flags for PrivateKey
            application.
        names: The list of string names of the PrivateKey.
    """

    def __init__(self, algorithm, length, value, format_type, masks=None,
                 name='Private Key'):
        """
        Create a PrivateKey.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration identifying the
                type of algorithm for the key.
            length(int): The length in bits of the key.
            value(bytes): The bytes representing the key.
            format_type(KeyFormatType): An enumeration defining the format of
                the key value.
            masks(list): A list of CryptographicUsageMask enumerations
                defining how the key will be used.
            name(string): The string name of the key.
        """
        super(PrivateKey, self).__init__()

        self._object_type = ObjectType.PRIVATE_KEY

        self.value = value
        self.cryptographic_algorithm = algorithm
        self.cryptographic_length = length
        self.key_format_type = format_type
        self.names = [name]

        if masks:
            self.cryptographic_usage_masks = masks
        else:
            self.cryptographic_usage_masks = list()

        # All remaining attributes are not considered part of the public API
        # and are subject to change.

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._cryptographic_domain_parameters = list()

        self.validate()

    def validate(self):
        """
        Verify that the contents of the PrivateKey object are valid.

        Raises:
            TypeError: if the types of any PrivateKey attributes are invalid.
        """
        if not isinstance(self.value, bytes):
            raise TypeError("key value must be bytes")
        elif not isinstance(self.cryptographic_algorithm,
                            CryptographicAlgorithm):
            raise TypeError("key algorithm must be a CryptographicAlgorithm "
                            "enumeration")
        elif not isinstance(self.cryptographic_length, six.integer_types):
            raise TypeError("key length must be an integer")
        elif not isinstance(self.key_format_type, KeyFormatType):
            raise TypeError("key format type must be a KeyFormatType "
                            "enumeration")
        elif not isinstance(self.cryptographic_usage_masks, list):
            raise TypeError("key usage masks must be a list")

        mask_count = len(self.cryptographic_usage_masks)
        for i in range(mask_count):
            mask = self.cryptographic_usage_masks[i]
            if not isinstance(mask, CryptographicUsageMask):
                position = "({0} in list)".format(i)
                raise TypeError(
                    "key mask {0} must be a CryptographicUsageMask "
                    "enumeration".format(position))

        name_count = len(self.names)
        for i in range(name_count):
            name = self.names[i]
            if not isinstance(name, six.string_types):
                position = "({0} in list)".format(i)
                raise TypeError("key name {0} must be a string".format(
                    position))

    def __repr__(self):
        algorithm = "algorithm={0}".format(self.cryptographic_algorithm)
        length = "length={0}".format(self.cryptographic_length)
        value = "value={0}".format(binascii.hexlify(self.value))
        format_type = "format_type={0}".format(self.key_format_type)

        return "PrivateKey({0}, {1}, {2}, {3})".format(
            algorithm, length, value, format_type)

    def __str__(self):
        return str(binascii.hexlify(self.value))

    def __eq__(self, other):
        if isinstance(other, PrivateKey):
            if self.value != other.value:
                return False
            elif self.key_format_type != other.key_format_type:
                return False
            elif self.cryptographic_algorithm != other.cryptographic_algorithm:
                return False
            elif self.cryptographic_length != other.cryptographic_length:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, PrivateKey):
            return not (self == other)
        else:
            return NotImplemented
