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

import logging
import six

from kmip.core.enums import AttributeType
from kmip.core.enums import CryptographicAlgorithm
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import ObjectType
from kmip.core.enums import ResultStatus

from kmip.core.factories.attributes import AttributeFactory

from kmip.core.objects import CommonTemplateAttribute
from kmip.core.objects import TemplateAttribute

from kmip.pie.factory import ObjectFactory

from kmip.pie.exceptions import ClientConnectionFailure
from kmip.pie.exceptions import ClientConnectionNotOpen
from kmip.pie.exceptions import KmipOperationFailure

from kmip.pie.objects import Key

from kmip.services.kmip_client import KMIPProxy


class KmipClient:
    """
    A simplified PyKMIP client for conducting KMIP operations.

    The KmipClient provides a simpler external interface for various KMIP
    operations and composes the bulk of the PyKMIP Pie API. It wraps the
    original KMIPProxy, reducing the boilerplate needed to deploy PyKMIP
    in client applications.
    """
    def __init__(self,
                 hostname=None,
                 port=None,
                 cert=None,
                 key=None,
                 ca=None,
                 config='client'):
        """
        Construct a KMIPClient.

        Args:
            hostname (string): The host or IP address of a KMIP appliance.
            port (int): The port number used to establish a connection to a
                KMIP appliance. Usually 5696 for KMIP applications.
            cert (string): The path to the client's certificate.
            key (string): The path to the key for the client's certificate.
            ca (string): The path to the CA certificate used to verify the
                server's certificate.
            config (string): The name of a section in the PyKMIP configuration
                file. Use to load a specific set of configuration settings from
                the configuration file, instead of specifying them manually.
        """
        self.logger = logging.getLogger()

        self.attribute_factory = AttributeFactory()
        self.object_factory = ObjectFactory()

        self.proxy = KMIPProxy(
            host=hostname,
            port=port,
            certfile=cert,
            keyfile=key,
            ca_certs=ca,
            config=config)

        self._is_open = False

    def open(self):
        """
        Open the client connection.

        Raises:
            ClientConnectionFailure: if the client connection is already open
            Exception: if an error occurs while trying to open the connection
        """
        if self._is_open:
            raise ClientConnectionFailure("client connection already open")
        else:
            try:
                self.proxy.open()
                self._is_open = True
            except Exception as e:
                self.logger.exception("could not open client connection", e)
                raise e

    def close(self):
        """
        Close the client connection.

        Raises:
            ClientConnectionNotOpen: if the client connection is not open
            Exception: if an error occurs while trying to close the connection
        """
        if not self._is_open:
            raise ClientConnectionNotOpen()
        else:
            try:
                self.proxy.close()
                self._is_open = False
            except Exception as e:
                self.logger.exception("could not close client connection", e)
                raise e

    def create_symmetric_key(self, algorithm, length):
        """
        Create a symmetric key secret on a KMIP appliance.

        Args:
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the symmetric key.
            length (int): The length in bits for the symmetric key.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid
        """
        # Check inputs
        if not isinstance(algorithm, CryptographicAlgorithm):
            raise TypeError(
                "algorithm must be a CryptographicAlgorithm enumeration")
        elif not isinstance(length, six.integer_types) or length <= 0:
            raise TypeError("length must be a positive integer")

        # Verify that operations can be given at this time
        if not self._is_open:
            raise ClientConnectionNotOpen()

        # Create the algorithm, length, and usage mask attributes
        algorithm_attribute = self.attribute_factory.create_attribute(
            AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            AttributeType.CRYPTOGRAPHIC_LENGTH,
            length)
        mask_attribute = self.attribute_factory.create_attribute(
            AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT])

        # Create the template containing the attributes
        attributes = [algorithm_attribute, length_attribute, mask_attribute]
        template = TemplateAttribute(attributes=attributes)

        # Create the symmetric key and handle the results
        result = self.proxy.create(ObjectType.SYMMETRIC_KEY, template)

        status = result.result_status.enum
        if status == ResultStatus.SUCCESS:
            uid = result.uuid.value
            return uid
        else:
            reason = result.result_reason.enum
            message = result.result_message.value
            raise KmipOperationFailure(status, reason, message)

    def create_asymmetric_key_pair(self, algorithm, length):
        """
        Create an asymmetric key pair on a KMIP appliance.

        Args:
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the key pair.
            length (int): The length in bits for the key pair.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid
        """
        # Check inputs
        if not isinstance(algorithm, CryptographicAlgorithm):
            raise TypeError(
                "algorithm must be a CryptographicAlgorithm enumeration")
        elif not isinstance(length, six.integer_types) or length <= 0:
            raise TypeError("length must be a positive integer")

        # Verify that operations can be given at this time
        if not self._is_open:
            raise ClientConnectionNotOpen()

        # Create the algorithm, length, and usage mask attributes
        algorithm_attribute = self.attribute_factory.create_attribute(
            AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            AttributeType.CRYPTOGRAPHIC_LENGTH,
            length)
        mask_attribute = self.attribute_factory.create_attribute(
            AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT])

        # Create the template containing the attributes
        attributes = [algorithm_attribute, length_attribute, mask_attribute]
        template = CommonTemplateAttribute(attributes=attributes)

        # Create the asymmetric key pair and handle the results
        result = self.proxy.create_key_pair(common_template_attribute=template)

        status = result.result_status.enum
        if status == ResultStatus.SUCCESS:
            public_uid = result.public_key_uuid.value
            private_uid = result.private_key_uuid.value
            return public_uid, private_uid
        else:
            reason = result.result_reason.enum
            message = result.result_message.value
            raise KmipOperationFailure(status, reason, message)

    def register_key(self, key):
        """
        Register a symmetric or asymmetric key with a KMIP appliance.

        Args:
            key (various): A key to register. Usually a SymmetricKey,
                PublicKey, or PrivateKey from the Pie API.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input argument is invalid
        """
        # Check input
        if not isinstance(key, Key):
            raise TypeError("key must be a Key object")

        # Verify that operations can be given at this time
        if not self._is_open:
            raise ClientConnectionNotOpen()

        # Extract and create attributes
        mask_attribute = self.attribute_factory.create_attribute(
            AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            key.cryptographic_usage_masks)

        attributes = [mask_attribute]
        template = TemplateAttribute(attributes=attributes)

        object_type = key.object_type

        # Register the secret and handle the results
        secret = self.object_factory.convert(key)
        result = self.proxy.register(object_type, template, secret)

        status = result.result_status.enum
        if status == ResultStatus.SUCCESS:
            uid = result.uuid.value
            return uid
        else:
            reason = result.result_reason.enum
            message = result.result_message.value
            raise KmipOperationFailure(status, reason, message)

    def get_secret(self, uid):
        """
        Get a secret from a KMIP appliance.

        Args:
            uid (string): The unique ID of the secret to retrieve.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input argument is invalid
        """
        # Check input
        if not isinstance(uid, six.string_types):
            raise TypeError("uid must be a string")

        # Verify that operations can be given at this time
        if not self._is_open:
            raise ClientConnectionNotOpen()

        # Get the secret and handle the results
        result = self.proxy.get(uid)

        status = result.result_status.enum
        if status == ResultStatus.SUCCESS:
            secret = self.object_factory.convert(result.secret)
            return secret
        else:
            reason = result.result_reason.enum
            message = result.result_message.value
            raise KmipOperationFailure(status, reason, message)

    def destroy_secret(self, uid):
        """
        Destroy a secret stored by a KMIP appliance.

        Args:
            uid (string): The unique ID of the secret to destroy.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input argument is invalid
        """
        # Check input
        if not isinstance(uid, six.string_types):
            raise TypeError("uid must be a string")

        # Verify that operations can be given at this time
        if not self._is_open:
            raise ClientConnectionNotOpen()

        # Destroy the secret and handle the results
        result = self.proxy.destroy(uid)

        status = result.result_status.enum
        if status == ResultStatus.SUCCESS:
            return
        else:
            reason = result.result_reason.enum
            message = result.result_message.value
            raise KmipOperationFailure(status, reason, message)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
