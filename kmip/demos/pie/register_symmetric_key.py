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

from kmip.core.enums import CryptographicAlgorithm
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import KeyFormatType

from kmip.demos import utils

from kmip.pie.client import KmipClient
from kmip.pie.objects import SymmetricKey

import logging
import sys


if __name__ == '__main__':
    parser = utils.build_cli_parser()
    logger = logging.getLogger(__name__)
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config

    algorithm = CryptographicAlgorithm.AES
    length = 128
    value = (
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
        b'\x0F')
    format_type = KeyFormatType.RAW
    usage_mask = [CryptographicUsageMask.ENCRYPT,
                  CryptographicUsageMask.DECRYPT]
    name = 'Demo Symmetric Key'

    key = SymmetricKey(algorithm, length, value, format_type, usage_mask, name)

    # Build the client and connect to the server
    with KmipClient(config=config) as client:
        try:
            uid = client.register_key(key)
            logger.info("Successfully registered symmetric key with ID: "
                        "{0}".format(uid))
        except Exception as e:
            logger.error(e)
