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

from kmip.core.enums import Operation

from kmip.demos import utils

from kmip.pie.client import KmipClient

import logging
import os
import sys


if __name__ == '__main__':
    # Build and parse arguments
    parser = utils.build_cli_parser(Operation.DESTROY)
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config
    uid = opts.uuid

    # Exit early if the UUID is not specified
    if uid is None:
        logging.debug('No UUID provided, exiting early from demo')
        sys.exit()

    # Build and setup logging and needed factories
    f_log = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir,
                         'logconfig.ini')
    logging.config.fileConfig(f_log)
    logger = logging.getLogger(__name__)

    # Build the client and connect to the server
    with KmipClient(config=config) as client:
        try:
            client.destroy_secret(uid)
            logger.info("Successfully destroyed secret with ID: {0}".format(
                uid))
        except Exception as e:
            logger.error(e)
