#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Test module """

import unittest

from elasticsearch import exceptions
from dmarccollector.elastic import ElasticManager

class MyTestCase(unittest.TestCase):
    """ s """
    def test_failed_connection(self):
        """ Test a normal """
        with self.assertRaises(exceptions.ConnectionError):
            ElasticManager(
                host="127.0.0.1",
                username="bad_user",
                password="bad_password",
            )

if __name__ == '__main__':
    unittest.main()
