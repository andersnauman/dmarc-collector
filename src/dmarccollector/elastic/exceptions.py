#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC analyzer """

class _AlreadyExistError(Exception):
    """ Exception raised when object already exist """
    def __init__(self, msg):
        super().__init__(msg)
