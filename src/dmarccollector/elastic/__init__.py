#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC analyzer """

import sys
import logging
import json
from datetime import datetime

from typing import Mapping
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import RequestError

from elasticsearch_dsl import IndexTemplate, Document

from .mappings import ForensicReport, AggregateReport
from .mappings import FORENSIC_PATTERN, FORENSIC_ALIAS, AGGREGATE_PATTERN, AGGREGATE_ALIAS

class ElasticManager:
    """ Elasticsearch manager to create and use a client connection. """
    # pylint: disable-next=line-too-long,R0913:too-many-arguments
    def __init__(self, host: str, username: str, password: str, verify_certs: bool = True, logger: logging.Logger = None) -> None:
        if not logger:
            self.logger = logging.getLogger("ElasticManager")
            self.logger.addHandler(logging.NullHandler())
        else:
            self.logger = logger
        if not username or not password:
            raise ValueError("Missing username or password")
        if not verify_certs:
            # pylint: disable-next=C0415:import-outside-toplevel
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self._es_client = Elasticsearch(
            host,
            request_timeout = 3,
            #ca_certs = "/path/to/http_ca.crt",
            verify_certs = verify_certs,
            http_auth = (username, password)
        )

        self.logger.info(self._es_client.info())
        self.logger.debug("ES is ready for connections")

    def create_index(self, index: str) -> bool:
        """
        Create an index if needed.
        Returns True if the index exist or is created by this method.
        """
        if self.index_exist(index):
            return True

        if index.startswith("forensic-report"):
            self.logger.debug("Creating index: %s", index)

            # pylint: disable-next=W0212:protected-access
            index_template = ForensicReport._index.as_template(FORENSIC_ALIAS, FORENSIC_PATTERN)
            index_template.save(using=self._es_client)

            # pylint: disable-next=W0212:protected-access
            if not ForensicReport._index.exists(using=self._es_client):
                #ForensicReport.init(using=self._es_client)
                self.migrate(
                    alias=FORENSIC_ALIAS,
                    pattern=FORENSIC_PATTERN,
                    move_data=False,
                )
            return True

        if index.startswith("aggregate-report"):
            self.logger.debug("Creating index: %s", index)

            # pylint: disable-next=W0212:protected-access
            index_template = AggregateReport._index.as_template(AGGREGATE_ALIAS, AGGREGATE_PATTERN)
            index_template.save(using=self._es_client)

            # pylint: disable-next=W0212:protected-access
            if not AggregateReport._index.exists(using=self._es_client):
                #ForensicReport.init(using=self._es_client)
                self.migrate(
                    alias=AGGREGATE_ALIAS,
                    pattern=AGGREGATE_PATTERN,
                    move_data=False,
                )
            return True

        return False

    def index_exist(self, index: str) -> bool:
        """ Simple method to check if the index exist """
        if not self._es_client.indices.exists(index=index):
            return False
        return True

    def get_mapping(self, index: str) -> json:
        """ Get mapping from an index """
        return json.dumps(self._es_client.indices.get_mapping(index=index))

    def get_client(self):
        """
        Fail-safe if there is a need to use 'using' outside this class.
        (Write a method for the task instead!)
        """
        return self._es_client

    def save_index(self, template: IndexTemplate):
        """
        'Overcome "Legacy index templates are deprecated" warning'
        https://github.com/elastic/elasticsearch-dsl-py/issues/1576
        """
        template_body = template.to_dict()
        index_patterns = template_body.pop("index_patterns")
        order = template_body.pop("order", None)

        body = {
            "template": template_body,
            "index_patterns": index_patterns,
            "composed_of": [],
        }
        if order is not None:
            body["priority"] = order

        # pylint: disable-next=W0212:protected-access
        return self._es_client.indices.put_index_template(name=template._template_name, body=body)

    def refresh(self, index: str = None):
        """ d """
        if not index:
            return
        self._es_client.indices.refresh(index)

    def save_document(self, document: Document):
        """ Wrapper to save document with 'using' """
        return document.save(using=self._es_client, refresh=True)

    # pylint: disable-next=line-too-long
    def migrate(self, pattern: str = None, alias: str = None, move_data: bool = True, update_alias: bool = True):
        """
        https://github.com/elastic/elasticsearch-dsl-py/blob/main/examples/alias_migration.py
        """
        next_index = pattern.replace("*", datetime.now().strftime("%Y%m%d%H%M%S%f"))

        self._es_client.indices.create(index=next_index)

        if move_data:
            self._es_client.reindex(
                body={"source": {"index": alias}, "dest": {"index": next_index}},
            )
            self._es_client.indices.refresh(index=next_index)

        if update_alias:
            self._es_client.indices.update_aliases(
                body={
                    "actions": [
                        {"remove": {"alias": alias, "index": pattern}},
                        {"add": {"alias": alias, "index": next_index}},
                    ]
                }
            )
