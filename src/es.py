#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC analyzer """

import sys
import time
import argparse
import logging

from elasticsearch import exceptions
from elasticsearch_dsl import Search, Q

from dmarcparser import dmarc_from_folder

from dmarccollector.elastic import ElasticManager
from dmarccollector.elastic.mappings import AggregateReport, ForensicReport, ForensicSample
from dmarccollector.elastic.mappings import  FORENSIC_ALIAS, AGGREGATE_ALIAS

def _create_logger(log_level: int = logging.INFO):
    """ Create a logger """
    formatter = logging.Formatter(
        fmt='%(asctime)s %(thread)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    _logger = logging.getLogger("ElasticManager")
    _logger.setLevel(log_level)

    # Screen logger
    screen_handler = logging.StreamHandler(stream=sys.stdout)
    screen_handler.setFormatter(formatter)
    _logger.addHandler(screen_handler)

    return _logger

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
        DMARC Collector. Digest input data from folders/files and inserts parsed data into databases.
        """
    )
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")

    required_args = parser.add_argument_group('required arguments')
    required_args.add_argument("--host", help="elastic search host", required=True)
    required_args.add_argument("-u", "--user", help="elastic search user", required=True)
    required_args.add_argument("-p", "--password", help="elastic search password", required=True)

    args = parser.parse_args()

    run_args = {}
    if args.verbose:
        run_args["log_level"] = logging.DEBUG
    else:
        run_args["log_level"] = logging.INFO
    run_args["folder"] = "example"
    run_args["recursive"] = True

    logger = _create_logger(log_level=run_args["log_level"])

    files = dmarc_from_folder(**run_args)

    if not files:
        logger.debug("No reports were found. Exiting")
        sys.exit(0)

    # {"<hash>": [{"type": ..., "report": ...}]}
    # [{"type": ..., "report": ...}]
    all_reports = []
    forensic_reports = []
    aggregate_reports = []
    for _, reports in files.items():
        all_reports.extend(reports)

    NOT_READY = True
    while NOT_READY:
        try:
            es = ElasticManager(
                host = args.host,
                username = args.user,
                password = args.password,
                verify_certs = False,
                logger = logger,
            )
        except (exceptions.ConnectionError, exceptions.ConnectionTimeout) as _error:
            logger.debug("Connection error: %s", _error)
        except exceptions.AuthenticationException as _error:
            logger.debug("Authentication error: %s", _error)
        else:
            NOT_READY = False
            continue
        finally:
            time.sleep(1)

    for report in all_reports:
        if "type" in report and report["type"] == "aggregate":
            if "report" not in report:
                continue
            a = AggregateReport(**report["report"])

            if not es.index_exist(AGGREGATE_ALIAS):
                if not es.create_index(AGGREGATE_ALIAS):
                    es.logger.debug("Could not create index for aggregated report")
                    continue

            # Try see if the report already exist
            # If it exist already, ignore and continue with next report
            query = Q("match", metadata__report_id = a.metadata.report_id)
            search = Search(using=es.get_client(), index=AGGREGATE_ALIAS).query(query)
            results = search.execute()
            if len(results):
                es.logger.debug("report exist already")
                continue
            es.save_document(a)

        elif "type" in report and report["type"] == "forensic":
            if "report" not in report:
                continue
            f = ForensicReport(**report["report"])

            if "sample" in report:
                f.sample = ForensicSample(**report["sample"])

            if not es.index_exist(FORENSIC_ALIAS):
                if not es.create_index(FORENSIC_ALIAS):
                    es.logger.debug("Could not create index for forensic report")
                    continue

            # Try see if the report already exist
            # If it exist already, ignore and continue with next report
            # Following fields makes up the 'index' / match:
            #   'arrival_date' + 'original_mail_from__address' + 'all original_rcpt_to.address'
            query = Q("match", arrival_date=f.arrival_date) & \
                    Q("match", original_mail_from__address=f.original_mail_from.address)
            if f.original_rcpt_to:
                for rcpt_to in f.original_rcpt_to:
                    query &= Q({
                        "nested": {
                            "path": "original_rcpt_to",
                            "query": {
                                "match": {
                                    "original_rcpt_to.address": rcpt_to.address,
                                },
                            },
                        },
                    })

            search = Search(using=es.get_client(), index=FORENSIC_ALIAS).query(query)
            results = search.execute()
            if len(results):
                es.logger.debug("report exist already")
                continue
            es.save_document(f)
