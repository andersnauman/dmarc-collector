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

from dmarcanalyzer.elastic import ElasticManager
from dmarcanalyzer.elastic.mappings import AggregateReport, ForensicReport, ForensicSample, FORENSIC_ALIAS, AGGREGATE_ALIAS

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", help="elastic search host")
    parser.add_argument("-u", "--user", help="elastic search user")
    parser.add_argument("-p", "--password", help="elastic search password")
    args = parser.parse_args()

    run_args = {}
    run_args["log_level"] = logging.DEBUG
    run_args["folder"] = "example"
    run_args["recursive"] = True

    files = dmarc_from_folder(**run_args)

    if not files:
        print("No reports were found. Exiting")
        sys.exit(0)
    print("")
    print("")
    print("")
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
            es = ElasticManager(args.host, args.user, args.password, verify_certs=False)
        except (exceptions.ConnectionError, exceptions.ConnectionTimeout) as _error:
            print("Connection error: ", _error)
        except exceptions.AuthenticationException as _error:
            print("Authentication error: ", _error)
        else:
            NOT_READY = False
            continue
        finally:
            time.sleep(1)

    for report in all_reports:
        if "type" in report and report["type"] == "aggregate":
#            for key, value in report["report"].items():
#                print("\t", key, value)

            a = AggregateReport(**report["report"])
            if not es.index_exist(AGGREGATE_ALIAS):
                print("Create status: ", es.create_index(AGGREGATE_ALIAS))
            es.save_document(a)

        elif "type" in report and report["type"] == "forensic":
#            for key, value in report["report"].items():
#                print("\t", key, value)

#            for key, value in report["sample"].items():
#                print("\t", key, value)

            f = ForensicReport(**report["report"])
            f.sample = ForensicSample(**report["sample"])

            if not es.index_exist(FORENSIC_ALIAS):
                print("Create status: ", es.create_index(FORENSIC_ALIAS))

            # Search for report.
            # If it exist already, ignore and continue with next report
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
                print("report exist already")
                continue
            es.save_document(f)
            #es.refresh()
