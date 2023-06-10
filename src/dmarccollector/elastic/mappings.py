#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" d """

from datetime import datetime

from elasticsearch_dsl import Document, InnerDoc, Object, Text, Date, Ip, Integer, Nested, Keyword

FORENSIC_ALIAS = "forensic-report"
FORENSIC_PATTERN = FORENSIC_ALIAS + "-*"

AGGREGATE_ALIAS = "aggregate-report"
AGGREGATE_PATTERN = AGGREGATE_ALIAS + "-*"


# pylint: disable-next=too-few-public-methods
class EmailAddress(InnerDoc):
    """ d """
    address = Keyword()
    name = Keyword()


class ReportedMTA(InnerDoc):
    """ d """
    name = Keyword()
    name_type = Keyword()


class Received(InnerDoc):
    """ Must be _ since variable names are reserved by python """
    _from = Keyword()
    _by = Keyword()
    _with = Keyword()
    _date = Date()


class ForensicSample(InnerDoc):
    """ d """
    created_date = Date()
    last_updated = Date()

    authentication_results = Text()
    date = Date()
    dkim_signature = Text()
    from_address = Object(EmailAddress)
    message_id = Keyword()
    reply_to_address = Object(EmailAddress)
    # received = Nested(Received)
    received = Keyword(multi=True)
    to_addresses = Nested(EmailAddress)
    subject = Text()


# pylint: disable-next=too-few-public-methods
class ForensicReport(Document):
    """ d """
    created_date = Date()
    last_updated = Date()

    arrival_date = Date()
    auth_failure = Keyword()
    authentication_results = Text()  # https://www.rfc-editor.org/rfc/rfc7001#page-33
    dkim_canonicalized_header = Text()
    dkim_canonicalized_body = Text()
    dkim_domain = Keyword()
    dkim_identity = Keyword()
    dkim_selector = Keyword()
    delivery_result = Text()
    feedback_type = Keyword()
    identity_alignment = Keyword()
    incidents = Keyword()
    original_envelope_id = Keyword(multi=True)
    original_mail_from = Object(EmailAddress)
    original_rcpt_to = Nested(EmailAddress)
    reported_domain = Keyword()
    reported_uri = Keyword(multi=True)
    reporting_mta = Object(ReportedMTA)
    source_ip = Ip()
    user_agent = Text()
    version = Integer()
    sample = Object(ForensicSample)

    # pylint: disable-next=too-few-public-methods
    class Index:
        """ d """
        name = FORENSIC_ALIAS
        settings = {
          "number_of_shards": 1,
          "number_of_replicas": 0,
        }

    # pylint: disable-next=arguments-differ
    def save(self, **kwargs):
        """ Set / overwrite created and last updated time values """
        if not self.created_date:
            self.created_date = datetime.now()
        self.last_updated = datetime.now()
        return super().save(**kwargs)


class AggregateMetadata(InnerDoc):
    """ Metadata """
    org_name = Keyword()
    email = Object(EmailAddress)
    report_id = Keyword()
    date_begin = Date()
    date_end = Date()


class AggregatePolicyPublished(InnerDoc):
    """ Published Policy """
    domain = Keyword()
    adkim = Keyword()
    aspf = Keyword()
    p = Keyword()
    sp = Keyword()
    pct = Integer()


class DKIM(InnerDoc):
    """ d """
    domain = Keyword()
    selector = Keyword()
    result = Keyword()  # none / pass / fail / policy / neutral / temperror / permerror
    human_result = Keyword()


class SPF(InnerDoc):
    """ SPF """
    domain = Keyword()
    result = Keyword()  # none / neutral / pass / fail / softfail / temperror / permerror
    scope = Keyword()  # helo / mfrom


class AggregatePolicyEvaluated(InnerDoc):
    """ Policy Evaluated """
    dkim = Keyword()
    disposition = Keyword()
    spf = Keyword()


class AggregateRow(InnerDoc):
    """ Row """
    count = Integer()
    source_ip = Ip()
    policy_evaluated = Object(AggregatePolicyEvaluated)


class AggregateIdentifiers(InnerDoc):
    """ Identifiers """
    header_from = Keyword()
    envelope_from = Keyword()
    envelope_to = Keyword()


class AggregateAuthResults(InnerDoc):
    """ Auth Results """
    spf = Nested(SPF)
    dkim = Nested(DKIM)


class AggregateRecord(InnerDoc):
    """ Record """
    row = Nested(AggregateRow)
    identifiers = Object(AggregateIdentifiers)
    auth_results = Object(AggregateAuthResults)


class AggregateReport(Document):
    """ d """
    created_date = Date()
    last_updated = Date()

    metadata = Object(AggregateMetadata)
    policy_published = Object(AggregatePolicyPublished)
    records = Nested(AggregateRecord)

    # pylint: disable-next=too-few-public-methods
    class Index:
        """ d """
        name = AGGREGATE_ALIAS
        settings = {
          "number_of_shards": 1,
          "number_of_replicas": 0,
        }

    # pylint: disable-next=arguments-differ
    def save(self, **kwargs):
        """ Set / overwrite created and last updated time values """
        if not self.created_date:
            self.created_date = datetime.now()
        self.last_updated = datetime.now()
        return super().save(**kwargs)
