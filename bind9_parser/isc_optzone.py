#!/usr/bin/env python3
"""
File: isc_optzone.py

Clause: options, zone

Title: Statements Used Only By options And zone Clauses.

Description: isc_optzone contains all parse elements pertaining
             to both options and zone (but not view)
"""
from pyparsing import Keyword, OneOrMore, MatchFirst, Group, \
    CaselessLiteral, Literal, quotedString, removeQuotes
from bind9_parser.isc_utils import isc_boolean, semicolon, \
    number_type, lbrack, rbrack
from bind9_parser.isc_inet import ip46_addr, ip_port


optzone_stmt_notify_to_soa = (
    Keyword('notify-to-soa')
    - isc_boolean('notify_to_soa')
    + semicolon
)

# QIP custom options
# qddns {
# 	allow-secondary-update <boolean>;
# 	rrset-order <boolean>;
# 	unix-use-unbuffered-write-for-journal <boolean>;
# 	sync-journal-to-disk <boolean>;
# 	remove-cname-on-cname-and-other-data-error <boolean>;
# 	udp-socket-rcvbuf <integer>;
# 	retry-tcp-on-truncate <boolean>;
# 	client-edns <boolean>;
# 	snmp-stats <boolean>;
# 	edup {
# 		my-ip ( <ipv4_address> | <ipv6_address> );
# 		message-service-ip ( <ipv4_address> | <ipv6_address> );
# 		message-service-port <integer>;
# 		org-id <integer>;
# 		rr-types { <quoted_string>; ... };
# 	};
# 	gss-principal <quoted_string>
# 	max-rdataset-for-update <integer>;
# 	notify-after-load <boolean>;
# 	lock-isc-stats <boolean>;
# 	gss-max-contexts <integer>;
# };

options_qddns_edup_rrtypes_values = MatchFirst([
    CaselessLiteral('aaaa'),
    CaselessLiteral('a'),
    CaselessLiteral('ptr'),
    CaselessLiteral('txt'),
    CaselessLiteral('srv'),
    CaselessLiteral('cname'),
])
options_qddns_edup_rrtypes_values.setName('(A|AAAA|PTR|TXT|SRV|CNAME)')

options_qddns_edup_rrtypes_dequotable = (
    (
            Literal('"').suppress() + options_qddns_edup_rrtypes_values + Literal('"').suppress()
    )
    ^ (
            Literal("'").suppress() + options_qddns_edup_rrtypes_values + Literal("'").suppress()
    )
)
options_qddns_edup_rrtypes_dequotable.setName('<quoted-rrtype>')

options_qddns_edup_options = (
    (
        (
            Keyword('my-ip').suppress()
            - ip46_addr('my-ip')
            - semicolon
        )('')
        | (
            Keyword('message-service-ip').suppress()
            - ip46_addr('message-service-ip')
            - semicolon
        )('')
        | (
            Keyword('message-service-port').suppress()
            - ip_port('message-service-port')
            - semicolon
        )('')
        | (
            Keyword('org-id').suppress()
            - number_type('org_id')
            - semicolon
        )('')
        | (
            Keyword('rr-types').suppress()
            - lbrack
            - Group(
                OneOrMore(
                    options_qddns_edup_rrtypes_dequotable
                    - semicolon
                )
            )('rr-types')
            - rbrack
            - semicolon
        )('')
        | (
            Group(
                OneOrMore(
                    options_qddns_edup_rrtypes_dequotable
                    - semicolon
                )
            )('rr-types')
        )('')
    )('')
)
options_qddns_edup_options.setName("""
    [ my-ip ( <ipv4_address> | <ipv6_address> ); ]
    [ message-service-ip ( <ipv4_address> | <ipv6_address> ); ]
    [ message-service-port <integer>; ]
    [ org-id <integer>; ]
    [ rr-types { <quoted_string>; ... }; ]
""")

options_qddns_options = (
    (
        (
            Keyword('allow-secondary-update').suppress()
            - isc_boolean('allow-secondary-update')
            - semicolon
        )('')
        | (
            Keyword('rrset-order').suppress()
            - isc_boolean('rrset-order')
            - semicolon
        )('')
        | (
            Keyword('unix-use-unbuffered-write-for-journal').suppress()
            - isc_boolean('unix-use-unbuffered-write-for-journal')
            - semicolon
        )('')
        | (
            Keyword('sync-journal-to-disk').suppress()
            - isc_boolean('sync-journal-to-disk')
            - semicolon
        )('')
        | (
            Keyword('remove-cname-on-cname-and-other-data-error').suppress()
            - isc_boolean('remove-cname-on-cname-and-other-data-error')
            - semicolon
        )('')
        | (
            Keyword('udp-socket-rcvbuf').suppress()
            - number_type('udp-socket-rcvbuf')
            - semicolon
        )('')
        | (
            Keyword('retry-tcp-on-truncate').suppress()
            - isc_boolean('retry-tcp-on-truncate')
            - semicolon
        )('')
        | (
            Keyword('client-edns').suppress()
            - isc_boolean('client-edns')
            - semicolon
        )('')
        | (
            Keyword('snmp-stats').suppress()
            - isc_boolean('snmp-stats')
            - semicolon
        )('')
        | (
            Keyword('edup').suppress()
            - lbrack
            - Group(
                OneOrMore(options_qddns_edup_options)
            )('edup')
            - rbrack
            - semicolon
        )('')
        | (
            Keyword('gss-principal').suppress()
            - quotedString.setParseAction(removeQuotes)('gss-principal')
            - semicolon
        )('')
        | (
            Keyword('max-rdataset-for-update').suppress()
            - number_type('max-rdataset-for-update')
            - semicolon
        )('')
        | (
            Keyword('notify-after-load').suppress()
            - isc_boolean('notify-after-load')
            - semicolon
        )('')
        | (
            Keyword('lock-isc-stats').suppress()
            - isc_boolean('lock-isc-stats')
            - semicolon
        )('')
        | (
            Keyword('gss-max-contexts').suppress()
            - number_type('gss-max-contexts')
            - semicolon
        )('')
    )('')
)
options_qddns_options.setName("""
    [ allow-secondary-update <boolean>; ]
    [ rrset-order <boolean>; ]
    [ unix-use-unbuffered-write-for-journal <boolean>; ]
    [ sync-journal-to-disk <boolean>; ]
    [ remove-cname-on-cname-and-other-data-error <boolean>; ]
    [ udp-socket-rcvbuf <integer>; ]
    [ retry-tcp-on-truncate <boolean>; ]
    [ client-edns <boolean>; ]
    [ snmp-stats <boolean>; ]
    [ edup { <options> }; ]
    [ gss-principal <quoted_string> ]
    [ max-rdataset-for-update <integer>; ]
    [ notify-after-load <boolean>; ]
    [ lock-isc-stats <boolean>; ]
    [ gss-max-contexts <integer>; ]
""")

options_stmt_qddns = (
    Group(
        Keyword('qddns').suppress()
        - lbrack
        - OneOrMore(
            options_qddns_options
        )
        - rbrack
        - semicolon
    )('')
)('qddns')
options_stmt_qddns.setName("""
qddns {
    [ allow-secondary-update <boolean>; ]
    [ rrset-order <boolean>; ]
    [ unix-use-unbuffered-write-for-journal <boolean>; ]
    [ sync-journal-to-disk <boolean>; ]
    [ remove-cname-on-cname-and-other-data-error <boolean>; ]
    [ udp-socket-rcvbuf <integer>; ]
    [ retry-tcp-on-truncate <boolean>; ]
    [ client-edns <boolean>; ]
    [ snmp-stats <boolean>; ]
    [ edup { <options> }; ]
    [ gss-principal <quoted_string> ]
    [ max-rdataset-for-update <integer>; ]
    [ notify-after-load <boolean>; ]
    [ lock-isc-stats <boolean>; ]
    [ gss-max-contexts <integer>; ]
};""")

# Keywords are in dictionary-order, but with longest pattern as
# having been listed firstly
optzone_statements_set = (
    optzone_stmt_notify_to_soa
    ^ options_stmt_qddns
)

optzone_statements_series = (
    OneOrMore(optzone_statements_set)
)
