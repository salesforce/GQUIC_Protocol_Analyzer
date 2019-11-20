# Copyright (c) 2017-2019, Corelight Inc. and GQUIC Protocol Analyzer contributors
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause

module GQUIC;

export {

	## Contains information related to the contents of the Public Header
	## portion of GQUIC Regular Packets.
	type PublicHeader: record {
		## The packet number.
		pkt_num: count;


		## The Connection ID field if present (a bit in the Public Flags
		## indicates this).
		cid: string &optional;


		version_exists: bool;
		## The version parsed as a numerical value.
		## E.g. for "Q039" this will be 39.
		## Only set when the version bit of the Public Flags is set
		## for in the client-side packets (servers never send this).
		version: count &optional;


	};

	## Contains information about the possible fields in a GQUIC Client
	## Hello Packet.
	type HelloInfo: record {
		tag:	count;
		tag_list: string; 
		padding_len:	count;
		sni:	string &optional;
		stk:	string &optional;
		sno:	string &optional;
		ver:	string &optional;
		ccs:	string &optional;
		nonc:	string &optional;
		mspc:	string &optional;
		aead:	string &optional;
		uaid:	string &optional;
		scid:	string &optional;
		tcid:	string &optional;
		pdmd:	string &optional;
		smhl:	string &optional;
		icsl:	string &optional;
		ctim:	string &optional;	
		nonp:	string &optional;
		pubs:	string &optional;
		mids:	string &optional;
		scls:	string &optional;
		kexs:	string &optional;
		xlct:	string &optional;
		csct:	string &optional;
		copt:	string &optional;
		ccrt:	string &optional;
		irtt:	string &optional;
		cetv:	string &optional;
		cfcw:	string &optional;
		sfcw:	string &optional;
	};

	## Contains information about the server-sent REJ packet
	type RejInfo: record {
		tag_count: count;
		tag_list: string; 
		stk:	string &optional;
		sno:	string &optional;
		svid:	string &optional;
		prof:	string &optional;
		scfg:	string &optional;
		rrej:	string &optional;
		sttl:	string &optional;
		csct:	string &optional;
		ver:	string &optional;
		aead:	string &optional;
		scid:	string &optional;
		pdmd:	string &optional;
		tbkp:	string &optional;
		pubs:	string &optional;
		kexs:	string &optional;
		obit:	string &optional;
		expy:	string &optional;	
		embedded_count:	count &optional;
	};

}
