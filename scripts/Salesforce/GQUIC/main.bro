# Copyright (c) 2019, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause

module GQUIC;

export {
	redef enum Log::ID += { LOG };

	type Info: record {

	ts:	time	&log;
	uid:	string	&log;
	id:	conn_id	&log;
	version:	count	&log &optional;
	server_name:	string	&log &optional;
	user_agent:	string	&log &optional;
	tag_count:	count	&log &optional;
	cyu:		string	&log &optional;
	cyutags:	string	&log &optional;	
	};
	global log_gquic: event(rec: Info);

}

const ports = { 80/udp, 443/udp };
redef likely_server_ports += { ports };

# probably best to rely on signature match
event bro_init() &priority=5
	{
	Log::create_stream(GQUIC::LOG, [$columns=Info, $ev=log_gquic, $path="gquic"]); 
#	Analyzer::register_for_ports(Analyzer::ANALYZER_GQUIC, ports);
	}

event gquic_hello(c: connection, is_orig: bool, hdr: GQUIC::PublicHeader, HeIn: GQUIC::HelloInfo)
	{
	local tag_list_string = HeIn$tag_list;	

	#Tag grabber
	local i = 0;
	local fingerprint = "";
	while ( i < (HeIn$tag) )
		{
		if (i == 0) {
		
		}
		else {
			fingerprint += "-";
		}

		local one = tag_list_string[i*8];
		local two = tag_list_string[i*8+1];
		local three = tag_list_string[i*8+2];
		local four = tag_list_string[i*8+3];
		local test = fmt("%s", four);	
		if (test == "\x00")
			fingerprint += (one+two+three);
		else	
			fingerprint += (one+two+three+four);
		++i;
		}
	if (hdr$version_exists == T)	
		{
		local version_string = fmt("%s", hdr$version);
		local cable_hash = (version_string + "," + fingerprint); 
		}
	else
		cable_hash=("," + fingerprint);
	local info: Info;
	info$ts=network_time();
	info$uid=c$uid;
	info$id=c$id;
	if (HeIn$sni_exists == T)
		{
		info$server_name=HeIn$sni;
		}
	if (HeIn$uaid_exists == T)
		{
		info$user_agent=HeIn$uaid;	
		}
	if (hdr$version_exists == T)
		{
		info$version=hdr$version;
		}
	info$tag_count=HeIn$tag;	
	info$cyu=md5_hash(cable_hash);
	info$cyutags=cable_hash;
	Log::write(GQUIC::LOG, info);  
	}
