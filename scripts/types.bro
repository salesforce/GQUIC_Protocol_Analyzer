
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
	## Hello Packet.  Half the fields determine the existence of a tag
	## while the other half contain the value of the tag.
	type HelloInfo: record {
		tag:	count;
		padding_len:	count;
		sni_exists:	bool;
		sni:	string &optional;
		stk_exists:	bool;
		stk:	string &optional;
		sno_exists:	bool;
		sno:	string &optional;
		ver_exists:	bool;
		ver:	string &optional;
		ccs_exists:	bool;
		ccs:	string &optional;
		nonc_exists:	bool;
		nonc:	string &optional;
		mspc_exists:	bool;
		mspc:	string &optional;
		aead_exists:	bool;
		aead:	string &optional;
		uaid_exists:	bool;
		uaid:	string &optional;
		scid_exists:	bool;
		scid:	string &optional;
		tcid_exists:	bool;
		tcid:	string &optional;
		pdmd_exists:	bool;
		pdmd:	string &optional;
		smhl_exists:	bool;
		smhl:	string &optional;
		icsl_exists:	bool;
		icsl:	string &optional;
		ctim_exists:	bool;
		ctim:	string &optional;	
		nonp_exists:	bool;
		nonp:	string &optional;
		pubs_exists:	bool;
		pubs:	string &optional;
		mids_exists:	bool;
		mids:	string &optional;
		scls_exists:	bool;
		scls:	string &optional;
		kexs_exists:	bool;
		kexs:	string &optional;
		xlct_exists:	bool;
		xlct:	string &optional;
		csct_exists:	bool;
		csct:	string &optional;
		copt_exists:	bool;
		copt:	string &optional;
		ccrt_exists:	bool;
		ccrt:	string &optional;
		irtt_exists:	bool;
		irtt:	string &optional;
		cetv_exists:	bool;
		cetv:	string &optional;
		cfcw_exists:	bool;
		cfcw:	string &optional;
		sfcw_exists:	bool;
		sfcw:	string &optional;
		tag_list: string;
	};

	## Contains information about the server-sent REJ packet
	type RejInfo: record {
		tag_count: count;
		tag_list: string; 
		stk_exists:	bool;
		stk:	string &optional;
		sno_exists:	bool;
		sno:	string &optional;
		svid_exists:	bool;
		svid:	string &optional;
		prof_exists:	bool;
		prof:	string &optional;
		scfg_exists:	bool;
		scfg:	string &optional;
		rrej_exists:	bool;
		rrej:	string &optional;
		sttl_exists:	bool;
		sttl:	string &optional;
		csct_exists:	bool;
		csct:	string &optional;
		ver_exists:	bool;
		ver:	string &optional;
		aead_exists:	bool;
		aead:	string &optional;
		scid_exists:	bool;
		scid:	string &optional;
		pdmd_exists:	bool;
		pdmd:	string &optional;
		tbkp_exists:	bool;
		tbkp:	string &optional;
		pubs_exists:	bool;
		pubs:	string &optional;
		kexs_exists:	bool;
		kexs:	string &optional;
		obit_exists:	bool;
		obit:	string &optional;
		expy_exists:	bool;
		expy:	string &optional;	
		embedded_count:	count &optional;
	};

}
