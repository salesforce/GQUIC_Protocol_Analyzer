# Google QUIC docs: https://www.chromium.org/quic
# Wire format spec: https://github.com/quicwg/base-drafts/blob/master/draft-ietf-quic-transport.md

# Parses GQUIC Versions Q039-Q046

# All long packets start the same: with flags, version, and a CID
type GQUIC_Packet(is_orig: bool) = record {
	flags: PublicFlags(is_orig);
	content: case flags.packet_type of {
		REGULAR -> reg_pkt: RegularPacket(flags, is_orig);
		OLDER   -> old_pkt: OldPacket(flags, is_orig);
		default -> nil_pkt: empty;
	};

	# Unencrypted search determines whether the packet is a client hello
	unencrypted_search: case flags.hello_length of {
		true  -> search: UnencryptedSearch(flags, is_orig);
		false -> stop: empty;
		default -> stopx: empty;
	};
	frames: bytestring &restofdata &transient;
} &byteorder = bigendian;

# List of Public Flags and byte breakdown
type PublicFlags(is_orig: bool) = record {
		byte: uint8;
	}
	&let {
		length = sourcedata.length();
		hello_length: bool = HelloLength(length, is_orig);
		# These flags are for version Q046
		is_long: bool   = (byte & 0x80) == 0x80;
		fixed_bit: bool = (byte & 0x40) == 0x40;
		type_initial: bool = (byte & 0x30) == 0x00;
		type_0rtt: bool = (byte & 0x30) == 0x10;
		type_handshake: bool = (byte & 0x30) == 0x20;
		type_retry: bool = (byte & 0x30) == 0x30;
		pkt_num_size: uint8 = (byte & 0x03);

		# These flags are for versions before Q046
		# Clients may set the nonce bit in the header even though there is no
		# nonce in the message.  See:
		# https://groups.google.com/a/chromium.org/forum/#!topic/proto-quic/kQVDZal_iwo
		have_version: bool   = (byte & 0x01) == 0x01;
		have_nonce:   bool   = (byte & 0x04) == 0x04 && ! is_orig;
		have_conn_id: bool   = (byte & 0x08) == 0x08;
		pkt_num_size_old: uint8  = (byte & 0x30);
		packet_type:  int    = (fixed_bit ? REGULAR :
	                        	OLDER);
		cid_exists: bool = CIDCheck(is_orig, is_long);
	} &exportsourcedata;

type OldPacket(flags: PublicFlags, is_orig: bool) = record {
	cid:   ConnectionIDOld(flags);
	version: case flags.have_version of {
		true  -> version_val: uint8[4];
		false -> version_nil: empty;
	};

	nonce: case flags.have_nonce of {
		true  -> nonce_val: uint8[32];
		false -> nonce_nil: empty;
	};

	pkt_num_bytes: case flags.pkt_num_size_old of {
		0x00    -> pkt_num_bytes1: uint8[1];
		0x10    -> pkt_num_bytes2: uint8[2];
		0x20    -> pkt_num_bytes4: uint8[4];
		0x30    -> pkt_num_bytes6: uint8[6];
		default -> pkt_num_bytesx: empty; # not possible, all 4 cases handled
	};
} &byteorder = bigendian; # NOTE: versions before Q039 are little-endian

type ConnectionIDOld(flags: PublicFlags) = record {
	present: case flags.have_conn_id of {
		true  -> bytes: uint8[8];
		false -> nil:   empty;
	};
};

type RegularPacket(flags: PublicFlags, is_orig: bool) = record {
	version: case flags.is_long of {
		true  -> version_val: bytestring &length=4;
		false -> version_nil:   empty;
	};
	dcil_scil: case flags.is_long of {
		true  -> conn_id: uint8;
		false -> short: empty;
	};
	cid:   ConnectionID(flags);
	# Determine the number of packet bytes needed to display the packet number
	pkt_num_bytes: case flags.pkt_num_size of {
		0x00    -> pkt_num_bytes1: uint8[1];
		0x01    -> pkt_num_bytes2: uint8[2];
		0x02    -> pkt_num_bytes3: uint8[3];
		0x03    -> pkt_num_bytes4: uint8[4];
		default -> pkt_num_bytesx: empty; # not possible, all 4 cases handled
	};

};

type ConnectionID(flags: PublicFlags) = record {
	present: case flags.cid_exists of {
		true  -> bytes: uint8[8];
		false -> nil:   empty;
	};
};

# This sets up the parts to look for the CHLO
type UnencryptedSearch(flags: PublicFlags, is_orig: bool) = record {
	msg_auth_hash: uint8[12];
	stream:   StreamID(flags);
	sid:	SId(stream);
	extra: NewerVersions(stream);
	offset:	StreamOffset(stream);
	data_len:	DataLength(stream);
	expected_string: HelloCheck(flags, is_orig);
	build_hello: TypeHello(flags, is_orig, expected_string);
};

type StreamID(flags: PublicFlags) = record {
	byte: uint8;
}&let{
	streams: bool	= (byte & 0x80) == 0x80;
	extra_bit: bool = (byte & 0x40) == 0x40;
	data_length:	bool	= (byte & 0x20) == 0x20;
	offset_length:	int	= (byte & 0x1c);
	fin_bit:	bool	= (byte & 0x01) == 0x01;
};

type SId(stream: StreamID) = record {
	is_stream: case stream.streams of {
		true  -> id: uint8;
		false -> nil:   empty;
	};
};

type NewerVersions(stream: StreamID) = record {
	extra_space: case stream.extra_bit of {
		true  -> plus_six: uint8[7];
		false -> none: empty;
	};
};
type DataLength(stream: StreamID) = record {
	len: case stream.data_length of {
		true -> yes: uint16;
		false -> no: empty;
	};
};

type StreamOffset(stream: StreamID) = record {
	offset_type: case stream.offset_length of {
		0x00    -> pkt_offset_bytes0: empty;
		0x04    -> pkt_offset_bytes2: uint8[2];
		0x08	-> pkt_offset_bytes3: uint8[3];
		0x0c	-> pkt_offset_bytes4: uint8[4];
		0x10	-> pkt_offset_bytes5: uint8[5];
		0x14	-> pkt_offset_bytes6: uint8[6];
		0x18	-> pkt_offset_bytes7: uint8[7];
		0x1c	-> pkt_offset_bytes8: uint8[8];
		default -> pkt_offset_bytesx: empty;
	};
};

# Looks for CHLO or REJ in the next four bytes
type HelloCheck(flags: PublicFlags, is_orig: bool) = record {
	hello_string: bytestring &length=4;
}&let{
	hello_check: bool = ((hello_string[0] == 0x43) && (hello_string[1] == 0x48) && (hello_string[2] == 0x4c) && (hello_string[3] == 0x4f));
	rej_check: bool = ((hello_string[0] == 0x52) && (hello_string[1] == 0x45) && (hello_string[2] == 0x4a) && (hello_string[3] == 0x00));
};

# Confirms the existence of the Client Hello
type TypeHello(flags: PublicFlags, is_orig: bool, expected_string: HelloCheck) = record {
	client: case expected_string.hello_check of {
		true -> yes: HelloPacket(flags, is_orig);
		false -> no: empty;
	};
	server: case expected_string.rej_check of {
		true  -> rej: RejPacket(flags, is_orig);
		false -> none: empty;
	};
};

# The HelloPacket may or may not have all these possible tags
type HelloPacket(flags: PublicFlags, is_orig: bool) = record {
	tag_number: uint16 &byteorder = littleendian;
	zero_pading: uint16;
	other_tags: TagFinder(tag_number); # This is the important type which finds which tags exist
	pad: ExtractPAD(other_tags, tag_number, p_tag_offset);
	sni: ExtractSNI(other_tags, tag_number, p_tag_offset);
	stk: ExtractSTK(other_tags, tag_number, p_tag_offset);
	sno: ExtractSNO(other_tags, tag_number, p_tag_offset);
	ver: ExtractVER(other_tags, tag_number, p_tag_offset);
	ccs: ExtractCCS(other_tags, tag_number, p_tag_offset);
	nonc: ExtractNONC(other_tags, tag_number, p_tag_offset);
	mspc: ExtractMSPC(other_tags, tag_number, p_tag_offset);
	aead: ExtractAEAD(other_tags, tag_number, p_tag_offset);
	uaid: ExtractUAID(other_tags, tag_number, p_tag_offset);
	scid: ExtractSCID(other_tags, tag_number, p_tag_offset);
	tcid: ExtractTCID(other_tags, tag_number, p_tag_offset);
	pdmd: ExtractPDMD(other_tags, tag_number, p_tag_offset);
	smhl: ExtractSMHL(other_tags, tag_number, p_tag_offset);
	icsl: ExtractICSL(other_tags, tag_number, p_tag_offset);
	ctim: ExtractCTIM(other_tags, tag_number, p_tag_offset);
	nonp: ExtractNONP(other_tags, tag_number, p_tag_offset);
	pubs: ExtractPUBS(other_tags, tag_number, p_tag_offset);
	mids: ExtractMIDS(other_tags, tag_number, p_tag_offset);
	scls: ExtractSCLS(other_tags, tag_number, p_tag_offset);
	kexs: ExtractKEXS(other_tags, tag_number, p_tag_offset);
	xlct: ExtractXLCT(other_tags, tag_number, p_tag_offset);
	csct: ExtractCSCT(other_tags, tag_number, p_tag_offset);
	copt: ExtractCOPT(other_tags, tag_number, p_tag_offset);
	ccrt: ExtractCCRT(other_tags, tag_number, p_tag_offset);
	irtt: ExtractIRTT(other_tags, tag_number, p_tag_offset);
	cetv: ExtractCETV(other_tags, tag_number, p_tag_offset);
	cfcw: ExtractCFCW(other_tags, tag_number, p_tag_offset);
	sfcw: ExtractSFCW(other_tags, tag_number, p_tag_offset);
} &let{
	p_tag_offset=0;
};


type RejPacket(flags: PublicFlags, is_orig: bool) = record {
	tag_number: uint16 &byteorder = littleendian;
	zero_pading: uint16;
	other_tags: TagFinder(tag_number); # This is the important type which finds which tags exist
	stk: ExtractSTK(other_tags, tag_number, p_tag_offset);
	sno: ExtractSNO(other_tags, tag_number, p_tag_offset);
	svid: ExtractSVID(other_tags, tag_number, p_tag_offset);
	prof: ExtractPROF(other_tags, tag_number, p_tag_offset);
	scfg: ExtractSCFG(other_tags, tag_number, p_tag_offset);
	rrej: ExtractRREJ(other_tags, tag_number, p_tag_offset);
	sttl: ExtractSTTL(other_tags, tag_number, p_tag_offset);
	csct: ExtractCSCT(other_tags, tag_number, p_tag_offset);
} &let{
	p_tag_offset=0;
};

type RejPacketSCFG() = record {
	tag:	bytestring &length=4;
	tag_number: uint32 &byteorder = littleendian;
	other_tags: TagFinder(tag_number); # This is the important type which finds which tags exist
	ver: ExtractVER(other_tags, tag_number, p_tag_offset);
	aead: ExtractAEAD(other_tags, tag_number, p_tag_offset);
	scid: ExtractSCID(other_tags, tag_number, p_tag_offset);
	pdmd: ExtractPDMD(other_tags, tag_number, p_tag_offset);
	tbkp: ExtractTBKP(other_tags, tag_number, p_tag_offset);
	pubs: ExtractPUBS(other_tags, tag_number, p_tag_offset);
	kexs: ExtractKEXS(other_tags, tag_number, p_tag_offset);
	obit: ExtractOBIT(other_tags, tag_number, p_tag_offset);
	expy: ExtractEXPY(other_tags, tag_number, p_tag_offset);
} &let{
	p_tag_offset=0;
};

# Each of these types are either bytestrings of a certain length or
# is an empty type, meaning it does not exist
type ExtractPAD(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.pad_check of {
		true -> collect: bytestring &length=(find_pad_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractSNI(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.sni_check of {
		true -> collect: bytestring &length=(find_sni_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractSTK(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.stk_check of {
		true -> collect: bytestring &length=(find_stk_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractSNO(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.sno_check of {
		true -> collect: bytestring &length=(find_sno_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractVER(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.ver_check of {
		true -> collect: bytestring &length=(find_ver_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};


type ExtractCCS(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.ccs_check of {
		true -> collect: bytestring &length=(find_ccs_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractCRT(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.crt_check of {
		true -> collect: bytestring &length=(find_crt_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractNONC(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.nonc_check of {
		true -> collect: bytestring &length=(find_nonc_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractMSPC(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.mspc_check of {
		true -> collect: bytestring &length=(find_mspc_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractAEAD(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.aead_check of {
		true -> collect: bytestring &length=(find_aead_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractUAID(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.uaid_check of {
		true -> collect: bytestring &length=(find_uaid_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractSCID(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.scid_check of {
		true -> collect: bytestring &length=(find_scid_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractTCID(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.tcid_check of {
		true -> collect: bytestring &length=(find_tcid_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractPDMD(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.pdmd_check of {
		true -> collect: bytestring &length=(find_pdmd_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractSMHL(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.smhl_check of {
		true -> collect: bytestring &length=(find_smhl_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractICSL(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.icsl_check of {
		true -> collect: bytestring &length=(find_icsl_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractNONP(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.nonp_check of {
		true -> collect: bytestring &length=(find_nonp_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractPUBS(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.pubs_check of {
		true -> collect: bytestring &length=(find_pubs_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractMIDS(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.mids_check of {
		true -> collect: bytestring &length=(find_mids_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractSCLS(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.scls_check of {
		true -> collect: bytestring &length=(find_scls_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractKEXS(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.kexs_check of {
		true -> collect: bytestring &length=(find_kexs_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractXLCT(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.xlct_check of {
		true -> collect: bytestring &length=(find_xlct_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractCSCT(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.csct_check of {
		true -> collect: bytestring &length=(find_csct_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractCOPT(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.copt_check of {
		true -> collect: bytestring &length=(find_copt_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractCCRT(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.ccrt_check of {
		true -> collect: bytestring &length=(find_ccrt_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractIRTT(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.irtt_check of {
		true -> collect: bytestring &length=(find_irtt_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractCFCW(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.cfcw_check of {
		true -> collect: bytestring &length=(find_cfcw_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractSFCW(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.sfcw_check of {
		true -> collect: bytestring &length=(find_sfcw_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractPROF(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.prof_check of {
		true -> collect: bytestring &length=(find_prof_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractSCFG(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.scfg_check of {
		true -> collect: RejPacketSCFG;
#bytestring &length=(find_scfg_length(other_tags.seek_tags, tag_number, p_tag_offset));
#RejPacketSCFG;
		false -> blank: empty;
	};
};

type ExtractRREJ(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.rrej_check of {
		true -> collect: bytestring &length=(find_rrej_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractOBIT(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.obit_check of {
		true -> collect: bytestring &length=(find_obit_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractEXPY(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.expy_check of {
		true -> collect: bytestring &length=(find_expy_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractSRBF(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.srbf_check of {
		true -> collect: bytestring &length=(find_srbf_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractCETV(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.cetv_check of {
		true -> collect: bytestring &length=(find_cetv_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractCTIM(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.ctim_check of {
		true -> collect: bytestring &length=(find_ctim_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractFHOL(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.fhol_check of {
		true -> collect: bytestring &length=(find_fhol_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractSTTL(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.sttl_check of {
		true -> collect: bytestring &length=(find_sttl_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractTBKP(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.tbkp_check of {
		true -> collect: bytestring &length=(find_tbkp_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

type ExtractSVID(other_tags: TagFinder, tag_number: uint16, p_tag_offset: uint32) = record {
	exists: case other_tags.svid_check of {
		true -> collect: bytestring &length=(find_svid_length(other_tags.seek_tags, tag_number, p_tag_offset));
		false -> blank: empty;
	};
};

# This important type uses many booleans to deterine the existence of tags
type TagFinder(tag_number: uint16) = record {
	seek_tags: bytestring &length=((8*tag_number));
} &let {
	pad_check: bool = PAD_check(seek_tags, tag_number);
	sni_check: bool = SNI_check(seek_tags, tag_number);
	stk_check: bool = STK_check(seek_tags, tag_number);
	sno_check: bool = SNO_check(seek_tags, tag_number);
	ver_check: bool = VER_check(seek_tags, tag_number);
	ccs_check: bool = CCS_check(seek_tags, tag_number);
	crt_check: bool = CRT_check(seek_tags, tag_number);
	nonc_check: bool = NONC_check(seek_tags, tag_number);
	mspc_check: bool = MSPC_check(seek_tags, tag_number);
	aead_check: bool = AEAD_check(seek_tags, tag_number);
	uaid_check: bool = UAID_check(seek_tags, tag_number);
	scid_check: bool = SCID_check(seek_tags, tag_number);
	tcid_check: bool = TCID_check(seek_tags, tag_number);
	pdmd_check: bool = PDMD_check(seek_tags, tag_number);
	smhl_check: bool = SMHL_check(seek_tags, tag_number);
	icsl_check: bool = ICSL_check(seek_tags, tag_number);
	nonp_check: bool = NONP_check(seek_tags, tag_number);
	pubs_check: bool = PUBS_check(seek_tags, tag_number);
	mids_check: bool = MIDS_check(seek_tags, tag_number);
	scls_check: bool = SCLS_check(seek_tags, tag_number);
	kexs_check: bool = KEXS_check(seek_tags, tag_number);
	xlct_check: bool = XLCT_check(seek_tags, tag_number);
	csct_check: bool = CSCT_check(seek_tags, tag_number);
	copt_check: bool = COPT_check(seek_tags, tag_number);
	ccrt_check: bool = CCRT_check(seek_tags, tag_number);
	irtt_check: bool = IRTT_check(seek_tags, tag_number);
	cfcw_check: bool = CFCW_check(seek_tags, tag_number);
	sfcw_check: bool = SFCW_check(seek_tags, tag_number);
	prof_check: bool = PROF_check(seek_tags, tag_number);
	scfg_check: bool = SCFG_check(seek_tags, tag_number);
	rrej_check: bool = RREJ_check(seek_tags, tag_number);
	obit_check: bool = OBIT_check(seek_tags, tag_number);
	expy_check: bool = EXPY_check(seek_tags, tag_number);
	srbf_check: bool = SRBF_check(seek_tags, tag_number);
	cetv_check: bool = CETV_check(seek_tags, tag_number);
	ctim_check: bool = CTIM_check(seek_tags, tag_number);
	fhol_check: bool = FHOL_check(seek_tags, tag_number);
	sttl_check: bool = STTL_check(seek_tags, tag_number);
	tbkp_check: bool = TBKP_check(seek_tags, tag_number);
	svid_check: bool = SVID_check(seek_tags, tag_number);

};

# This function determines the length of a packet
function HelloLength(length: uint16, is_orig: bool): bool
	%{
		if ((length >= 60))
		{
			return true;
		}
		else
		{
			return false;
		}
	%}

function CIDCheck(is_orig: bool, is_long: bool): bool
	%{
		if (is_orig == true)
			return true;
		else
		{
			if (is_long == true)
			{
				return true;
			}
			else
				return false;
		}
	%}

# The following pairs of functions determine if a particular tag exists by iterating through the bytestring
# and checking for the bytes of the tag of the check function.  The second function determines the length
# of the tag, assuming the tag exists.
function PAD_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x50 && other_tags[(i*8)+1] == 0x41 && other_tags[(i*8)+2] == 0x44)
				{
				return true;
				}
			}
		return false;
	%}

function find_pad_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if ((other_tags[i*8] == 0x50) && (other_tags[(i*8)+1] == 0x41) && (other_tags[(i*8)+2] == 0x44))
				{
				if (i < 1)
					{
					return (other_tags[(i*8)+4]-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function SNI_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x4e && other_tags[(i*8)+2] == 0x49)
				{
				return true;
				}
			}
		return false;
	%}

function find_sni_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if ((other_tags[i*8] == 0x53) && (other_tags[(i*8)+1] == 0x4e) && (other_tags[(i*8)+2] == 0x49))
				{
				if (i < 1)
					{
					return (other_tags[(i*8)+4]-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function STK_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x54 && other_tags[(i*8)+2] == 0x4b)
				{
				return true;
				}
			}
		return false;
	%}

function find_stk_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if ((other_tags[i*8] == 0x53) && (other_tags[(i*8)+1] == 0x54) && (other_tags[(i*8)+2] == 0x4b))
				{
				if (i < 1) //(other_tags[(i*8)+5] == other_tags[(i*8)-3])
					{
					return (other_tags[(i*8)+4]-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function SNO_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x4e && other_tags[(i*8)+2] == 0x4f)
				{
				return true;
				}
			}
		return false;
	%}


function find_sno_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if ((other_tags[i*8] == 0x53) && (other_tags[(i*8)+1] == 0x4e) && (other_tags[(i*8)+2] == 0x4f))
				{
				if (i < 1)
					{
					return (other_tags[(i*8)+4]-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function VER_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x56 && other_tags[(i*8)+1] == 0x45 && other_tags[(i*8)+2] == 0x52)
				{
				return true;
				}
			}
		return false;
	%}

function find_ver_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x56 && other_tags[(i*8)+1] == 0x45 && other_tags[(i*8)+2] == 0x52)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function CCS_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number-2; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x53)
				{
				return true;
				}
			}
		return false;
	%}

function find_ccs_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x53)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function CRT_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number-2; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x52 && other_tags[(i*8)+2] == 0x54)
				{
				return true;
				}
			}
		return false;
	%}

function find_crt_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x52 && other_tags[(i*8)+2] == 0x54)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function NONC_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x4e && other_tags[(i*8)+1] == 0x4f && other_tags[(i*8)+2] == 0x4e && other_tags[(i*8)+3] == 0x43)
				{
				return true;
				}
			}
		return false;
	%}

function find_nonc_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x4e && other_tags[(i*8)+1] == 0x4f && other_tags[(i*8)+2] == 0x4e && other_tags[(i*8)+3] == 0x43)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function MSPC_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x4d && other_tags[(i*8)+1] == 0x53 && other_tags[(i*8)+2] == 0x50 && other_tags[(i*8)+3] == 0x43)
				{
				return true;
				}
			}
		return false;
	%}

function find_mspc_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x4d && other_tags[(i*8)+1] == 0x53 && other_tags[(i*8)+2] == 0x50 && other_tags[(i*8)+3] == 0x43)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function AEAD_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x41 && other_tags[(i*8)+1] == 0x45 && other_tags[(i*8)+2] == 0x41 && other_tags[(i*8)+3] == 0x44)
				{
				return true;
				}
			}
		return false;
	%}

function find_aead_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x41 && other_tags[(i*8)+1] == 0x45 && other_tags[(i*8)+2] == 0x41 && other_tags[(i*8)+3] == 0x44)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function UAID_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x55 && other_tags[(i*8)+1] == 0x41 && other_tags[(i*8)+2] == 0x49 && other_tags[(i*8)+3] == 0x44)
				{
				return true;
				}
			}
		return false;
	%}

function find_uaid_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x55 && other_tags[(i*8)+1] == 0x41 && other_tags[(i*8)+2] == 0x49 && other_tags[(i*8)+3] == 0x44)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function SCID_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x49 && other_tags[(i*8)+3] == 0x44)
				{
				return true;
				}
			}
		return false;
	%}

function find_scid_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x49 && other_tags[(i*8)+3] == 0x44)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}


function TCID_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x54 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x49 && other_tags[(i*8)+3] == 0x44)
				{
				return true;
				}
			}
		return false;
	%}

function find_tcid_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x54 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x49 && other_tags[(i*8)+3] == 0x44)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function PDMD_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x50 && other_tags[(i*8)+1] == 0x44 && other_tags[(i*8)+2] == 0x4d && other_tags[(i*8)+3] == 0x44)
				{
				return true;
				}
			}
		return false;
	%}

function find_pdmd_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x50 && other_tags[(i*8)+1] == 0x44 && other_tags[(i*8)+2] == 0x4d && other_tags[(i*8)+3] == 0x44)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function SMHL_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x4d && other_tags[(i*8)+2] == 0x48 && other_tags[(i*8)+3] == 0x4c)
				{
				return true;
				}
			}
		return false;
	%}

function find_smhl_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x4d && other_tags[(i*8)+2] == 0x48 && other_tags[(i*8)+3] == 0x4c)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function NONP_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x4e && other_tags[(i*8)+1] == 0x4f && other_tags[(i*8)+2] == 0x4e && other_tags[(i*8)+3] == 0x50)
				{
				return true;
				}
			}
		return false;
	%}

function find_nonp_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x4e && other_tags[(i*8)+1] == 0x4f && other_tags[(i*8)+2] == 0x4e && other_tags[(i*8)+3] == 0x50)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}

		return 0x00;
	%}

function PUBS_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x50 && other_tags[(i*8)+1] == 0x55 && other_tags[(i*8)+2] == 0x42 && other_tags[(i*8)+3] == 0x53)
				{
				return true;
				}
			}
		return false;
	%}

function find_pubs_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x50 && other_tags[(i*8)+1] == 0x55 && other_tags[(i*8)+2] == 0x42 && other_tags[(i*8)+3] == 0x53)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function MIDS_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x4d && other_tags[(i*8)+1] == 0x49 && other_tags[(i*8)+2] == 0x44 && other_tags[(i*8)+3] == 0x53)
				{
				return true;
				}
			}
		return false;
	%}

function find_mids_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x4d && other_tags[(i*8)+1] == 0x49 && other_tags[(i*8)+2] == 0x44 && other_tags[(i*8)+3] == 0x53)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function SCLS_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x4c && other_tags[(i*8)+3] == 0x53)
				{
				return true;
				}
			}
		return false;
	%}

function find_scls_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x4c && other_tags[(i*8)+3] == 0x53)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function KEXS_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x4b && other_tags[(i*8)+1] == 0x45 && other_tags[(i*8)+2] == 0x58 && other_tags[(i*8)+3] == 0x53)
				{
				return true;
				}
			}
		return false;
	%}

function find_kexs_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x4b && other_tags[(i*8)+1] == 0x45 && other_tags[(i*8)+2] == 0x58 && other_tags[(i*8)+3] == 0x53)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function XLCT_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x58 && other_tags[(i*8)+1] == 0x4c && other_tags[(i*8)+2] == 0x43 && other_tags[(i*8)+3] == 0x54)
				{
				return true;
				}
			}
		return false;
	%}

function find_xlct_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x58 && other_tags[(i*8)+1] == 0x4c && other_tags[(i*8)+2] == 0x43 && other_tags[(i*8)+3] == 0x54)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function CSCT_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x53 && other_tags[(i*8)+2] == 0x43 && other_tags[(i*8)+3] == 0x54)
				{
				return true;
				}
			}
		return false;
	%}

function find_csct_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x53 && other_tags[(i*8)+2] == 0x43 && other_tags[(i*8)+3] == 0x54)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function COPT_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x4f && other_tags[(i*8)+2] == 0x50 && other_tags[(i*8)+3] == 0x54)
				{
				return true;
				}
			}
		return false;
	%}

function find_copt_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x4f && other_tags[(i*8)+2] == 0x50 && other_tags[(i*8)+3] == 0x54)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function CCRT_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x52 && other_tags[(i*8)+3] == 0x54)
				{
				return true;
				}
			}
		return false;
	%}

function find_ccrt_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x52 && other_tags[(i*8)+3] == 0x54)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function IRTT_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x49 && other_tags[(i*8)+1] == 0x52 && other_tags[(i*8)+2] == 0x54 && other_tags[(i*8)+3] == 0x54)
				{
				return true;
				}
			}
		return false;
	%}

function find_irtt_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x49 && other_tags[(i*8)+1] == 0x52 && other_tags[(i*8)+2] == 0x54 && other_tags[(i*8)+3] == 0x54)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function CFCW_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x46 && other_tags[(i*8)+2] == 0x43 && other_tags[(i*8)+3] == 0x57)
				{
				return true;
				}
			}
		return false;
	%}

function find_cfcw_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x46 && other_tags[(i*8)+2] == 0x43 && other_tags[(i*8)+3] == 0x57)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function SFCW_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x46 && other_tags[(i*8)+2] == 0x43 && other_tags[(i*8)+3] == 0x57)
				{
				return true;
				}
			}
		return false;
	%}

function find_sfcw_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x46 && other_tags[(i*8)+2] == 0x43 && other_tags[(i*8)+3] == 0x57)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function PROF_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x50 && other_tags[(i*8)+1] == 0x52 && other_tags[(i*8)+2] == 0x4f && other_tags[(i*8)+3] == 0x46)
				{
				return true;
				}
			}
		return false;
	%}

function find_prof_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x50 && other_tags[(i*8)+1] == 0x52 && other_tags[(i*8)+2] == 0x4f && other_tags[(i*8)+3] == 0x46)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function SCFG_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x46 && other_tags[(i*8)+3] == 0x47)
				{
				return true;
				}
			}
		return false;
	%}

function find_scfg_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x46 && other_tags[(i*8)+3] == 0x47)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function RREJ_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x52 && other_tags[(i*8)+1] == 0x52 && other_tags[(i*8)+2] == 0x45 && other_tags[(i*8)+3] == 0x4a)
				{
				return true;
				}
			}
		return false;
	%}

function find_rrej_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x52 && other_tags[(i*8)+1] == 0x52 && other_tags[(i*8)+2] == 0x45 && other_tags[(i*8)+3] == 0x4a)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function OBIT_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x4f && other_tags[(i*8)+1] == 0x42 && other_tags[(i*8)+2] == 0x49 && other_tags[(i*8)+3] == 0x54)
				{
				return true;
				}
			}
		return false;
	%}

function find_obit_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x4f && other_tags[(i*8)+1] == 0x42 && other_tags[(i*8)+2] == 0x49 && other_tags[(i*8)+3] == 0x54)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function EXPY_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x45 && other_tags[(i*8)+1] == 0x58 && other_tags[(i*8)+2] == 0x50 && other_tags[(i*8)+3] == 0x59)
				{
				return true;
				}
			}
		return false;
	%}

function find_expy_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x45 && other_tags[(i*8)+1] == 0x58 && other_tags[(i*8)+2] == 0x50 && other_tags[(i*8)+3] == 0x59)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function SRBF_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x52 && other_tags[(i*8)+2] == 0x42 && other_tags[(i*8)+3] == 0x46)
				{
				return true;
				}
			}
		return false;
	%}

function find_srbf_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x52 && other_tags[(i*8)+2] == 0x42 && other_tags[(i*8)+3] == 0x46)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function CETV_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x45 && other_tags[(i*8)+2] == 0x54 && other_tags[(i*8)+3] == 0x56)
				{
				return true;
				}
			}
		return false;
	%}

function find_cetv_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x45 && other_tags[(i*8)+2] == 0x54 && other_tags[(i*8)+3] == 0x56)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function CTIM_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x54 && other_tags[(i*8)+2] == 0x49 && other_tags[(i*8)+3] == 0x4d)
				{
				return true;
				}
			}
		return false;
	%}

function find_ctim_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x43 && other_tags[(i*8)+1] == 0x54 && other_tags[(i*8)+2] == 0x49 && other_tags[(i*8)+3] == 0x4d)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function FHOL_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x46 && other_tags[(i*8)+1] == 0x48 && other_tags[(i*8)+2] == 0x4f && other_tags[(i*8)+3] == 0x4c)
				{
				return true;
				}
			}
		return false;
	%}

function find_fhol_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x46 && other_tags[(i*8)+1] == 0x48 && other_tags[(i*8)+2] == 0x4f && other_tags[(i*8)+3] == 0x4c)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function STTL_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x54 && other_tags[(i*8)+2] == 0x54 && other_tags[(i*8)+3] == 0x4c)
				{
				return true;
				}
			}
		return false;
	%}

function find_sttl_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x54 && other_tags[(i*8)+2] == 0x54 && other_tags[(i*8)+3] == 0x4c)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function TBKP_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x54 && other_tags[(i*8)+1] == 0x42 && other_tags[(i*8)+2] == 0x4b && other_tags[(i*8)+3] == 0x50)
				{
				return true;
				}
			}
		return false;
	%}

function find_tbkp_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x54 && other_tags[(i*8)+1] == 0x42 && other_tags[(i*8)+2] == 0x4b && other_tags[(i*8)+3] == 0x50)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function ICSL_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x49 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x53 && other_tags[(i*8)+3] == 0x4c)
				{
				return true;
				}
			}
		return false;
	%}

function find_icsl_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x49 && other_tags[(i*8)+1] == 0x43 && other_tags[(i*8)+2] == 0x53 && other_tags[(i*8)+3] == 0x4c)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

function SVID_check(other_tags: bytestring, tag_number: uint16) : bool
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x56 && other_tags[(i*8)+2] == 0x49 && other_tags[(i*8)+3] == 0x44)
				{
				return true;
				}
			}
		return false;
	%}

function find_svid_length(other_tags: bytestring, tag_number: uint16, p_tag_offset: uint32) : uint16
	%{
		for ( int i = 0; i < tag_number; i++ )
			{
			if (other_tags[i*8] == 0x53 && other_tags[(i*8)+1] == 0x56 && other_tags[(i*8)+2] == 0x49 && other_tags[(i*8)+3] == 0x44)
				{
				if (i < 1)
					{
					return ((other_tags[4])-(p_tag_offset-(256*other_tags[5])));
					}
				else
					{
					if (other_tags[(i*8)+5] == other_tags[(i*8)-3])
						{
						return (other_tags[(i*8)+4]-other_tags[(i*8)-4]);
						}
					if (other_tags[(i*8)+5] > other_tags[(i*8)-3])
						{
						return (256-other_tags[(i*8)-4]+other_tags[(i*8)+4]);
						}
					}
				}
			}
		return 0x00;
	%}

enum PacketType {
	REGULAR,
	OLDER,
};
