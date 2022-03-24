# Copyright (c) 2017-2019, Corelight Inc. and GQUIC Protocol Analyzer contributors
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause

# Much of this code was taken from Corelights previous work
%extern{
	#include <cctype>
	#include <unordered_set>
	#include "consts.bif.h"
	#include "types.bif.h"
%}

%header{
%}

%code{
%}

refine connection GQUIC_Conn += {

	%member{
		bool saw_server_pkt1;
		uint16 last_known_client_version;
		std::unordered_set<uint16> potential_client_versions;

		// Add the gquic string to conn.log
		void confirm()
			{
			zeek_analyzer()->ProtocolConfirmation();

			if ( zeek::BifConst::GQUIC::skip_after_confirm )
				zeek_analyzer()->SetSkip(true);
			}

		uint16 extract_gquic_version(const uint8* version_bytes)
			{
			if ( version_bytes[0] != 'Q' )
				{
				zeek_analyzer()->ProtocolViolation("invalid GQUIC Version",
				    reinterpret_cast<const char*>(version_bytes), 4);
				return 0;
				}

			for ( auto i = 1u; i < 4; ++i )
				{
				if ( ! isdigit(version_bytes[i]) )
					{
					zeek_analyzer()->ProtocolViolation(
					    "invalid GQUIC Version",
				        reinterpret_cast<const char*>(version_bytes), 4);
					return 0;
					}
				}

			uint16 rval = 0;
			rval += (version_bytes[1] - 0x30) * 100;
			rval += (version_bytes[2] - 0x30) * 10;
			rval += (version_bytes[3] - 0x30);
			return rval;
			}
	%}

	%init{
		saw_server_pkt1 = false;
		last_known_client_version = 0;
	%}

	%cleanup{
	%}
function process_packet(pkt: GQUIC_Packet, is_orig: bool): bool
		%{
		switch ( ${pkt.flags.packet_type} ) {
		//This is currently the only type the parser analyzes.  Other types do exist, but are not as beneficial to parse
		case REGULAR:
			{
			auto pkt_num = 0u;
			auto pkt_version = get_gquic_version(${pkt.reg_pkt});

			if ( is_orig )
				{
				if ( pkt_version )
					{
					last_known_client_version = pkt_version;
					auto p = potential_client_versions.emplace(pkt_version);

					if ( gquic_client_version && p.second )
						zeek::BifEvent::enqueue_gquic_client_version(
						    zeek_analyzer(),
						    zeek_analyzer()->Conn(),
						    pkt_version);
					}

				pkt_num = get_packet_number_current(${pkt}, ${pkt.reg_pkt}, last_known_client_version);

				if ( last_known_client_version && saw_server_pkt1 )
					confirm();
				}
			else
				{
				pkt_num = get_packet_number_current(${pkt}, ${pkt.reg_pkt}, last_known_client_version);

				if ( pkt_num == 1 )
					saw_server_pkt1 = true;

				if ( last_known_client_version && saw_server_pkt1)
					confirm();
				}

			if ( gquic_packet )
				{
				//Populate standard GQUIC packet characteristics
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::GQUIC::PublicHeader);
				rv->Assign(0, zeek::val_mgr->Count(pkt_num));

				if ( ${pkt.reg_pkt.cid}->present_case_index() )
					{
					auto bytes = ${pkt.reg_pkt.cid.bytes};
					auto ptr = reinterpret_cast<const char*>(bytes->data());
					rv->Assign(1, new zeek::StringVal(bytes->size(), ptr));
					}
					rv->Assign(2, zeek::val_mgr->Bool(${pkt.flags.is_long}));
				if ( ${pkt.reg_pkt}->version_case_index() )
					rv->Assign(3, zeek::val_mgr->Count(pkt_version));

				if ( ${pkt.flags.hello_length} == true )
					{
					if ( ${pkt.search.expected_string.hello_check} == true )
						{
						zeek::BifEvent::enqueue_gquic_hello(zeek_analyzer(), zeek_analyzer()->Conn(), is_orig, rv,
																								{zeek::AdoptRef{}, hello_packet_creation(${pkt}, is_orig)});
						}
					else if ( ${pkt.search.expected_string.rej_check} == true)
						{
						zeek::BifEvent::enqueue_gquic_rej(zeek_analyzer(), zeek_analyzer()->Conn(), is_orig, rv,
																							{zeek::AdoptRef{}, rej_packet_creation(${pkt}, is_orig)});
						}
					else
						{
						zeek::BifEvent::enqueue_gquic_packet(zeek_analyzer(), zeek_analyzer()->Conn(), is_orig, rv);
						}
					}
				else
					{
					zeek::BifEvent::enqueue_gquic_packet(zeek_analyzer(), zeek_analyzer()->Conn(), is_orig, rv);
					}
				}
			}
			break;

		case OLDER:
			{
			auto pkt_num = 0u;
			auto pkt_version = get_gquic_version_old(${pkt.old_pkt});

			if ( is_orig )
				{
				if ( pkt_version )
					{
					last_known_client_version = pkt_version;
					auto p = potential_client_versions.emplace(pkt_version);

					if ( gquic_client_version && p.second )
						zeek::BifEvent::enqueue_gquic_client_version(
								zeek_analyzer(),
								zeek_analyzer()->Conn(),
								pkt_version);
					}

				pkt_num = get_packet_number_old(${pkt}, ${pkt.old_pkt}, last_known_client_version);

				if ( last_known_client_version && saw_server_pkt1 )
					confirm();
				}
			else
				{
				pkt_num = get_packet_number_old(${pkt}, ${pkt.old_pkt}, last_known_client_version);

				if ( pkt_num == 1 )
					saw_server_pkt1 = true;

				if ( last_known_client_version && saw_server_pkt1)
					confirm();
				}

			if ( gquic_packet )
				{
				//Populate standard GQUIC packet characteristics
				auto rv = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::GQUIC::PublicHeader);
				rv->Assign(0, zeek::val_mgr->Count(pkt_num));

				if ( ${pkt.old_pkt.cid}->present_case_index() )
					{
					auto bytes = ${pkt.old_pkt.cid.bytes};
					auto ptr = reinterpret_cast<const char*>(bytes->data());
					rv->Assign(1, new zeek::StringVal(bytes->size(), ptr));
					}
				rv->Assign(2, zeek::val_mgr->Bool(${pkt.flags.have_version}));
				if ( ${pkt.old_pkt}->version_case_index() )
					rv->Assign(3, zeek::val_mgr->Count(pkt_version));

				if ( ${pkt.flags.hello_length} == true )
					{
					if ( ${pkt.search.expected_string.hello_check} == true )
						{
						zeek::BifEvent::enqueue_gquic_hello(zeek_analyzer(), zeek_analyzer()->Conn(), is_orig, rv,
																							  {zeek::AdoptRef{}, hello_packet_creation(${pkt}, is_orig)});
						}
					else if ( ${pkt.search.expected_string.rej_check} == true)
						{
						zeek::BifEvent::enqueue_gquic_rej(zeek_analyzer(), zeek_analyzer()->Conn(), is_orig, rv,
																							{zeek::AdoptRef{}, rej_packet_creation(${pkt}, is_orig)});
						}
					else
						{
						zeek::BifEvent::enqueue_gquic_packet(zeek_analyzer(), zeek_analyzer()->Conn(), is_orig, rv);
						}
					}

				else
					{
					zeek::BifEvent::enqueue_gquic_packet(zeek_analyzer(), zeek_analyzer()->Conn(), is_orig, rv);
					}
				}
			}
			break;
		default:
			break;
		}

		return true;
		%}

	function hello_packet_creation(pkt: GQUIC_Packet, is_orig: bool): ZeekVal
		%{
		//Populate the characteristics of the Hello Packet
		static auto hello_info = zeek::id::find_type<zeek::RecordType>("GQUIC::HelloInfo");
		auto* hi_1 = new zeek::RecordVal(hello_info);
		if ( ${pkt.search.build_hello.yes.tag_number} )
			{
			auto bytes = ${pkt.search.build_hello.yes.tag_number};
			hi_1->Assign(0, zeek::val_mgr->Count(bytes));
			hi_1->Assign(1, new zeek::StringVal(${pkt.search.build_hello.yes.other_tags.seek_tags}.length(), (const char*)${pkt.search.build_hello.yes.other_tags.seek_tags}.begin()));
			auto bytes2 = ${pkt.search.build_hello.yes.p_tag_offset};
			hi_1->Assign(2, zeek::val_mgr->Count(bytes2));
			}
		if ( ${pkt.search.build_hello.yes.other_tags.sni_check} )
			hi_1->Assign(3, new zeek::StringVal(${pkt.search.build_hello.yes.sni.collect}.length(), (const char*)${pkt.search.build_hello.yes.sni.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.stk_check} )
			hi_1->Assign(4, new zeek::StringVal(${pkt.search.build_hello.yes.stk.collect}.length(), (const char*)${pkt.search.build_hello.yes.stk.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.sno_check} )
			hi_1->Assign(5, new zeek::StringVal(${pkt.search.build_hello.yes.sno.collect}.length(), (const char*)${pkt.search.build_hello.yes.sno.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.ver_check} )
			hi_1->Assign(6, new zeek::StringVal(${pkt.search.build_hello.yes.ver.collect}.length(), (const char*)${pkt.search.build_hello.yes.ver.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.ccs_check} )
			hi_1->Assign(7, new zeek::StringVal(${pkt.search.build_hello.yes.ccs.collect}.length(), (const char*)${pkt.search.build_hello.yes.ccs.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.nonc_check} )
			hi_1->Assign(8, new zeek::StringVal(${pkt.search.build_hello.yes.nonc.collect}.length(), (const char*)${pkt.search.build_hello.yes.nonc.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.mspc_check} )
			hi_1->Assign(9, new zeek::StringVal(${pkt.search.build_hello.yes.mspc.collect}.length(), (const char*)${pkt.search.build_hello.yes.mspc.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.aead_check} )
			hi_1->Assign(10, new zeek::StringVal(${pkt.search.build_hello.yes.aead.collect}.length(), (const char*)${pkt.search.build_hello.yes.aead.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.uaid_check} )
			hi_1->Assign(11, new zeek::StringVal(${pkt.search.build_hello.yes.uaid.collect}.length(), (const char*)${pkt.search.build_hello.yes.uaid.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.scid_check} )
			hi_1->Assign(12, new zeek::StringVal(${pkt.search.build_hello.yes.scid.collect}.length(), (const char*)${pkt.search.build_hello.yes.scid.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.tcid_check} )
			hi_1->Assign(13, new zeek::StringVal(${pkt.search.build_hello.yes.tcid.collect}.length(), (const char*)${pkt.search.build_hello.yes.tcid.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.pdmd_check} )
			hi_1->Assign(14, new zeek::StringVal(${pkt.search.build_hello.yes.pdmd.collect}.length(), (const char*)${pkt.search.build_hello.yes.pdmd.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.smhl_check} )
			hi_1->Assign(15, new zeek::StringVal(${pkt.search.build_hello.yes.smhl.collect}.length(), (const char*)${pkt.search.build_hello.yes.smhl.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.icsl_check} )
			hi_1->Assign(16, new zeek::StringVal(${pkt.search.build_hello.yes.icsl.collect}.length(), (const char*)${pkt.search.build_hello.yes.icsl.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.ctim_check} )
			hi_1->Assign(17, new zeek::StringVal(${pkt.search.build_hello.yes.ctim.collect}.length(), (const char*)${pkt.search.build_hello.yes.ctim.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.nonp_check} )
			hi_1->Assign(18, new zeek::StringVal(${pkt.search.build_hello.yes.nonp.collect}.length(), (const char*)${pkt.search.build_hello.yes.nonp.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.pubs_check} )
			hi_1->Assign(19, new zeek::StringVal(${pkt.search.build_hello.yes.pubs.collect}.length(), (const char*)${pkt.search.build_hello.yes.pubs.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.mids_check} )
			hi_1->Assign(20, new zeek::StringVal(${pkt.search.build_hello.yes.mids.collect}.length(), (const char*)${pkt.search.build_hello.yes.mids.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.scls_check} )
			hi_1->Assign(21, new zeek::StringVal(${pkt.search.build_hello.yes.scls.collect}.length(), (const char*)${pkt.search.build_hello.yes.scls.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.kexs_check} )
			hi_1->Assign(22, new zeek::StringVal(${pkt.search.build_hello.yes.kexs.collect}.length(), (const char*)${pkt.search.build_hello.yes.kexs.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.xlct_check} )
			hi_1->Assign(23, new zeek::StringVal(${pkt.search.build_hello.yes.xlct.collect}.length(), (const char*)${pkt.search.build_hello.yes.xlct.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.csct_check} )
			hi_1->Assign(24, new zeek::StringVal(${pkt.search.build_hello.yes.csct.collect}.length(), (const char*)${pkt.search.build_hello.yes.csct.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.copt_check} )
			hi_1->Assign(25, new zeek::StringVal(${pkt.search.build_hello.yes.copt.collect}.length(), (const char*)${pkt.search.build_hello.yes.copt.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.ccrt_check} )
			hi_1->Assign(26, new zeek::StringVal(${pkt.search.build_hello.yes.ccrt.collect}.length(), (const char*)${pkt.search.build_hello.yes.ccrt.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.irtt_check} )
			hi_1->Assign(27, new zeek::StringVal(${pkt.search.build_hello.yes.irtt.collect}.length(), (const char*)${pkt.search.build_hello.yes.irtt.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.cetv_check} )
			hi_1->Assign(28, new zeek::StringVal(${pkt.search.build_hello.yes.cetv.collect}.length(), (const char*)${pkt.search.build_hello.yes.cetv.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.cfcw_check} )
			hi_1->Assign(29, new zeek::StringVal(${pkt.search.build_hello.yes.cfcw.collect}.length(), (const char*)${pkt.search.build_hello.yes.cfcw.collect}.begin()));
		if ( ${pkt.search.build_hello.yes.other_tags.sfcw_check} )
			hi_1->Assign(30, new zeek::StringVal(${pkt.search.build_hello.yes.sfcw.collect}.length(), (const char*)${pkt.search.build_hello.yes.sfcw.collect}.begin()));
		return hi_1;
	%}

	function rej_packet_creation(pkt: GQUIC_Packet, is_orig: bool): ZeekVal
		%{
		static auto rej_info = zeek::id::find_type<zeek::RecordType>("GQUIC::RejInfo");
		auto* rej_1 = new zeek::RecordVal(rej_info);
		if ( ${pkt.search.build_hello.rej.tag_number} )
			rej_1->Assign(0, zeek::val_mgr->Count(${pkt.search.build_hello.rej.tag_number}));
		rej_1->Assign(1, new zeek::StringVal(${pkt.search.build_hello.rej.other_tags.seek_tags}.length(), (const char*)${pkt.search.build_hello.rej.other_tags.seek_tags}.begin()));
		if ( ${pkt.search.build_hello.rej.other_tags.stk_check} )
			rej_1->Assign(2, new zeek::StringVal(${pkt.search.build_hello.rej.stk.collect}.length(), (const char*)${pkt.search.build_hello.rej.stk.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.other_tags.sno_check} )
			rej_1->Assign(3, new zeek::StringVal(${pkt.search.build_hello.rej.sno.collect}.length(), (const char*)${pkt.search.build_hello.rej.sno.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.other_tags.svid_check} )
			rej_1->Assign(4, new zeek::StringVal(${pkt.search.build_hello.rej.svid.collect}.length(), (const char*)${pkt.search.build_hello.rej.svid.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.other_tags.prof_check} )
			rej_1->Assign(5, new zeek::StringVal(${pkt.search.build_hello.rej.prof.collect}.length(), (const char*)${pkt.search.build_hello.rej.prof.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.other_tags.scfg_check} )
			rej_1->Assign(6, new zeek::StringVal(${pkt.search.build_hello.rej.scfg.collect.other_tags.seek_tags}.length(), (const char*)${pkt.search.build_hello.rej.scfg.collect.other_tags.seek_tags}.begin()));
		if ( ${pkt.search.build_hello.rej.other_tags.rrej_check} )
			rej_1->Assign(7, new zeek::StringVal(${pkt.search.build_hello.rej.rrej.collect}.length(), (const char*)${pkt.search.build_hello.rej.rrej.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.other_tags.sttl_check} )
			rej_1->Assign(8, new zeek::StringVal(${pkt.search.build_hello.rej.sttl.collect}.length(), (const char*)${pkt.search.build_hello.rej.sttl.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.other_tags.csct_check} )
			rej_1->Assign(9, new zeek::StringVal(${pkt.search.build_hello.rej.csct.collect}.length(), (const char*)${pkt.search.build_hello.rej.csct.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.scfg.collect.other_tags.ver_check} )
			rej_1->Assign(10, new zeek::StringVal(${pkt.search.build_hello.rej.scfg.collect.ver.collect}.length(), (const char*)${pkt.search.build_hello.rej.scfg.collect.ver.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.scfg.collect.other_tags.aead_check} )
			rej_1->Assign(11, new zeek::StringVal(${pkt.search.build_hello.rej.scfg.collect.aead.collect}.length(), (const char*)${pkt.search.build_hello.rej.scfg.collect.aead.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.scfg.collect.other_tags.scid_check} )
			rej_1->Assign(12, new zeek::StringVal(${pkt.search.build_hello.rej.scfg.collect.scid.collect}.length(), (const char*)${pkt.search.build_hello.rej.scfg.collect.scid.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.scfg.collect.other_tags.pdmd_check} )
			rej_1->Assign(13, new zeek::StringVal(${pkt.search.build_hello.rej.scfg.collect.pdmd.collect}.length(), (const char*)${pkt.search.build_hello.rej.scfg.collect.pdmd.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.scfg.collect.other_tags.tbkp_check} )
			rej_1->Assign(14, new zeek::StringVal(${pkt.search.build_hello.rej.scfg.collect.tbkp.collect}.length(), (const char*)${pkt.search.build_hello.rej.scfg.collect.tbkp.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.scfg.collect.other_tags.pubs_check} )
			rej_1->Assign(15, new zeek::StringVal(${pkt.search.build_hello.rej.scfg.collect.pubs.collect}.length(), (const char*)${pkt.search.build_hello.rej.scfg.collect.pubs.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.scfg.collect.other_tags.kexs_check} )
			rej_1->Assign(16, new zeek::StringVal(${pkt.search.build_hello.rej.scfg.collect.kexs.collect}.length(), (const char*)${pkt.search.build_hello.rej.scfg.collect.kexs.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.scfg.collect.other_tags.obit_check} )
			rej_1->Assign(17, new zeek::StringVal(${pkt.search.build_hello.rej.scfg.collect.obit.collect}.length(), (const char*)${pkt.search.build_hello.rej.scfg.collect.obit.collect}.begin()));
		if ( ${pkt.search.build_hello.rej.scfg.collect.other_tags.expy_check} )
			rej_1->Assign(18, new zeek::StringVal(${pkt.search.build_hello.rej.scfg.collect.expy.collect}.length(), (const char*)${pkt.search.build_hello.rej.scfg.collect.expy.collect}.begin()));
		rej_1->Assign(19, zeek::val_mgr->Count(${pkt.search.build_hello.rej.scfg.collect.tag_number}));
		return rej_1;
		%}


	function get_gquic_version(reg_pkt: RegularPacket): uint16
		%{
		if ( ! reg_pkt->version_case_index() )
			return 0;

		return extract_gquic_version(${reg_pkt.version_val}.data());
		%}

	function get_gquic_version_old(old_pkt: OldPacket): uint16
		%{
		if ( ! old_pkt->version_case_index() )
			return 0;

		return extract_gquic_version(${old_pkt.version_val}->data());
		%}

	function get_packet_number_current(pkt: GQUIC_Packet, reg_pkt: RegularPacket, version: uint16): uint64
		%{
		return convert_packet_bytes(get_packet_number_bytes_current(pkt, reg_pkt), version);
		%}

	function get_packet_number_bytes_current(pkt: GQUIC_Packet, reg_pkt: RegularPacket): uint8[]
		%{
		switch ( reg_pkt->pkt_num_bytes_case_index() ) {
			case 0x00:
				return ${pkt.reg_pkt.pkt_num_bytes1};
			case 0x01:
				return ${pkt.reg_pkt.pkt_num_bytes2};
			case 0x02:
				return ${pkt.reg_pkt.pkt_num_bytes3};
			case 0x03:
				return ${pkt.reg_pkt.pkt_num_bytes4};
			default:
				assert(false);
		}
		return nullptr;
		%}

	function get_packet_number_old(pkt: GQUIC_Packet, old_pkt: OldPacket, version: uint16): uint64
		%{
		return convert_packet_bytes(get_packet_number_bytes_old(pkt, old_pkt), version);
		%}

	function get_packet_number_bytes_old(pkt: GQUIC_Packet, old_pkt: OldPacket): uint8[]
		%{
		switch ( old_pkt->pkt_num_bytes_case_index() ) {
			case 0x00:
				return ${pkt.old_pkt.pkt_num_bytes1};
			case 0x10:
				return ${pkt.old_pkt.pkt_num_bytes2};
			case 0x20:
				return ${pkt.old_pkt.pkt_num_bytes4};
			case 0x30:
				return ${pkt.old_pkt.pkt_num_bytes6};
			default:
				assert(false);
		}
		return nullptr;
		%}

	function convert_packet_bytes(bytes: uint8[], version: uint16): uint64
		%{
		uint64 rval = 0;
		uint8* byte_ptr = reinterpret_cast<uint8*>(&rval);
		byte_ptr += sizeof(rval) - bytes->size();

		for ( auto i = 0u; i < bytes->size(); ++i )
			{
			auto byte = (*bytes)[i];
			*byte_ptr = byte;
			++byte_ptr;
			}

		// Version 0 essentially means we haven't seen a version yet, so
		// assume a recent version of GQUIC.
		auto gquic_is_big_endian = version == 0 || version >= 39;

		if ( gquic_is_big_endian )
			rval = zeek::ntohll(rval);
		else
			{
#ifdef WORDS_BIGENDIAN
			uint64 tmp;
			uint8* src = reinterpret_cast<uint8*>(&rval);
			uint8* dst = reinterpret_cast<uint8*>(&tmp);
			dst[0] = src[7];
			dst[1] = src[6];
			dst[2] = src[5];
			dst[3] = src[4];
			dst[4] = src[3];
			dst[5] = src[2];
			dst[6] = src[1];
			dst[7] = src[0];
			rval = tmp;
#endif
			}

		return rval;
		%}
};

refine typeattr GQUIC_Packet += &let {
	proc = $context.connection.process_packet(this, is_orig);
};
