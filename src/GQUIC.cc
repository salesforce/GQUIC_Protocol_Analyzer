/*
 * Copyright (c) 2019, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

#include "GQUIC.h"
#include "gquic_pac.h"

using namespace analyzer::gquic;

GQUIC_Analyzer::GQUIC_Analyzer(Connection* conn)
: Analyzer("GQUIC", conn)
	{
	interp = new binpac::GQUIC::GQUIC_Conn(this);
	did_session_done = 0;
	orig_done = resp_done = false;
	pia = 0;
	}

GQUIC_Analyzer::~GQUIC_Analyzer()
	{
	delete interp;
	}

void GQUIC_Analyzer::Done()
	{
	Analyzer::Done();

	if ( ! did_session_done )
		Event(udp_session_done);

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void GQUIC_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
                                   uint64 seq, const IP_Hdr* ip,
                                   int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}
