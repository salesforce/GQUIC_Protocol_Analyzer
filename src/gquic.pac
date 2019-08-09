# Copyright (c) 2019, salesforce.com, inc.
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
# For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause

%include binpac.pac
%include bro.pac

%extern{
#include "GQUIC.h"
#include "events.bif.h"
%}

analyzer GQUIC withcontext {
    connection: GQUIC_Conn;
    flow:       GQUIC_Flow;
};

connection GQUIC_Conn(bro_analyzer: BroAnalyzer) {
    upflow   = GQUIC_Flow(true);
    downflow = GQUIC_Flow(false);
};

%include gquic-protocol.pac

flow GQUIC_Flow(is_orig: bool) {
	datagram = GQUIC_Packet(is_orig) withcontext(connection, this);
};

%include gquic-analyzer.pac
