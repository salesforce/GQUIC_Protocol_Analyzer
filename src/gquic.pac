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
