event gquic_packet(c: connection, is_orig: bool, hdr: GQUIC::PublicHeader)
	{
#	print "gquic_packet", c$id, is_orig, hdr;
	}

event gquic_hello(c: connection, is_orig: bool, hdr: GQUIC::PublicHeader, hello: GQUIC::HelloInfo)
	{
#	print "gquic_hello", c$id, is_orig, hdr, hello;
	}

event gquic_client_version(c: connection, version: count)
	{
#	print "gquic_client_version", c$id, version;
	}

event gquic_rej(c: connection, is_orig: bool, hdr: GQUIC::PublicHeader, rej: GQUIC::RejInfo)
	{
	#print "gquic rejection", c$id, is_orig, hdr, rej;
	}
