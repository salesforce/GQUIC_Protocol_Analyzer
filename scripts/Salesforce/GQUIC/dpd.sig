signature dpd_gquic {
    ip-proto = udp
    # TODO: could possibly also check for version bit + connection ID
    # in public flags and/or packet #1 to help narrow this down.
    payload /^(.{1}|.{9})Q0[0-9][0-9]/
    enable "gquic"
}
