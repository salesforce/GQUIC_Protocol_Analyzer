# GQUIC Protocol Analyzer
This analyzer parses GQUIC traffic in Bro/Zeek for logging and detection purposes.  It examines the initial exchange between a client and server communicating over GQUIC, and extracts the information contained in the connection's client hello packet and  server rejection packet.  Currently, this protocol analyzer supports GQUIC versions Q039 to Q046.

## Installing the GQUIC Protocol Analyzer using Source Tree

##### For a standard installation

 ```sh
./configure --bro-dist=/path/to/bro/dist
make
make install
```

##### To test before installation
```sh
export BRO_PLUGIN_PATH=/path/to/bro-quic/build
bro -N
```
##### To see all options, including setting the install path, run:
 ```sh
./configure --help
```
## CYU
To provide further insight and help detect anomalous (and potentially malicious) GQUIC traffic, fingerprinting is utilized.  The fingerprinting method, named "CYU" works by identifying the GQUIC version and tags present in client hello packets.  First, the version of the packet is extracted, immediately followed by a comma.  After this, each tag in the client hello packet is gathered and concatenated together with hyphens to delimit each tag.  For example: `46,PAD-SNI-STK-VER-CCS-NONC-AEAD-UAID-SCID-TCID-PDMD-SMHL-ICSL-NONP-PUBS-MIDS-SCLS-KEXS-XLCT-CSCT-COPT-CCRT-IRTT-CFCW-SFCW`.  After this string is created, it is then MD5 hashed to produce an easily shareable fingerprint.  Hashing the previous string results in a CYU value of `a46560d4548108cf99308319b3b85346`.  This is the most common fingerprint, making up the vast majority of GQUIC traffic.

### Use case: Merlin C2
The CYU fingerprinting method can be very useful when it comes to detecting beacons transmitting to servers over GQUIC.  For example, Merlin C2 clients use very few tags in their client hellos, giving them an anomalous fingerprints.
Known Merlin beacon fingerprints: `e030dea1f2eea44ac7db5fe4de792acd`, `0811fab28e41e8c8a33e220a15b964d9`, `d8b208b236d176c89407500dbefb04c2`.

## New Events Created
The GQUIC protocol analyzer adds new four events which can be called in Zeek scripts.
### gquic_packet
```sh
event (c: connection, is_orig: bool, hdr: GQUIC::PublicHeader)
```
Generated whenever a regular GQUIC packet is raised.
* **c**: The connection.
* **is_orig**: True if the event is raised for the originator side.
* **hdr**: A data type which contains the packet number, connection ID, and version of a GQUIC packet.

### gquic_client_version
```sh
event event(c: connection, version: count)
```
Raised whenever a GQUIC client sends a Regular Packet with a novel GQUIC version number.
* **c**: The connection.
* **version**: The version number seen in the packet.

### gquic_hello
```sh
event (c: connection, is_orig: bool, hdr: GQUIC::PublicHeader, hello: GQUIC::HelloInfo);
```
Generated whenever a client hello packet is detected in GQUIC traffic.  It includes the additional information contained in the hello packet.
* **c**: The connection.
* **is_orig**: True if the event is raised for the originator side.
* **hdr**: A data type which contains the packet number, connection ID, and version of a GQUIC packet.
* **hello**: A data type which contains the information about the tags of a client hello packet.

### gquic_rej
```sh
event (c: connection, is_orig: bool, hdr: GQUIC::PublicHeader, rej: GQUIC::RejInfo);
```
Generated whenever a rejection packet (server hello) is detected in GQUIC traffic.  It includes the additional information contained in the rejection packet.
* **c**: The connection.
* **is_orig**: True if the event is raised for the originator side.
* **hdr**: A data type which contains the packet number, connection ID, and version of a GQUIC packet.
* **rej**: A data type which contains the information about the tags of a server rejection packet.

## New Constants
Defined in the init.bro script, a constant named `skip_after_confirm` is set to true.  This means that only the initial exchange between the client and server will be captured.  This is done to reduce noise, but it also reduces some visibility.  It can be set to true as one sees fit.

## New Types Created
The GQUIC protocol analyzer adds three new data types which can be referenced in Zeek scripts.
### type: PublicHeader
```sh
pkt_num: count
cid: string &optional
version_exists: bool
version: count &optional
```
* **pkt_num**: The packet number in the GQUIC traffic.
* **cid**: The unique, client-selected, connection ID which defines the connection.
* **version_exists**: True if the version number is in the packet header.
* **version**: The GQUIC version used by the packet and stream.

### type: HelloInfo
```sh
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
```
* **tag**: The total number of tags found in the client hello packet
* **tag_list**: This captures the list of tags and their offsets in the order which they appear in the client hello packet.
* **padding_len**: The offset at which padding length starts.  Currently it is set to zero.
* **sni**: The fully qualified DNS name of the server, canonicalized to lowercase with no trailing period. Internationalized domain names need to be encoded as A-labels defined in RFC 5890.
* **stk**: The source-address token that the server has previously provided, if any.
* **sno**: An echoed server nonce, if the server has provided one.
* **ver**: The protocol version advertised by the client.
* **ccs**: A series of 64-bit, FNV-1a hashes of sets of common certificates that the client possesses.
* **nonc**: 32 bytes consisting of 4 bytes of timestamp (big-endian, UNIX epoch seconds), 8 bytes of server orbit and 20 bytes of random data.
* **mspc**: The value through which each endpoint to independently set maximum number of supported streams.  Being replaced by MIDS ("Maximum Incoming Dynamic Streams").
* **aead**: Contains the tag of the encryption algorithm to be used.
* **uaid**: Contains the value of the user agent that sent the client hello packet.
* **scid**: 16-byte identifier for the ID of the server configuration that the client is using.
* **tcid**: Indicates support for truncated Connection IDs. If sent by a peer, indicates the connection IDs sent to the peer should be truncated to 0 bytes. Useful for cases when a client ephemeral port is only used for a single connection.
* **pdmd**: A list of tags describing the types of proof acceptable to the client, in preference order. Currently only X509 is defined.
* **smhl**: The value of support max header list (size).
* **icsl**: The value denoting implicit shutdown.  The default idle timeout for a QUIC connection is 30 seconds. The maximum is 10 minutes. If there is no network activity for the duration of the idle timeout, the connection is closed.
* **ctim**: The value of the client timestamp.
* **nonp**: The 32 byte value of the client proof nonce.
* **pubs**: The client’s public value for the given key exchange algorithm.  24-bit, little-endian length prefixed, in the same order as in KEXS.  P-256 public values, if any, are encoded as uncompressed points in X9.62 format.
* **mids**: The value of the set maximum number of supported incoming streams.
* **scls**: The value which permits a silent close upon timeout.
* **kexs**:  The selected tag of the key exchange algorithm to be used.  Currently defined tags include C255 and P256.
* **xlct**:  A 64-bit,  FNV-1a hash of the leaf certificate that the client expects the server to be using. The full contents of the certificate will be added into the HMAC-based key derivation function. If cached certificates are present, the first such entry should be identical to the value of this field.
* **csct**:  The value of the signed cert timestamp, which is often missing.
* **copt**:  The field contains any connection options being requested by the client or server.  These are typically used for experimentation and will evolve over time.  Example use cases include changing congestion control algorithms and parameters such as initial window.
* **ccrt**:  A series of 64-bit, FNV-1a hashes of cached certificates for this server.
* **irtt**:  The value of the estimated initial round trip time for the connection.
* **cetv**:  Specifies client certificates, Channel IDs and other non-public data in the client hello and encrypted using the AEAD. 
* **cfcw**: The size in bytes of the connection level flow control window.
* **sfcw**: The size in bytes of the stream level flow control window.

### type: RejInfo
```sh
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
```
* **tag_count**: The total number of tags found in the rejection packet
* **tag_list**: This captures the list of tags and their offsets in the order which they appear in the server rejection packet.  Does not include tags found under SCFG.
* **stk**: An opaque byte string that the client should echo in future client hello messages.
* **sno**: The server may set a nonce, which the client should echo in any future client hello messages. This allows a server to operate without a strike-register and for clients with clock-skew to connect.
* **svid**: The SVID tag was once found in a pcap of Merlin C2 traffic.  This tag is not currently supported by Wireshark.
* **prof**: In the case of X.509, a signature of the server config by the public key in the leaf certificate. The format of the signature is currently fixed by the type of public key.  
* **scfg**: A message containing the server’s serialized config with its own set of tag/value pairs.  
* **rrej**: The value which signifies why the server sent the rejection packet. 
* **sttl**: The duration, in seconds, that the server config is valid for. 
* **csct**: The value of the signed certificate timestamp (defined by RFC 6962) of the leaf certificate
* **ver**: Lists the versions that the server is able to use.
* **aead**: A list of tags, in preference order, specifying the AEAD primitives supported by the server.
* **scid**: 16-byte identifier for this server configuration.
* **pdmd**: Used for finding proof acceptable to the client. Currently only X509 is defined.
* **tbkp**: Value of the token.
* **pubs**: A list of public values, 24-bit, little-endian length prefixed, in the same order as in KEXS. P-256 public values, if any, are encoded as uncompressed points in X9.62 format.
* **kexs**: The selected tag of the key exchange algorithm to be used.  Currently defined tags include C255 and P256.
* **obit**: An 8-byte, opaque value that identifies the strike-register.
* **expy**: A 64-bit expiry time for the server config in UNIX epoch seconds.
* **embedded_count**: The number of tags/value pairs defined in the server config message.


## Credits
Created by:
* [Caleb Yu](https://www.linkedin.com/in/caleb-yu)

With assistance from:
* [John Althouse](https://twitter.com/4A4133)
* [Rakesh Passa](https://twitter.com/Sithari443)
* The [Corelight Team](https://github.com/corelight/bro-quic)
* Salesforce Threat Detection Team

### References:
* https://docs.google.com/document/d/1g5nIXAIkN_Y-7XJW5K45IblHd_L2f5LTaDUDwvZ5L6g
* https://docs.google.com/document/d/1WJvyZflAO2pq77yOLbp9NsGjC1CHetAXV8I0fQe-B_U
