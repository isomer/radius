#include "libtrace.h"
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

typedef struct radius_t {
    uint8_t  code;
    uint8_t  identifier;
    uint16_t length;
    uint8_t  authenticator[16];
} radius_t;

static const char *radius_code_name[] = {
    /* 0 */ "Zero",
    /* 1 */ "Access-Request",
    /* 2 */ "Access-Accept",
    /* 3 */ "Access-Reject",
    /* 4 */ "Accounting-Request",
    /* 5 */ "Accounting-Response",
    /* 6 */ "Six",
    /* 7 */ "Seven",
    /* 8 */ "Eight",
    /* 9 */ "Nine",
    /* 10 */ "Ten",
    /* 11 */ "Access-Challenge",
    /* 12 */ "Status-Server",
    /* 13 */ "Status-Client",
};


typedef struct eap_header_t {
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
} eap_header_t;

static void dump_bytes(uint8_t *data, uint32_t len)
{
    for(uint32_t i=0; i<len; ++i) {
        if (data[i] >= ' ' && data[i] <= '~')
            printf("%c", data[i]);
        else
            printf("\\x%02x", data[i]);
    }
}

static void decode_eap(uint8_t *payload, uint32_t remaining)
{
    printf("EAP:\n");
    if (remaining < sizeof(eap_header_t)) {
        printf(" Truncated header\n");
        return;
    }
    eap_header_t *header = payload;
    payload += sizeof(*header);
    remaining -= sizeof(*header);
    switch(header->code) {
        case 1: /* Request */
        case 2: /* Response */
            printf(" Code: %s\n", header->code == 1 ? "Request" : "Response");
            switch (payload[0]) {
                case 1: printf(" Type: Identity\n");
                        printf(" Message: ");
                        dump_bytes(&payload[1], remaining-1);
                        printf("\n");
                        break;

                case 2:
                        printf(" Type: Notification\n");
                        printf(" Message: ");
                        dump_bytes(&payload[1], remaining-1);
                        printf("\n");
                        break;
                case 3:
                        printf(" Type: Nak\n");
                        printf(" Required type: %d\n", payload[1]);
                        break;
                case 4: printf(" Type: MD5-Challenge\n"); break;
                case 5: printf(" Type: One Time Password\n"); break;
                case 6:  printf(" Type: Generic Token Card\n"); break;
                case 25: printf(" Type: PEAP\n"); break;
                default:
                        printf(" Type: #%d\n", payload[0]);
                        break;
            }
            break;
        case 3: /* Success */
        case 4: /* Failure */
            printf(" Code: %s\n", header->code == 3 ? "Success" : "Failure");
            break;
        default:
            printf(" Code: #%d\n", header->code);
            break;
    }
}

const char *get_attribute_name(uint8_t attribute)
{
    switch (attribute) {
        case  1: return "User-Name";
        case  4: return "NAS-IP Address";
        case  5: return "NAS-Port";
        case  6: return "Service-Type";
        case 12: return "Framed-MTU";
        case 22: return "Framed-Route";
        case 24: return "State";
        case 25: return "Class";
        case 26: return "Vendor-Specific";
        case 27: return "Session-Timeout";
        case 30: return "Called-Station-Id";
        case 31: return "Calling-Station-Id";
        case 32: return "NAS-Identifier";
        case 33: return "Proxy-State";
        case 48: return "Acct-Output-Packets";
        case 61: return "NAS-Port-Type";
        case 79: return "EAP-Message";
        case 80: return "Message-Authenticator";
        case 83: return "Tunnel-Preference";
        case 87: return "NAS-Port-Id";
        default:
                 return NULL;
    }
}


static void process_radius(uint8_t *payload, uint32_t remaining)
{
    radius_t *radius = (void*)payload;
    if (remaining < sizeof(radius_t)) {
        printf("Runt packet\n");
        return;
    }
    if (ntohs(radius->length) > remaining) {
        printf("Runt packet\n");
        return;
    }
    if (ntohs(radius->length) != remaining) {
        printf("Packet too big, truncating to %d bytes\n", ntohs(radius->length));
        remaining = radius->length;
    }
    printf("Code: %d", radius->code);
    if (radius->code < sizeof(radius_code_name) / sizeof(radius_code_name[0])) {
        printf(" (%s)\n", radius_code_name[radius->code]);
    }
    else
        printf("\n");
    printf("Identifier: %d\n", radius->identifier);
    printf("Length: %d\n", radius->length);
    printf("Authenticator:");
    for(int i=0; i<sizeof(radius->authenticator); ++i) {
        printf(" %02x", radius->authenticator[i]);
    }
    printf("\n");

    uint8_t *data = payload + sizeof(radius_t);
    remaining -= sizeof(radius_t);
    uint8_t *eap = NULL;
    size_t eaplen = 0;
    while (remaining > 2) {
        uint8_t type = data[0];
        uint8_t length = data[1];
        printf("Attribute %d", type);
        if (get_attribute_name(type))
            printf(" [%s]", get_attribute_name(type));
        printf(" (%d bytes): ", length);
        if (length < 2) {
            printf("Invalid length\n");
            return;
        }
        if (remaining < length) {
            printf("TRUNCATED\n");
            break;
        }
        data += 2;
        remaining -= 2;
        dump_bytes(data, length-2);
        switch (type) {
            case 79: /* EAP Message */
                eap = realloc(eap, eaplen + length);
                memcpy(&eap[eaplen], data, length);
                eaplen += length;
        }
        data += (length-2);
        remaining -= (length-2);
        printf("\n");
    }
    if (remaining != 0)
        printf("Data left over?\n");
    if (eap) {
        decode_eap(eap, eaplen);
    }
    printf("\n");

}

static void per_packet(libtrace_packet_t *packet)
{
	assert(packet);
        uint32_t remaining;
        uint8_t proto;
        void *transport = trace_get_transport(packet, &proto, &remaining);
        if (!transport || proto != TRACE_IPPROTO_UDP)
            return;
        void *radius = trace_get_payload_from_udp(transport, &remaining);
        if (!radius)
            return;
        process_radius(radius, remaining);
}

static void usage(char *argv0)
{
	fprintf(stderr,"usage: %s [ --filter | -f bpfexp ]  [ --snaplen | -s snap ]\n\t\t[ --promisc | -p flag] [ --help | -h ] [ --libtrace-help | -H ] libtraceuri...\n",argv0);
}

int main(int argc, char *argv[])
{
	libtrace_t *trace;
	libtrace_packet_t *packet;
	libtrace_filter_t *filter=NULL;
	int snaplen=-1;
	int promisc=-1;

	while(1) {
		int option_index;
		struct option long_options[] = {
			{ "filter",		1, 0, 'f' },
			{ "snaplen",		1, 0, 's' },
			{ "promisc",		1, 0, 'p' },
			{ "help",		0, 0, 'h' },
			{ "libtrace-help",	0, 0, 'H' },
			{ NULL,			0, 0, 0 }
		};

		int c= getopt_long(argc, argv, "f:s:p:hH",
				long_options, &option_index);

		if (c==-1)
			break;

		switch (c) {
			case 'f':
				filter=trace_create_filter(optarg);
				break;
			case 's':
				snaplen=atoi(optarg);
				break;
			case 'p':
				promisc=atoi(optarg);
				break;
			case 'H':
				trace_help();
				return 1;
			default:
				fprintf(stderr,"Unknown option: %c\n",c);
				/* FALL THRU */
			case 'h':
				usage(argv[0]);
				return 1;
		}
	}

	if (optind>=argc) {
		fprintf(stderr,"Missing input uri\n");
		usage(argv[0]);
		return 1;
	}

	while (optind<argc) {
		trace = trace_create(argv[optind]);
		++optind;

		if (trace_is_err(trace)) {
			trace_perror(trace,"Opening trace file");
			return 1;
		}

		if (snaplen>0)
			if (trace_config(trace,TRACE_OPTION_SNAPLEN,&snaplen)) {
				trace_perror(trace,"ignoring: ");
			}
		if (filter)
			if (trace_config(trace,TRACE_OPTION_FILTER,filter)) {
				trace_perror(trace,"ignoring: ");
			}
		if (promisc!=-1) {
			if (trace_config(trace,TRACE_OPTION_PROMISC,&promisc)) {
				trace_perror(trace,"ignoring: ");
			}
		}

		if (trace_start(trace)) {
			trace_perror(trace,"Starting trace");
			trace_destroy(trace);
			return 1;
		}

		packet = trace_create_packet();

		while (trace_read_packet(trace,packet)>0) {
			per_packet(packet);
		}

		trace_destroy_packet(packet);

		if (trace_is_err(trace)) {
			trace_perror(trace,"Reading packets");
		}

		trace_destroy(trace);
	}

	return 0;
}
