#include <libxml/parser.h>
#define USAGE "Usage: %s xmlfile\n"

main(int argc, char **argv)
{
    char errbuf[2048];
    errbuf[0] = '\0';
    xmlDocPtr doc;

    if (argc < 2) {
	fprintf(stderr, USAGE, argv[0]);
	exit(1);
    }
    xmlInitParser();
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    doc = xmlParseFile(argv[1]);

    if (gaa_simple_i_xml_sig_ok(doc, errbuf, sizeof(errbuf))) {
	printf("signature is okay\n");
    } else {
	printf("signature is bad\n");
    }
}
