#include <iostream>
#include <pcap.h>

using namespace std;

void usage() {
	cout << "syntax : reduce-pcap <src pcap file> <dst pcap file>" << endl;
	cout << "sample : reduce-pcap input.pcap output.pcap" << endl;
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

	std::string inputPcapFile = argv[1];
	std::string outputPcapFile = argv[2];

	char errBuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_offline(inputPcapFile.c_str(), errBuf);
	if (pcap == nullptr) {
		fprintf(stderr, "pcap_open_offline(%s) return nullptr\n", inputPcapFile.c_str());
		return -1;
	}

	pcap_dumper_t* dumper = pcap_dump_open(pcap, outputPcapFile.c_str());
	if (dumper == nullptr) {
		fprintf(stderr, "pcap_dump_open(%s) return nullptr\n", outputPcapFile.c_str());
		return -1;
	}

	pcap_t* pcap_filter = pcap_open_dead(pcap_datalink(pcap), 1);
	bpf_program* code = static_cast<bpf_program*>(malloc(sizeof(bpf_program)));
	std::string filter = "udp port 53";
	int res = pcap_compile(pcap_filter, code, filter.c_str(), 1, 0xFFFFFFFF);
	if (res < 0) {
		fprintf(stderr, "pcap_compile(%s) return %d\n", filter.c_str(), res);
		return -1;
	}

	while (true) {
		pcap_pkthdr* header;
		const u_char* packet;
		int i = pcap_next_ex(pcap, &header, &packet);
		if (i == 0) continue;
		if (i == -1 || i == -2) break;
		bool filtered = bpf_filter(code->bf_insns, packet, header->len, header->caplen) > 0;
		if (!filtered && header->caplen > 54)
			header->caplen = 54;
		pcap_dump(reinterpret_cast<u_char*>(dumper), header, packet);
	}

	if (pcap_filter != nullptr) {
		pcap_close(pcap_filter);
		pcap_filter = nullptr;
	}
	if (code != nullptr) {
		pcap_freecode(code);
		free(code);
		code = nullptr;
	}
	if (dumper != nullptr) {
		pcap_dump_close(dumper);
		dumper = nullptr;
	}
	if (pcap != nullptr) {
		pcap_close(pcap);
		pcap = nullptr;
	}
}
