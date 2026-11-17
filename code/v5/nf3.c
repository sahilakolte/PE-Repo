#include "nf_lib.h"

static void handle(struct nf_pkt *p)
{
    print_packet_info(p->data, p->off, p->len, "NF3");
}

int main(void)
{
    return nf_run("nf3", handle);
}
