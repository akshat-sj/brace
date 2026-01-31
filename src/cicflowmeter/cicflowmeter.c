/*
 * cicflowmeter.c - Lightweight C implementation of CICFlowMeter
 * Outputs 82 flow features compatible with CIC-IDS datasets
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <math.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>

#define MAX_FLOWS 50000
#define FLOW_TIMEOUT_SEC 120
#define ACTIVE_TIMEOUT 5.0
#define CLUMP_TIMEOUT 1.0
#define BULK_BOUND 4

typedef struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} flow_key;

typedef struct pkt_info {
    double timestamp;
    int length;
    int header_len;
    int payload_len;
    int direction;
    uint8_t tcp_flags;
    uint16_t tcp_window;
} pkt_info;

typedef struct flow_stats {
    flow_key key;
    char src_ip_str[16];
    char dst_ip_str[16];

    pkt_info *packets;
    int packet_count;
    int packet_capacity;

    double start_timestamp;
    double latest_timestamp;

    int init_fwd_win_byts;
    int init_bwd_win_byts;
    int fwd_win_set;
    int bwd_win_set;

    double start_active;
    double last_active;
    double *active_times;
    double *idle_times;
    int active_count;
    int idle_count;
    int active_capacity;
    int idle_capacity;

    double *flow_iat;
    int flow_iat_count;
    int flow_iat_capacity;

    double fwd_bulk_last_timestamp;
    double fwd_bulk_start_tmp;
    int fwd_bulk_count;
    int fwd_bulk_count_tmp;
    double fwd_bulk_duration;
    int fwd_bulk_packet_count;
    int fwd_bulk_size;
    int fwd_bulk_size_tmp;

    double bwd_bulk_last_timestamp;
    double bwd_bulk_start_tmp;
    int bwd_bulk_count;
    int bwd_bulk_count_tmp;
    double bwd_bulk_duration;
    int bwd_bulk_packet_count;
    int bwd_bulk_size;
    int bwd_bulk_size_tmp;
} flow_stats;

flow_stats *flows = NULL;
int flow_count = 0;
pcap_t *global_handle = NULL;
char *output_filename = "flows.csv";
int verbose = 0;

static inline double timeval_to_sec(struct timeval tv) {
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

static double get_var(double *arr, int n) {
    if (n < 1) return 0.0;
    double mean = 0.0;
    for (int i = 0; i < n; i++) mean += arr[i];
    mean /= n;
    double var = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = arr[i] - mean;
        var += diff * diff;
    }
    return var / n;
}

static double get_std(double *arr, int n) { return sqrt(get_var(arr, n)); }
static double get_mean(double *arr, int n) {
    if (n < 1) return 0.0;
    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += arr[i];
    return sum / n;
}

static double get_max(double *arr, int n) {
    if (n < 1) return 0.0;
    double max = arr[0];
    for (int i = 1; i < n; i++) if (arr[i] > max) max = arr[i];
    return max;
}

static double get_min(double *arr, int n) {
    if (n < 1) return 0.0;
    double min = arr[0];
    for (int i = 1; i < n; i++) if (arr[i] < min) min = arr[i];
    return min;
}

static double get_sum(double *arr, int n) {
    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += arr[i];
    return sum;
}

static int get_int_max(int *arr, int n) {
    if (n < 1) return 0;
    int max = arr[0];
    for (int i = 1; i < n; i++) if (arr[i] > max) max = arr[i];
    return max;
}

static int get_int_min(int *arr, int n) {
    if (n < 1) return 0;
    int min = arr[0];
    for (int i = 1; i < n; i++) if (arr[i] < min) min = arr[i];
    return min;
}

void init_flow(flow_stats *f, flow_key *key, pkt_info *pkt) {
    memset(f, 0, sizeof(flow_stats));
    f->key = *key;

    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = key->src_ip;
    dst_addr.s_addr = key->dst_ip;
    inet_ntop(AF_INET, &src_addr, f->src_ip_str, 16);
    inet_ntop(AF_INET, &dst_addr, f->dst_ip_str, 16);

    f->packet_capacity = 100;
    f->packets = malloc(f->packet_capacity * sizeof(pkt_info));
    f->flow_iat_capacity = 100;
    f->flow_iat = malloc(f->flow_iat_capacity * sizeof(double));
    f->active_capacity = 50;
    f->idle_capacity = 50;
    f->active_times = malloc(f->active_capacity * sizeof(double));
    f->idle_times = malloc(f->idle_capacity * sizeof(double));

    f->start_timestamp = pkt->timestamp;
    f->latest_timestamp = pkt->timestamp;
    f->start_active = pkt->timestamp;
    f->last_active = 0;

    if (pkt->direction == 0 && pkt->tcp_window > 0) {
        f->init_fwd_win_byts = pkt->tcp_window;
        f->fwd_win_set = 1;
    }
}

void free_flow(flow_stats *f) {
    if (f->packets) free(f->packets);
    if (f->flow_iat) free(f->flow_iat);
    if (f->active_times) free(f->active_times);
    if (f->idle_times) free(f->idle_times);
}

int compare_flow_key(flow_key *a, flow_key *b) {
    if (a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
        a->src_port == b->src_port && a->dst_port == b->dst_port &&
        a->protocol == b->protocol)
        return 1;
    if (a->src_ip == b->dst_ip && a->dst_ip == b->src_ip &&
        a->src_port == b->dst_port && a->dst_port == b->src_port &&
        a->protocol == b->protocol)
        return 2;
    return 0;
}

int find_flow(flow_key *key) {
    for (int i = 0; i < flow_count; i++) {
        if (compare_flow_key(&flows[i].key, key)) return i;
    }
    return -1;
}

void update_flow_bulk(flow_stats *f, pkt_info *pkt) {
    if (pkt->payload_len == 0) return;

    if (pkt->direction == 0) {
        if (f->bwd_bulk_last_timestamp > f->fwd_bulk_start_tmp)
            f->fwd_bulk_start_tmp = 0;
        if (f->fwd_bulk_start_tmp == 0) {
            f->fwd_bulk_start_tmp = pkt->timestamp;
            f->fwd_bulk_last_timestamp = pkt->timestamp;
            f->fwd_bulk_count_tmp = 1;
            f->fwd_bulk_size_tmp = pkt->payload_len;
        } else {
            if ((pkt->timestamp - f->fwd_bulk_last_timestamp) > CLUMP_TIMEOUT) {
                f->fwd_bulk_start_tmp = pkt->timestamp;
                f->fwd_bulk_last_timestamp = pkt->timestamp;
                f->fwd_bulk_count_tmp = 1;
                f->fwd_bulk_size_tmp = pkt->payload_len;
            } else {
                f->fwd_bulk_count_tmp++;
                f->fwd_bulk_size_tmp += pkt->payload_len;
                if (f->fwd_bulk_count_tmp == BULK_BOUND) {
                    f->fwd_bulk_count++;
                    f->fwd_bulk_packet_count += f->fwd_bulk_count_tmp;
                    f->fwd_bulk_size += f->fwd_bulk_size_tmp;
                    f->fwd_bulk_duration += (pkt->timestamp - f->fwd_bulk_start_tmp);
                } else if (f->fwd_bulk_count_tmp > BULK_BOUND) {
                    f->fwd_bulk_packet_count++;
                    f->fwd_bulk_size += pkt->payload_len;
                    f->fwd_bulk_duration += (pkt->timestamp - f->fwd_bulk_last_timestamp);
                }
                f->fwd_bulk_last_timestamp = pkt->timestamp;
            }
        }
    } else {
        if (f->fwd_bulk_last_timestamp > f->bwd_bulk_start_tmp)
            f->bwd_bulk_start_tmp = 0;
        if (f->bwd_bulk_start_tmp == 0) {
            f->bwd_bulk_start_tmp = pkt->timestamp;
            f->bwd_bulk_last_timestamp = pkt->timestamp;
            f->bwd_bulk_count_tmp = 1;
            f->bwd_bulk_size_tmp = pkt->payload_len;
        } else {
            if ((pkt->timestamp - f->bwd_bulk_last_timestamp) > CLUMP_TIMEOUT) {
                f->bwd_bulk_start_tmp = pkt->timestamp;
                f->bwd_bulk_last_timestamp = pkt->timestamp;
                f->bwd_bulk_count_tmp = 1;
                f->bwd_bulk_size_tmp = pkt->payload_len;
            } else {
                f->bwd_bulk_count_tmp++;
                f->bwd_bulk_size_tmp += pkt->payload_len;
                if (f->bwd_bulk_count_tmp == BULK_BOUND) {
                    f->bwd_bulk_count++;
                    f->bwd_bulk_packet_count += f->bwd_bulk_count_tmp;
                    f->bwd_bulk_size += f->bwd_bulk_size_tmp;
                    f->bwd_bulk_duration += (pkt->timestamp - f->bwd_bulk_start_tmp);
                } else if (f->bwd_bulk_count_tmp > BULK_BOUND) {
                    f->bwd_bulk_packet_count++;
                    f->bwd_bulk_size += pkt->payload_len;
                    f->bwd_bulk_duration += (pkt->timestamp - f->bwd_bulk_last_timestamp);
                }
                f->bwd_bulk_last_timestamp = pkt->timestamp;
            }
        }
    }
}

void write_csv(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) { perror("fopen"); return; }

    fprintf(fp,
        "src_ip,dst_ip,src_port,dst_port,protocol,timestamp,"
        "flow_duration,flow_byts_s,flow_pkts_s,fwd_pkts_s,bwd_pkts_s,"
        "tot_fwd_pkts,tot_bwd_pkts,totlen_fwd_pkts,totlen_bwd_pkts,"
        "fwd_pkt_len_max,fwd_pkt_len_min,fwd_pkt_len_mean,fwd_pkt_len_std,"
        "bwd_pkt_len_max,bwd_pkt_len_min,bwd_pkt_len_mean,bwd_pkt_len_std,"
        "pkt_len_max,pkt_len_min,pkt_len_mean,pkt_len_std,pkt_len_var,"
        "fwd_header_len,bwd_header_len,fwd_seg_size_min,fwd_act_data_pkts,"
        "flow_iat_mean,flow_iat_max,flow_iat_min,flow_iat_std,"
        "fwd_iat_tot,fwd_iat_max,fwd_iat_min,fwd_iat_mean,fwd_iat_std,"
        "bwd_iat_tot,bwd_iat_max,bwd_iat_min,bwd_iat_mean,bwd_iat_std,"
        "fwd_psh_flags,bwd_psh_flags,fwd_urg_flags,bwd_urg_flags,"
        "fin_flag_cnt,syn_flag_cnt,rst_flag_cnt,psh_flag_cnt,ack_flag_cnt,urg_flag_cnt,ece_flag_cnt,"
        "down_up_ratio,pkt_size_avg,init_fwd_win_byts,init_bwd_win_byts,"
        "active_max,active_min,active_mean,active_std,"
        "idle_max,idle_min,idle_mean,idle_std,"
        "fwd_byts_b_avg,fwd_pkts_b_avg,bwd_byts_b_avg,bwd_pkts_b_avg,"
        "fwd_blk_rate_avg,bwd_blk_rate_avg,fwd_seg_size_avg,bwd_seg_size_avg,"
        "cwr_flag_count,subflow_fwd_pkts,subflow_bwd_pkts,subflow_fwd_byts,subflow_bwd_byts\n"
    );

    int written = 0;
    for (int i = 0; i < flow_count; i++) {
        flow_stats *f = &flows[i];
        if (f->packet_count < 1) continue;

        int fwd_count = 0, bwd_count = 0;
        int totlen_fwd = 0, totlen_bwd = 0;
        int fwd_header_len = 0, bwd_header_len = 0;
        int fwd_act_data_pkts = 0;

        double *fwd_lengths = malloc(f->packet_count * sizeof(double));
        double *bwd_lengths = malloc(f->packet_count * sizeof(double));
        double *all_lengths = malloc(f->packet_count * sizeof(double));
        int *fwd_header_sizes = malloc(f->packet_count * sizeof(int));
        double *fwd_iat = malloc(f->packet_count * sizeof(double));
        double *bwd_iat = malloc(f->packet_count * sizeof(double));
        int fwd_iat_count = 0, bwd_iat_count = 0;

        int fwd_psh = 0, bwd_psh = 0, fwd_urg = 0, bwd_urg = 0;
        int fin_cnt = 0, syn_cnt = 0, rst_cnt = 0, psh_cnt = 0;
        int ack_cnt = 0, urg_cnt = 0, ece_cnt = 0, cwr_cnt = 0;

        double last_fwd_time = -1, last_bwd_time = -1;

        for (int j = 0; j < f->packet_count; j++) {
            pkt_info *p = &f->packets[j];
            all_lengths[j] = p->length;

            if (p->direction == 0) {
                fwd_lengths[fwd_count] = p->length;
                fwd_header_sizes[fwd_count] = p->header_len;
                totlen_fwd += p->length;
                fwd_header_len += p->header_len;
                if (p->payload_len > 0) fwd_act_data_pkts++;
                if (last_fwd_time >= 0)
                    fwd_iat[fwd_iat_count++] = p->timestamp - last_fwd_time;
                last_fwd_time = p->timestamp;
                if (p->tcp_flags & TH_PUSH) fwd_psh++;
                if (p->tcp_flags & TH_URG) fwd_urg++;
                fwd_count++;
            } else {
                bwd_lengths[bwd_count] = p->length;
                totlen_bwd += p->length;
                bwd_header_len += p->header_len;
                if (last_bwd_time >= 0)
                    bwd_iat[bwd_iat_count++] = p->timestamp - last_bwd_time;
                last_bwd_time = p->timestamp;
                if (p->tcp_flags & TH_PUSH) bwd_psh++;
                if (p->tcp_flags & TH_URG) bwd_urg++;
                bwd_count++;
            }

            if (p->tcp_flags & TH_FIN) fin_cnt++;
            if (p->tcp_flags & TH_SYN) syn_cnt++;
            if (p->tcp_flags & TH_RST) rst_cnt++;
            if (p->tcp_flags & TH_PUSH) psh_cnt++;
            if (p->tcp_flags & TH_ACK) ack_cnt++;
            if (p->tcp_flags & TH_URG) urg_cnt++;
            if (p->tcp_flags & 0x40) ece_cnt++;
            if (p->tcp_flags & 0x80) cwr_cnt++;
        }

        double flow_duration = f->latest_timestamp - f->start_timestamp;
        int total_bytes = totlen_fwd + totlen_bwd;
        int total_pkts = f->packet_count;
        double flow_byts_s = flow_duration > 0 ? total_bytes / flow_duration : 0;
        double flow_pkts_s = flow_duration > 0 ? total_pkts / flow_duration : 0;
        double fwd_pkts_s = flow_duration > 0 ? fwd_count / flow_duration : 0;
        double bwd_pkts_s = flow_duration > 0 ? bwd_count / flow_duration : 0;

        double fwd_pkt_len_max = fwd_count > 0 ? get_max(fwd_lengths, fwd_count) : 0;
        double fwd_pkt_len_min = fwd_count > 0 ? get_min(fwd_lengths, fwd_count) : 0;
        double fwd_pkt_len_mean = fwd_count > 0 ? get_mean(fwd_lengths, fwd_count) : 0;
        double fwd_pkt_len_std = fwd_count > 0 ? get_std(fwd_lengths, fwd_count) : 0;

        double bwd_pkt_len_max = bwd_count > 0 ? get_max(bwd_lengths, bwd_count) : 0;
        double bwd_pkt_len_min = bwd_count > 0 ? get_min(bwd_lengths, bwd_count) : 0;
        double bwd_pkt_len_mean = bwd_count > 0 ? get_mean(bwd_lengths, bwd_count) : 0;
        double bwd_pkt_len_std = bwd_count > 0 ? get_std(bwd_lengths, bwd_count) : 0;

        double pkt_len_max = get_max(all_lengths, f->packet_count);
        double pkt_len_min = get_min(all_lengths, f->packet_count);
        double pkt_len_mean = get_mean(all_lengths, f->packet_count);
        double pkt_len_std = get_std(all_lengths, f->packet_count);
        double pkt_len_var = get_var(all_lengths, f->packet_count);

        int fwd_seg_size_min = fwd_count > 0 ? get_int_min(fwd_header_sizes, fwd_count) : 0;

        double flow_iat_mean_val = f->flow_iat_count > 0 ? get_mean(f->flow_iat, f->flow_iat_count) : 0;
        double flow_iat_max_val = f->flow_iat_count > 0 ? get_max(f->flow_iat, f->flow_iat_count) : 0;
        double flow_iat_min_val = f->flow_iat_count > 0 ? get_min(f->flow_iat, f->flow_iat_count) : 0;
        double flow_iat_std_val = f->flow_iat_count > 0 ? get_std(f->flow_iat, f->flow_iat_count) : 0;

        double fwd_iat_tot = fwd_iat_count > 0 ? get_sum(fwd_iat, fwd_iat_count) : 0;
        double fwd_iat_max_val = fwd_iat_count > 0 ? get_max(fwd_iat, fwd_iat_count) : 0;
        double fwd_iat_min_val = fwd_iat_count > 0 ? get_min(fwd_iat, fwd_iat_count) : 0;
        double fwd_iat_mean_val = fwd_iat_count > 0 ? get_mean(fwd_iat, fwd_iat_count) : 0;
        double fwd_iat_std_val = fwd_iat_count > 0 ? get_std(fwd_iat, fwd_iat_count) : 0;

        double bwd_iat_tot = bwd_iat_count > 0 ? get_sum(bwd_iat, bwd_iat_count) : 0;
        double bwd_iat_max_val = bwd_iat_count > 0 ? get_max(bwd_iat, bwd_iat_count) : 0;
        double bwd_iat_min_val = bwd_iat_count > 0 ? get_min(bwd_iat, bwd_iat_count) : 0;
        double bwd_iat_mean_val = bwd_iat_count > 0 ? get_mean(bwd_iat, bwd_iat_count) : 0;
        double bwd_iat_std_val = bwd_iat_count > 0 ? get_std(bwd_iat, bwd_iat_count) : 0;

        double down_up_ratio = fwd_count > 0 ? (double)bwd_count / fwd_count : 0;
        double pkt_size_avg = total_pkts > 0 ? (double)total_bytes / total_pkts : 0;

        double active_max = f->active_count > 0 ? get_max(f->active_times, f->active_count) : 0;
        double active_min = f->active_count > 0 ? get_min(f->active_times, f->active_count) : 0;
        double active_mean = f->active_count > 0 ? get_mean(f->active_times, f->active_count) : 0;
        double active_std = f->active_count > 0 ? get_std(f->active_times, f->active_count) : 0;

        double idle_max = f->idle_count > 0 ? get_max(f->idle_times, f->idle_count) : 0;
        double idle_min = f->idle_count > 0 ? get_min(f->idle_times, f->idle_count) : 0;
        double idle_mean = f->idle_count > 0 ? get_mean(f->idle_times, f->idle_count) : 0;
        double idle_std = f->idle_count > 0 ? get_std(f->idle_times, f->idle_count) : 0;

        double fwd_byts_b_avg = f->fwd_bulk_count > 0 ? (double)f->fwd_bulk_size / f->fwd_bulk_count : 0;
        double fwd_pkts_b_avg = f->fwd_bulk_count > 0 ? (double)f->fwd_bulk_packet_count / f->fwd_bulk_count : 0;
        double bwd_byts_b_avg = f->bwd_bulk_count > 0 ? (double)f->bwd_bulk_size / f->bwd_bulk_count : 0;
        double bwd_pkts_b_avg = f->bwd_bulk_count > 0 ? (double)f->bwd_bulk_packet_count / f->bwd_bulk_count : 0;
        double fwd_blk_rate_avg = f->fwd_bulk_duration > 0 ? (double)f->fwd_bulk_size / f->fwd_bulk_duration : 0;
        double bwd_blk_rate_avg = f->bwd_bulk_duration > 0 ? (double)f->bwd_bulk_size / f->bwd_bulk_duration : 0;

        time_t ts = (time_t)f->start_timestamp;
        struct tm *tm_info = localtime(&ts);
        char timestamp_str[32];
        strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);

        fprintf(fp,
            "%s,%s,%d,%d,%d,%s,"
            "%.6f,%.6f,%.6f,%.6f,%.6f,"
            "%d,%d,%d,%d,"
            "%.0f,%.0f,%.6f,%.6f,"
            "%.0f,%.0f,%.6f,%.6f,"
            "%.0f,%.0f,%.6f,%.6f,%.6f,"
            "%d,%d,%d,%d,"
            "%.6f,%.6f,%.6f,%.6f,"
            "%.6f,%.6f,%.6f,%.6f,%.6f,"
            "%.6f,%.6f,%.6f,%.6f,%.6f,"
            "%d,%d,%d,%d,"
            "%d,%d,%d,%d,%d,%d,%d,"
            "%.6f,%.6f,%d,%d,"
            "%.6f,%.6f,%.6f,%.6f,"
            "%.6f,%.6f,%.6f,%.6f,"
            "%.6f,%.6f,%.6f,%.6f,"
            "%.6f,%.6f,%.6f,%.6f,"
            "%d,%d,%d,%d,%d\n",
            f->src_ip_str, f->dst_ip_str, f->key.src_port, f->key.dst_port, f->key.protocol, timestamp_str,
            flow_duration, flow_byts_s, flow_pkts_s, fwd_pkts_s, bwd_pkts_s,
            fwd_count, bwd_count, totlen_fwd, totlen_bwd,
            fwd_pkt_len_max, fwd_pkt_len_min, fwd_pkt_len_mean, fwd_pkt_len_std,
            bwd_pkt_len_max, bwd_pkt_len_min, bwd_pkt_len_mean, bwd_pkt_len_std,
            pkt_len_max, pkt_len_min, pkt_len_mean, pkt_len_std, pkt_len_var,
            fwd_header_len, bwd_header_len, fwd_seg_size_min, fwd_act_data_pkts,
            flow_iat_mean_val, flow_iat_max_val, flow_iat_min_val, flow_iat_std_val,
            fwd_iat_tot, fwd_iat_max_val, fwd_iat_min_val, fwd_iat_mean_val, fwd_iat_std_val,
            bwd_iat_tot, bwd_iat_max_val, bwd_iat_min_val, bwd_iat_mean_val, bwd_iat_std_val,
            fwd_psh, bwd_psh, fwd_urg, bwd_urg,
            fin_cnt, syn_cnt, rst_cnt, psh_cnt, ack_cnt, urg_cnt, ece_cnt,
            down_up_ratio, pkt_size_avg, f->init_fwd_win_byts, f->init_bwd_win_byts,
            active_max, active_min, active_mean, active_std,
            idle_max, idle_min, idle_mean, idle_std,
            fwd_byts_b_avg, fwd_pkts_b_avg, bwd_byts_b_avg, bwd_pkts_b_avg,
            fwd_blk_rate_avg, bwd_blk_rate_avg, fwd_pkt_len_mean, bwd_pkt_len_mean,
            cwr_cnt, fwd_count, bwd_count, totlen_fwd, totlen_bwd
        );

        free(fwd_lengths);
        free(bwd_lengths);
        free(all_lengths);
        free(fwd_header_sizes);
        free(fwd_iat);
        free(bwd_iat);
        written++;
    }

    fclose(fp);
    printf("Wrote %d flows to %s\n", written, filename);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int link_type = *(int *)args;
    int ip_offset;

    switch (link_type) {
        case DLT_EN10MB:     ip_offset = 14; break;
        case DLT_RAW:        ip_offset = 0;  break;
        case DLT_LINUX_SLL:  ip_offset = 16; break;
        case DLT_NULL:
        case DLT_LOOP:       ip_offset = 4;  break;
        default: return;
    }

    if (link_type == DLT_EN10MB) {
        struct ether_header *eth = (struct ether_header *)packet;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;
    }

    struct ip *ip = (struct ip *)(packet + ip_offset);
    if (ip->ip_v != 4) return;

    int ip_hdr_len = ip->ip_hl * 4;
    if (ip_hdr_len < 20) return;

    flow_key key = {0};
    key.src_ip = ip->ip_src.s_addr;
    key.dst_ip = ip->ip_dst.s_addr;
    key.protocol = ip->ip_p;

    uint16_t src_port = 0, dst_port = 0;
    uint8_t tcp_flags = 0;
    uint16_t tcp_window = 0;
    int payload_len = 0;

    if (ip->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(packet + ip_offset + ip_hdr_len);
        src_port = ntohs(tcp->th_sport);
        dst_port = ntohs(tcp->th_dport);
        tcp_flags = tcp->th_flags;
        tcp_window = ntohs(tcp->th_win);
        int tcp_hdr_len = tcp->th_off * 4;
        payload_len = ntohs(ip->ip_len) - ip_hdr_len - tcp_hdr_len;
        if (payload_len < 0) payload_len = 0;
    } else if (ip->ip_p == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(packet + ip_offset + ip_hdr_len);
        src_port = ntohs(udp->uh_sport);
        dst_port = ntohs(udp->uh_dport);
        payload_len = ntohs(udp->uh_ulen) - 8;
        if (payload_len < 0) payload_len = 0;
    } else {
        payload_len = ntohs(ip->ip_len) - ip_hdr_len;
    }

    key.src_port = src_port;
    key.dst_port = dst_port;

    pkt_info pkt = {
        .timestamp = timeval_to_sec(header->ts),
        .length = header->len,
        .header_len = ip_hdr_len,
        .payload_len = payload_len,
        .tcp_flags = tcp_flags,
        .tcp_window = tcp_window,
        .direction = 0
    };

    int idx = find_flow(&key);

    if (idx == -1) {
        if (flow_count >= MAX_FLOWS) {
            fprintf(stderr, "Max flows reached, writing output\n");
            write_csv(output_filename);
            for (int i = 0; i < flow_count; i++) free_flow(&flows[i]);
            flow_count = 0;
        }
        idx = flow_count++;
        init_flow(&flows[idx], &key, &pkt);
    } else {
        pkt.direction = (compare_flow_key(&flows[idx].key, &key) == 2) ? 1 : 0;
    }

    flow_stats *f = &flows[idx];

    if (f->packet_count >= f->packet_capacity) {
        f->packet_capacity *= 2;
        f->packets = realloc(f->packets, f->packet_capacity * sizeof(pkt_info));
    }
    f->packets[f->packet_count++] = pkt;

    if (f->packet_count > 1) {
        double iat = pkt.timestamp - f->latest_timestamp;
        if (f->flow_iat_count >= f->flow_iat_capacity) {
            f->flow_iat_capacity *= 2;
            f->flow_iat = realloc(f->flow_iat, f->flow_iat_capacity * sizeof(double));
        }
        f->flow_iat[f->flow_iat_count++] = iat;
    }

    if (f->latest_timestamp > 0) {
        double time_diff = pkt.timestamp - f->latest_timestamp;
        if (time_diff > CLUMP_TIMEOUT) {
            double current_time = pkt.timestamp;
            if (f->last_active > 0 && (current_time - f->last_active) > ACTIVE_TIMEOUT) {
                double duration = fabs(f->last_active - f->start_active);
                if (duration > 0) {
                    if (f->active_count >= f->active_capacity) {
                        f->active_capacity *= 2;
                        f->active_times = realloc(f->active_times, f->active_capacity * sizeof(double));
                    }
                    f->active_times[f->active_count++] = duration;
                }
                if (f->idle_count >= f->idle_capacity) {
                    f->idle_capacity *= 2;
                    f->idle_times = realloc(f->idle_times, f->idle_capacity * sizeof(double));
                }
                f->idle_times[f->idle_count++] = current_time - f->last_active;
                f->start_active = current_time;
            }
            f->last_active = pkt.timestamp;
        } else {
            f->last_active = pkt.timestamp;
        }
    } else {
        f->last_active = pkt.timestamp;
    }

    update_flow_bulk(f, &pkt);

    if (pkt.timestamp > f->latest_timestamp)
        f->latest_timestamp = pkt.timestamp;

    if (pkt.direction == 0 && !f->fwd_win_set && tcp_window > 0) {
        f->init_fwd_win_byts = tcp_window;
        f->fwd_win_set = 1;
    } else if (pkt.direction == 1 && !f->bwd_win_set && tcp_window > 0) {
        f->init_bwd_win_byts = tcp_window;
        f->bwd_win_set = 1;
    }
}

void handle_sigint(int sig) {
    (void)sig;
    printf("\nInterrupted, writing flows...\n");
    write_csv(output_filename);
    for (int i = 0; i < flow_count; i++) free_flow(&flows[i]);
    free(flows);
    if (global_handle) {
        pcap_breakloop(global_handle);
        pcap_close(global_handle);
    }
    exit(0);
}

void print_usage(const char *prog) {
    printf("Usage: %s [-i interface | -f pcap] [-o output.csv] [-v]\n", prog);
    printf("  -i  Capture from network interface\n");
    printf("  -f  Read from pcap file\n");
    printf("  -o  Output CSV file (default: flows.csv)\n");
    printf("  -v  Verbose output\n");
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *pcap_file = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int opt;

    while ((opt = getopt(argc, argv, "i:f:o:vh")) != -1) {
        switch (opt) {
            case 'i': interface = optarg; break;
            case 'f': pcap_file = optarg; break;
            case 'o': output_filename = optarg; break;
            case 'v': verbose = 1; break;
            case 'h':
            default:
                print_usage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }

    if (!interface && !pcap_file) {
        print_usage(argv[0]);
        return 1;
    }

    flows = calloc(MAX_FLOWS, sizeof(flow_stats));
    if (!flows) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }

    pcap_t *handle;
    int link_type;

    if (pcap_file) {
        handle = pcap_open_offline(pcap_file, errbuf);
        if (!handle) {
            fprintf(stderr, "Cannot open %s: %s\n", pcap_file, errbuf);
            return 2;
        }
        if (verbose) printf("Reading: %s\n", pcap_file);
    } else {
        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            fprintf(stderr, "Cannot open %s: %s\n", interface, errbuf);
            return 2;
        }
        if (verbose) printf("Capturing: %s\n", interface);
    }

    link_type = pcap_datalink(handle);
    if (verbose) printf("Link type: %s\nOutput: %s\n", pcap_datalink_val_to_name(link_type), output_filename);

    global_handle = handle;
    signal(SIGINT, handle_sigint);

    if (!pcap_file) printf("Press Ctrl+C to stop capture\n");

    pcap_loop(handle, 0, packet_handler, (u_char *)&link_type);

    write_csv(output_filename);

    for (int i = 0; i < flow_count; i++) free_flow(&flows[i]);
    free(flows);
    pcap_close(handle);

    return 0;
}
