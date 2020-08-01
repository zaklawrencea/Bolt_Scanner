#ifndef MAIN_H
#define MAIN_H

// From tcp.h
#define TCP_USER_TIMEOUT 0  // how long for loss retry before timeout [ms]

// Includes
#include <linux/tcp.h> // tcp header - linux
#include <stdbool.h> // bool
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h> // getopt
#include <ctype.h> // isprint
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/ip.h> // ip header - linux
#include <linux/if.h> // local ip (interfaces)
#include <pthread.h>
#include <sys/time.h>

// Structs
struct  ScanOptions {
        // /24 for now
        char *targets[257];
        int target_count;
        int current_target;
        int targets_scanned;
        bool subnet;
        char *x_ptr;

        char *source_ip;
        char *interface;
        
        int port_min;
        int port_max;
        int no_of_ports;
        int port;
        int source_port;
        int current_port;
        int connect_port_delay;
        int port_delay;

        int micro_delay;
        char *buffer; 
        char datagram[2048];
        int data;
        bool scan_finished;

        int timeout;
        int time_to_live;

        bool verbose;
        char *output_file;

        char *flags;

        // For calculating the elapsed time
        struct timeval timer_start, timer_stop;
        unsigned long elapsed_time, elapsed_time_ms;

        enum scan_types{
                HALF_OPEN,
                CONNECT,
                ACK,
                FIN,
                XMAS,
                NULL_scan,
                CUSTOM
        } scan_type;

        struct Results {
                char *target_ip_addr;
                int port_counter;

                struct Port {
                        int port_num;
                        bool status_open;
                        bool status_closed;
                        bool status_unfiltered;
                        bool status_unknown;

                }port_number[65536];

        }*target_ip_addr;

        struct ChecksumHeader {
                int source_address;
                int dest_address;
                char placeholder;
                char protocol;
                short tcp_length;

                struct tcphdr tcp;
        } checksum_header;

        struct iphdr *ip_header;
        struct tcphdr *tcp_header;

        pthread_t listener_thread;
};

// Functions
void print_help();
void print_extended_help();
void set_packet_details(struct ScanOptions *);
void init();
void print_output(struct ScanOptions *);
void apply_flags(int, char **, struct ScanOptions *);
void filter_flags(struct ScanOptions *);
void resolve_subnet(struct ScanOptions *);
void *receive_packet(void *);
void *connect_scan(void *);
void *perform_scan(void *);
void start_scan(struct ScanOptions *, pthread_t);
void *parse_packet(void *);
void write_to_file(struct ScanOptions *);
void get_local_ip_address(struct ScanOptions *);
unsigned short csum(unsigned short *, int);
void free_mem(struct ScanOptions *);
bool handle_inputs(struct ScanOptions *);

#endif
