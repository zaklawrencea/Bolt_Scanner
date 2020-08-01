#include "main.h"
#include "scanOptions.c"

void set_packet_details(struct ScanOptions *so) {

        // IP and TCP header size inits
        memset (so->datagram, 0, 2048);
        so->ip_header = (struct iphdr *) so->datagram;
        so->tcp_header = (struct tcphdr *) (so->datagram + sizeof (struct iphdr));
        
        get_local_ip_address(so);

        if (so->source_ip == NULL) {
                printf("ERROR: Could not fetch local ip\n");
                exit(1);
        }

        printf(" * Local IP set to: %s\n", so->source_ip);

        // IP header main
        // iphdr struct reference: 
        // www.cs.vu.nl/~herbertb/projects/corral/docs/html/structiphdr.html

        so->ip_header->ihl = 5;
        so->ip_header->version = 4; 
        so->ip_header->tos = 0;
        so->ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr); // Total length -- careful here!
        int my_id = rand() % 10000;
        so->ip_header->id = htons(my_id);
        so->ip_header->frag_off = htons(0);
        
        if (so->time_to_live == 0) {
                // Time to live: 
                // 64  default linux
                // 128 default windows
                so->ip_header->ttl = 64;
        }
        else {
                if (so->time_to_live > 255)
                        so->ip_header->ttl = 255;

                else if (so->time_to_live < 1)
                        so->ip_header->ttl = 1;
                
                else
                        so->ip_header->ttl = so->time_to_live;
                
        }
        so->ip_header->protocol = IPPROTO_TCP; // IPPROTO_TCP 6
        so->ip_header->check = csum((unsigned short *) so->datagram, so->ip_header->tot_len >> 1);
        so->ip_header->saddr = inet_addr(so->source_ip);

        // TCP header main
        // tcphdr struct regerence:
        // www.cs.vu.nl/~herbertb/projects/corral/docs/html/structtcphdr.html

        so->tcp_header->dest = htons(80);
        so->tcp_header->seq = htonl(3112279261); // change this to random
        so->tcp_header->ack_seq = 0;
        so->tcp_header->doff = sizeof(struct tcphdr) /4;

        // Where the fun begins
        
        if (so->scan_type != CUSTOM) {
                so->tcp_header->fin = 0;
                so->tcp_header->syn = 0;
                so->tcp_header->rst = 0;
                so->tcp_header->psh = 0;
                so->tcp_header->ack = 0;
                so->tcp_header->urg = 0;
                so->tcp_header->ece = 0;
                so->tcp_header->cwr = 0;
        }

        switch (so->scan_type) {
                case HALF_OPEN:
                        printf(" * Scan type: SYN HALF-OPEN\n");
                        so->tcp_header->syn = 1;
                        break;

                case CONNECT:
                        printf(" * Scan type: TCP CONNECT\n");
                        // No flag setting required.
                        break;
                
                case ACK:
                        printf(" * Scan type: ACK\n");
                        so->tcp_header->ack = 1;
                        break;
                
                case FIN:
                        printf(" * Scan type: FIN\n");
                        so->tcp_header->fin = 1;
                        break;
                
                case XMAS:
                        printf(" * Scan type: XMAS\n");
                        so->tcp_header->fin = 1;
                        so->tcp_header->psh = 1;
                        so->tcp_header->urg = 1;
                        break;
                
                case NULL_scan:
                        printf(" * Scan type: NULL\n");
                        // No flag setting required.
                        break;

                case CUSTOM:
                        filter_flags(so);
                        printf(" * Scan type: CUSTOM");
                        // No flag setting required
                        break;

                default:
                        printf("Error\n");
                        exit(1);
                        
        }
        
        so->tcp_header->window = htons(14600);
        so->tcp_header->check = csum ((unsigned short *) &so->checksum_header, sizeof(struct ChecksumHeader));
        so->tcp_header->urg_ptr = 0;

        so->listener_thread;

        if(pthread_create(&so->listener_thread, NULL, receive_packet, (void *) so) < 0) {
                printf ("Could not create thread. Error number : %d . Error message : %s \n" , errno , strerror(errno));
                exit(1);
        }           

        start_scan(so, so->listener_thread); 
}

/*

This function searches inside the string provided by the
user for certain characters. Each character represent 
one of the TCP flags. If one of the characters is found
it will enable the corresponding flag.

*/
void filter_flags(struct ScanOptions *so) {
        
        if (strlen(so->flags) > 8) {
                printf(" ERROR: Flag string too large\n");
                printf(" Please try a new string.\n");
                exit(1);
        }

        char *search;
        search = so->flags;

        char *ptr_cwr;
        char *ptr_ece;
        char *ptr_urg;
        char *ptr_ack;
        char *ptr_psh;
        char *ptr_rst;
        char *ptr_syn;
        char *ptr_fin;

        int cwr = 'c';
        int ece = 'e';
        int urg = 'u';
        int ack = 'a';
        int psh = 'p';
        int rst = 'r';
        int syn = 's';
        int fin = 'f';

        ptr_cwr = strchr(search, cwr);
        ptr_ece = strchr(search, ece);
        ptr_urg = strchr(search, urg);
        ptr_ack = strchr(search, ack);
        ptr_psh = strchr(search, psh);
        ptr_rst = strchr(search, rst);
        ptr_syn = strchr(search, syn);
        ptr_fin = strchr(search, fin);

        printf(" * Flag(s) set:");
        if (ptr_cwr != NULL) {
                so->tcp_header->cwr = 1;
                printf(" cwr");
        }
        if (ptr_ece != NULL) {
                so->tcp_header->ece = 1;
                printf(" ece");
        }
        if (ptr_urg != NULL) {
                so->tcp_header->urg = 1;
                printf(" urg");
        }
        if (ptr_ack != NULL) {
                so->tcp_header->ack = 1;
                printf(" ack");
        }
        if (ptr_psh != NULL) {
                so->tcp_header->psh = 1;
                printf(" psh");
        }
        if (ptr_rst != NULL) {
                so->tcp_header->rst = 1;
                printf(" rst");
        }
        if (ptr_syn != NULL) {
                so->tcp_header->syn = 1;
                printf(" syn");
        }
        if (ptr_fin != NULL) {
                so->tcp_header->fin = 1;
                printf(" fin");
        }

        if (so->tcp_header->cwr == 0 &&
        (so->tcp_header->ece == 0) &&
        (so->tcp_header->urg == 0) &&
        (so->tcp_header->ack == 0) &&
        (so->tcp_header->psh == 0) &&
        (so->tcp_header->rst == 0) &&
        (so->tcp_header->syn == 0) &&
        (so->tcp_header->fin == 0)) {
                printf(" \n\n Flag argument required.\n\n");
                exit(1);
        }

        printf("\n");
}

void start_scan(struct ScanOptions *so, pthread_t listener_thread) {

        // Sleep here to allow the listening thread to initialise.
        usleep(500000);   
        
        int s;
        if (so->scan_type != CONNECT) {
                // Socket for normal scan
                s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP); 
                if (s < 0) {
                printf ("Error creating socket. Error number : %d . Error message : %s \n" , 
                        errno , strerror(errno));
		exit(1);
                }

                int one = 1; // For IP_HDRINCL
                const int *val = &one; // For IP_HDRINCL
                if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
                        printf ("ERROR: IP_HDRINCL could not be set. Error number : %d . Error message : %s \n" , 
                                errno , strerror(errno));
                        exit(1);
                }
        }

        // A single port with the '-p' flag is still treated as a loop.
        if (so->port != 0) {
                so->port_min = so->port;
                so->port_max = (so->port + 1);
        } 

        printf("\n Starting scan...\n");
        so->checksum_header.source_address = inet_addr(so->source_ip);
        so->checksum_header.protocol = IPPROTO_TCP;
        so->checksum_header.tcp_length = htons( sizeof (struct tcphdr));
        so->checksum_header.placeholder = 0;

        pthread_t scanner_threads[so->target_count];

                for (int i = 0; i < so->target_count; i++) {  
                        if(pthread_create(&scanner_threads[i], NULL, perform_scan, (void *) so) < 0) {
                        printf ("Could not create thread. Error number : %d . Error message : %s \n" , errno , strerror(errno));
                        exit(1);
                        }
        
                        // Allows new thread to use next target
                        usleep(so->micro_delay);
                        so->current_target++;
                }

                for (int i = 0; i < so->target_count; i++) {  
                        if(pthread_join(scanner_threads[i], NULL)) {
                        printf ("Could not join threads. Error number : %d . Error message : %s \n" , errno , strerror(errno));
                        exit(1);
                        }
                }
}

void *connect_scan(void *thread_options) {
        struct ThreadOptions {
                unsigned char *target;
                unsigned int port;
        } *to = (struct ThreadOptions *)thread_options;

        // Socket for connect scan
        int s = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP); //IPPROTO_TCP/RAW/IPPROTO_TCP
        if (s < 0) {
        printf (" Error creating socket. Error number: %d. Error message: %s \n" , 
                errno , strerror(errno));
                exit(1);
        }

        // Set the TCP retransmission timeout so the socket is released.
        int timeout = 1; //timeout in ms

        if (setsockopt (s, IPPROTO_TCP, TCP_USER_TIMEOUT, (char *)&timeout,
                sizeof(timeout)) < 0) {
                printf(" setsockopt failed. Error number: %d. Error message: %s\n",
                errno, strerror(errno));
                exit(1);
        }

        struct sockaddr_in thread_sock_addr_in;
        thread_sock_addr_in.sin_family = AF_INET;
        thread_sock_addr_in.sin_port = htons(to->port);
        thread_sock_addr_in.sin_addr.s_addr = inet_addr(to->target);

        connect(s,(struct sockaddr *) &thread_sock_addr_in, sizeof(thread_sock_addr_in));

        close(s);
}

/*

The perform scan function uses the current target variable from the loop inside the start
scan function in order to set the target IP for the current instance of the thread. Once the target
has been set, the type of scan is determined.

CONNECT SCAN:
A new ThreadOptions struct is initialised to allow a constant target for each new thread 
created as the port loop runs. This new thread only contains the target IP and the Port.
Inside the connect scan function a new, local socket address in struct is created.

OTHER SCANS:
Final details for the raw packet are set and the packet is sent to the current thread's target IP.

*/
void *perform_scan(void *scan_options) {
        struct ScanOptions *so = (struct ScanOptions *)scan_options;
        
        struct ThreadOptions {
                unsigned char *target;
                unsigned int port;
        }thread_options[so->port_max];

        // Setting the target for this thread.
        struct sockaddr_in sock_addr_in;
        unsigned int thread_target_set;
        char *thread_target;
        pthread_t connect_threads[so->port_max - so->port_min];

        if (thread_target_set != 1) {
                thread_target = so->targets[so->current_target];
        }

        thread_target_set = 1;

        if (so->verbose == true) {
                printf(" NEW TARGET: %s\n", thread_target);
        }

        
        int p;
        for(p = so->port_min; p < so->port_max; p++) {

                if (so->scan_type == CONNECT) {
                        
                        // Create a new thread for the connect scan based on the current thread's target.
                        //struct ThreadOptions *to;
                        
                         thread_options[p].target = thread_target;
                         thread_options[p].port = p;
                        
                        if(pthread_create(&connect_threads[p], NULL, connect_scan, (void *) &thread_options[p]) < 0) {
                        printf ("Could not create thread. Error number : %d . Error message : %s \n" , errno , strerror(errno));
                        exit(1);
                        }

                        if (so->verbose)
                                printf(" Target host: %s Target port: %d\n", thread_target, p);

                        // Ensure the port is properly incremented
                        usleep(so->connect_port_delay);
                        

                }
                else {
                        // Socket for half-scans
                        int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP); //IPPROTO_TCP/RAW
                        if (s < 0) {
                                printf ("Error creating socket. Error number : %d . Error message : %s \n" , 
                                        errno , strerror(errno));
                                exit(1);
                        }

                        // For IP_HDRINCL
                        int one = 1;
                        const int *val = &one;

                        if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
                                printf ("ERROR: IP_HDRINCL could not be set. Error number : %d . Error message : %s \n" , 
                                        errno , strerror(errno));
                                exit(1);
                        }
                        sock_addr_in.sin_family = AF_INET;
                        sock_addr_in.sin_addr.s_addr = inet_addr(thread_target);
                        so->ip_header->daddr = inet_addr(thread_target);
                        so->checksum_header.dest_address = inet_addr(thread_target);
                        so->tcp_header->dest = htons(p);
                        so->tcp_header->check = 0;
                        so->source_port = rand() % 65000;
                        so->tcp_header->source = htons(so->source_port);
                        

                        // Copy our tcp header into the sub struct in the checksum header.
                        memcpy(&so->checksum_header.tcp, so->tcp_header, sizeof(struct tcphdr));
                        so->tcp_header->check = csum ((unsigned short *) &so->checksum_header, sizeof(struct ChecksumHeader));                                

                        int num = sendto (s, so->datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                                (struct sockaddr *) &sock_addr_in, sizeof(sock_addr_in)) <0;

                        if (num <0) {
                                printf("ERROR: could not send packet. Error number : %d . Error message : %s \n" , 
                                errno , strerror(errno));
                                        //exit(1);
                        }
                        if (so->verbose)
                                printf(" Packet sent to %s on port %d\n", thread_target, p);
                        
                        close(s);
                        usleep(so->port_delay);
                }
        }

        // Re-join the connect threads.
        // Most should have already timed out.
        if (so->scan_type == CONNECT) {
                for(p = so->port_min; p < so->port_max; p++) {
                        if (pthread_join(connect_threads[p],NULL) <0) {
                                        printf ("Could not join threads. Error number : %d . Error message : %s \n" , errno , strerror(errno));
                                        exit(1);
                        }
                }
        }
        
        so->targets_scanned++;
        if (so->verbose)
                printf(" Target IP %s COMPLETE\n", thread_target);
}

void *receive_packet(void *scan_options) {
        struct ScanOptions *so = (struct ScanOptions *)scan_options;
        
        if (so->verbose)
                printf("\n Starting listener\n");
        // Creating our socket
        int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP); 
        
        if (s < 0) {
                printf ("Error creating socket. Error number : %d . Error message : %s \n" ,
                        errno , strerror(errno));
		exit(1);
        }

        so->buffer = (unsigned char *) malloc(65536);
        memset(so->buffer, 0, 65536);

        struct sockaddr sock_address;
        int sock_address_length = sizeof(sock_address);

        while(1) {
                if(so->scan_finished == false) {
                        so->data = recvfrom(s, so->buffer, 65536, 0, &sock_address, (socklen_t *) &sock_address_length);

                        if(so->data < 0) {
                                printf("ERROR: packets not received correctly.\n");
                                exit(1);
                        }

                        parse_packet(so);
                }
                else {
                        break;
                }
        }
        close(s);
}

void *parse_packet(void *scan_options) {
        struct ScanOptions *so = (struct ScanOptions *)scan_options;
        unsigned short ip_header_length;
        struct iphdr *ip_header = (struct iphdr *)so->buffer;
        struct sockaddr_in source_sock_address_in;

        if (ip_header->protocol == 6) {

                memset(&source_sock_address_in, 0, sizeof(source_sock_address_in));
                source_sock_address_in.sin_addr.s_addr = ip_header->saddr;
                
		ip_header_length = ip_header->ihl*4;
                
                struct tcphdr *tcp_header = (struct tcphdr *)(so->buffer + ip_header_length);
                
                for (int i = 0; i < so->target_count; i++) {  
                        // Check IPs match
                        if(inet_addr(so->targets[i]) == source_sock_address_in.sin_addr.s_addr) {
                                switch (so->scan_type) {
                                        case HALF_OPEN:
                                        case CONNECT:
                                                if (tcp_header->syn == 1 && tcp_header->ack == 1) {
                                                        so->target_ip_addr[i].target_ip_addr = so->targets[i];
                                                        so->target_ip_addr[i].port_number[so->target_ip_addr[i].port_counter].port_num = ntohs(tcp_header->source);
                                                        so->target_ip_addr[i].port_number[so->target_ip_addr[i].port_counter].status_open = true;

                                                        printf(" LIVE RESULT %s PORT %d is OPEN\n", so->target_ip_addr[i].target_ip_addr,
                                                        so->target_ip_addr[i].port_number[so->target_ip_addr[i].port_counter].port_num);

                                                        so->target_ip_addr[i].port_counter++;
                                                }
                                                break;

                                        case ACK:
                                                // Check for a RST response. This means the port is unfiltered.
                                                if (tcp_header->rst == 1) {
                                                        so->target_ip_addr[i].target_ip_addr = so->targets[i];
                                                        so->target_ip_addr[i].port_number[so->target_ip_addr[i].port_counter].port_num = ntohs(tcp_header->source);
                                                        so->target_ip_addr[i].port_number[so->target_ip_addr[i].port_counter].status_unfiltered = true;

                                                        printf(" LIVE RESULT %s PORT %d is UNFILTERED\n", so->target_ip_addr[i].target_ip_addr,
                                                        so->target_ip_addr[i].port_number[so->target_ip_addr[i].port_counter].port_num);
                                                        
                                                        so->target_ip_addr[i].port_counter++;
                                                }
                                                break;

                                        case FIN:
                                        case XMAS:
                                        case NULL_scan:
                                                // Check for a RST response. This means the port is closed. No reply means filtered/open
                                                if (tcp_header->rst == 1) {
                                                        so->target_ip_addr[i].target_ip_addr = so->targets[i];
                                                        so->target_ip_addr[i].port_number[so->target_ip_addr[i].port_counter].port_num = ntohs(tcp_header->source);
                                                        so->target_ip_addr[i].port_number[so->target_ip_addr[i].port_counter].status_closed = true;

                                                        printf(" LIVE RESULT %s PORT %d is CLOSED\n", so->target_ip_addr[i].target_ip_addr,
                                                        so->target_ip_addr[i].port_number[so->target_ip_addr[i].port_counter].port_num);
                                                        
                                                        so->target_ip_addr[i].port_counter++;
                                                        
                                                }
                                                break;

                                        case CUSTOM:
                                                if (tcp_header->ack == 1 || tcp_header->rst == 1) {
                                                        so->target_ip_addr[i].target_ip_addr = so->targets[i];
                                                        so->target_ip_addr[i].port_number[so->target_ip_addr[i].port_counter].port_num = ntohs(tcp_header->source);
                                                        so->target_ip_addr[i].port_number[so->target_ip_addr[i].port_counter].status_unknown = true;

                                                        printf(" LIVE RESULT %s PORT %d packet received\n", so->target_ip_addr[i].target_ip_addr,
                                                        so->target_ip_addr[i].port_number[so->target_ip_addr[i].port_counter].port_num);
                                                
                                                        so->target_ip_addr[i].port_counter++;
                                                        
                                                }
                                                break;
                                }
                                                                                                                            
                                 
                        }           
                }
        }
}

void print_output(struct ScanOptions *so) {

        if (so->output_file != NULL) {
                printf (" ...writing to file %s\n", so->output_file);
                FILE *file = fopen(so->output_file, "w");
                if (file == NULL) {
                printf (" Could not open file. Error number : %d . Error message : %s \n" , 
                        errno , strerror(errno));
                        exit(1);
                }

                fprintf(file, "\n\n ******************************************\n");
                fprintf(file, " *              Bolt Scanner              *\n");
                fprintf(file, " *                 v1.0.0                 *\n");
                fprintf(file, " ******************************************\n");
                fprintf(file, "\n * Target IP/Range: %s\n", so->targets[0]);

                if (so->port != 0)
                        fprintf(file, " * Target Port: %d\n", so->port); 
                else
                        fprintf(file, " * Target Port: %d - %d\n", so->port_min, so->port_max); 
                
                if (so->verbose)
                        fprintf(file, " * Port delay: %d\n", so->port_delay);
                        
                fprintf(file, " * Interface: %s\n", so->interface);
                fprintf(file, " * Local IP: %s\n", so->source_ip);               

                switch (so->scan_type) {
                        case HALF_OPEN:
                                fprintf(file, " * Scan type: SYN HALF-OPEN\n");
                                break;

                        case CONNECT:
                                fprintf(file, " * Scan type: TCP CONNECT\n");
                                break;
                        
                        case ACK:
                                fprintf(file, " * Scan type: ACK\n");
                                break;
                        
                        case FIN:
                                fprintf(file, " * Scan type: FIN\n");
                                break;
                        
                        case XMAS:
                                fprintf(file, " * Scan type: XMAS\n");
                                break;
                        
                        case NULL_scan:
                                fprintf(file, " * Scan type: NULL\n");
                                break;

                        case CUSTOM:
                                filter_flags(so);
                                fprintf(file, " * Scan type: CUSTOM");
                                break;

                        default:
                        printf("Error\n");
                        exit(1);
                }

                //printf(" Scan duration: %ld s %.6ld ms\n",so->elapsed_time, so->elapsed_time_ms);
                //fprintf(file, "\n Scan duration: %ld s %.6ld ms\n",so->elapsed_time, so->elapsed_time_ms);

                printf("\n ***   RESULTS   ***\n");
                fprintf(file, "\n ***   RESULTS   ***\n");

                switch (so->scan_type) {
                        case HALF_OPEN:
                        case CONNECT:
                                for (int t = 0; t < so->target_count; t++) {
                                        for (int p = 0; p < so->target_ip_addr[t].port_counter; p++) {
                                                if (so->target_ip_addr[t].port_number[p].status_open == true) {
                                                        printf(" Target :%s | Port %d is open\n", so->target_ip_addr[t].target_ip_addr,
                                                        so->target_ip_addr[t].port_number[p].port_num);

                                                        fprintf(file, " Target :%s | Port %d is open\n", so->target_ip_addr[t].target_ip_addr,
                                                        so->target_ip_addr[t].port_number[p].port_num);
                                                }

                                        } 
                                }
                                break;

                        case ACK:
                                for (int t = 0; t < so->target_count; t++) {
                                        for (int p = 0; p < so->target_ip_addr[t].port_counter; p++) {
                                                if (so->target_ip_addr[t].port_number[p].status_unfiltered == true) {
                                                        printf(" Target :%s | Port %d is unfiltered\n", so->target_ip_addr[t].target_ip_addr,
                                                        so->target_ip_addr[t].port_number[p].port_num);

                                                        fprintf(file, " Target :%s | Port %d is unfiltered\n", so->target_ip_addr[t].target_ip_addr,
                                                        so->target_ip_addr[t].port_number[p].port_num);
                                                }

                                        } 
                                }
                                break;

                        case FIN:
                        case XMAS:
                        case NULL_scan:
                                for (int t = 0; t < so->target_count; t++) {
                                        for (int p = 0; p < so->target_ip_addr[t].port_counter; p++) {
                                                if (so->target_ip_addr[t].port_number[p].status_closed == true) {
                                                        printf(" Target :%s | Port %d is closed\n", so->target_ip_addr[t].target_ip_addr,
                                                        so->target_ip_addr[t].port_number[p].port_num);

                                                        fprintf(file, " Target :%s | Port %d is closed\n", so->target_ip_addr[t].target_ip_addr,
                                                        so->target_ip_addr[t].port_number[p].port_num);
                                                }

                                        } 
                                }
                                break;

                        case CUSTOM:
                                for (int t = 0; t < so->target_count; t++) {
                                        for (int p = 0; p < so->target_ip_addr[t].port_counter; p++) {
                                                if (so->target_ip_addr[t].port_number[p].status_unknown == true) {
                                                        printf(" Target :%s | Port %d packet received\n", so->target_ip_addr[t].target_ip_addr,
                                                        so->target_ip_addr[t].port_number[p].port_num);

                                                        fprintf(file, " Target :%s | Port %d packet received\n", so->target_ip_addr[t].target_ip_addr,
                                                        so->target_ip_addr[t].port_number[p].port_num);
                                                }

                                        } 
                                }
                                break;

                        default:
                                printf("Error\n");
                                exit(1);
                                break;

                }
                fprintf(file, "\n");
                fclose(file);
        }
        else if (so->output_file == NULL) {

                //printf(" Scan duration: %lds %.3ld ms\n",so->elapsed_time, so->elapsed_time_ms);
                printf("\n ***   RESULTS   ***\n");

                switch (so->scan_type) {
                        case HALF_OPEN:
                        case CONNECT:
                                for (int t = 0; t < so->target_count; t++) {
                                        for (int p = 0; p < so->target_ip_addr[t].port_counter; p++) {
                                                if (so->target_ip_addr[t].port_number[p].status_open == true) {
                                                        printf(" Target :%s | Port %d is open\n", so->target_ip_addr[t].target_ip_addr,
                                                        so->target_ip_addr[t].port_number[p].port_num);
                                                }

                                        } 
                                }
                                break;

                        case ACK:
                                for (int t = 0; t < so->target_count; t++) {
                                        for (int p = 0; p < so->target_ip_addr[t].port_counter; p++) {
                                                if (so->target_ip_addr[t].port_number[p].status_unfiltered == true) {
                                                        printf(" Target :%s | Port %d is unfiltered\n", so->target_ip_addr[t].target_ip_addr,
                                                        so->target_ip_addr[t].port_number[p].port_num);
                                                }

                                        } 
                                }
                                break;

                        case FIN:
                        case XMAS:
                        case NULL_scan:
                                for (int t = 0; t < so->target_count; t++) {
                                        for (int p = 0; p < so->target_ip_addr[t].port_counter; p++) {
                                                if (so->target_ip_addr[t].port_number[p].status_closed == true) {
                                                        printf(" Target :%s | Port %d is unfiltered\n", so->target_ip_addr[t].target_ip_addr,
                                                        so->target_ip_addr[t].port_number[p].port_num);
                                                }

                                        } 
                                }
                                break;

                        case CUSTOM:
                                for (int t = 0; t < so->target_count; t++) {
                                        for (int p = 0; p < so->target_ip_addr[t].port_counter; p++) {
                                                if (so->target_ip_addr[t].port_number[p].status_unknown == true) {
                                                        printf(" Target :%s | Port %d packet received\n", so->target_ip_addr[t].target_ip_addr,
                                                        so->target_ip_addr[t].port_number[p].port_num);
                                                }

                                        } 
                                }
                                break;

                        default:
                                printf("Error\n");
                                exit(1);
                                break;

                }

        }
       
}

void get_local_ip_address(struct ScanOptions *so) {
        struct ifreq req;
        printf(" * Interface set to: %s\n", so->interface);

        int s = socket(AF_INET, SOCK_DGRAM, 0);

        req.ifr_addr.sa_family = AF_INET;

        // Get IP for given interface
        strncpy(req.ifr_name, so->interface, IFNAMSIZ -1);

        ioctl(s, SIOCGIFADDR, &req);

        close(s);
        so->source_ip = inet_ntoa(((struct sockaddr_in *) &req.ifr_addr)->sin_addr);
}

/*

Details of this function, including comments, can be found at:
www.arl.wustl.edu/~jdd/NDN/NDN/OSPFN/lib/checksum.c

From this page:

"Checksum routine for Internet Protocol family headers (C Version).

Refer to "Computing the Internet Checksum" by R. Braden, D. Borman and
C. Partridge, Computer Communication Review, Vol. 19, No. 2, April 1989,
pp. 86-101, for additional details on computing this checksum."

*/
unsigned short csum(unsigned short *ptr, int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((unsigned char*)&oddbyte)=*(unsigned char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

void free_mem(struct ScanOptions *so) {
        free(so->buffer);
        free(so->target_ip_addr);
        free(so);
}

/*
This function detects if the target is a subnet. If so, the CIDR range
is taken from the inputted string following the '/' character and the 
relevant number of hosts to scan is calcuated.
*/
void resolve_subnet(struct ScanOptions *so) {
      
        char *search_target = so->targets[0];
        
        char *slash_ptr;
        int character = '/';
        char *base_target = so->targets[0];
                                char *new_target;

        slash_ptr = strchr(search_target, character);

        if (slash_ptr) {
                so->subnet = true;
                slash_ptr++;
                int cidr_range = atoi(slash_ptr);
                
                switch (cidr_range) {
                        case 1:
                        case 2:
                        case 3:
                        case 4:
                        case 5:
                        case 6:
                        case 7:
                        case 8:
                        case 9:
                        case 10:
                        case 11:
                        case 12:
                        case 13:
                        case 14:
                        case 15:
                        case 16:
                        case 17:
                        case 18:
                        case 19:
                        case 20:
                        case 21:
                        case 22:
                        case 23:
                                printf("\n CIDR ranges of /23 and less are currently\n" 
                                       " not supported.\n");
                                printf("\n");
                                exit(1);
                                break;

                        case 24:
                                so->target_count = 256;
                                so->targets[0][strlen(so->targets[0]) - 4] = '\0';
                                for(int i = 0;i < 257; i++) {
                                        new_target = NULL;
                                        char i_string[8];
                                        snprintf(i_string, 8, "%d", i);
                                        if((new_target = malloc(strlen(so->targets[0])+strlen(i_string)+1)) != NULL){
                                                new_target[0] = '\0';
                                                strcat(new_target, base_target);
                                                strcat(new_target, i_string);
                                        }
                                        else {
                                                printf(" Could not allocate new target\n");
                                                exit(1);
                                        }
                                        so->targets[i] = new_target;
                                }
                                break;

                        case 25:
                                so->target_count = 128;
                                so->targets[0][strlen(so->targets[0]) - 4] = '\0';
                                for(int i = 0;i < 129; i++) {
                                        new_target = NULL;
                                        char i_string[8];
                                        snprintf(i_string, 8, "%d", i);
                                        if((new_target = malloc(strlen(so->targets[0])+strlen(i_string)+1)) != NULL){
                                                new_target[0] = '\0';
                                                strcat(new_target, base_target);
                                                strcat(new_target, i_string);
                                        }
                                        else {
                                                printf(" Could not allocate new target\n");
                                                exit(1);
                                        }
                                        so->targets[i] = new_target;
                                }
                                break;

                        case 26:
                                so->target_count = 64;
                                so->targets[0][strlen(so->targets[0]) - 4] = '\0';
                                for(int i = 0;i < 65; i++) {
                                        new_target = NULL;
                                        char i_string[8];
                                        snprintf(i_string, 8, "%d", i);
                                        if((new_target = malloc(strlen(so->targets[0])+strlen(i_string)+1)) != NULL){
                                                new_target[0] = '\0';
                                                strcat(new_target, base_target);
                                                strcat(new_target, i_string);
                                        }
                                        else {
                                                printf(" Could not allocate new target\n");
                                                exit(1);
                                        }
                                        so->targets[i] = new_target;
                                }
                                break;

                        case 27:
                                so->target_count = 32;
                                so->targets[0][strlen(so->targets[0]) - 4] = '\0';
                                for(int i = 0;i < 33; i++) {
                                        new_target = NULL;
                                        char i_string[8];
                                        snprintf(i_string, 8, "%d", i);
                                        if((new_target = malloc(strlen(so->targets[0])+strlen(i_string)+1)) != NULL){
                                                new_target[0] = '\0';
                                                strcat(new_target, base_target);
                                                strcat(new_target, i_string);
                                        }
                                        else {
                                                printf(" Could not allocate new target\n");
                                                exit(1);
                                        }
                                        so->targets[i] = new_target;
                                }
                                break;

                        case 28:
                                so->target_count = 16;
                                so->targets[0][strlen(so->targets[0]) - 4] = '\0';
                                for(int i = 0;i < 17; i++) {
                                        new_target = NULL;
                                        char i_string[8];
                                        snprintf(i_string, 8, "%d", i);
                                        if((new_target = malloc(strlen(so->targets[0])+strlen(i_string)+1)) != NULL){
                                                new_target[0] = '\0';
                                                strcat(new_target, base_target);
                                                strcat(new_target, i_string);
                                        }
                                        else {
                                                printf(" Could not allocate new target\n");
                                                exit(1);
                                        }
                                        so->targets[i] = new_target;
                                }
                                break;

                        case 29:
                                so->target_count = 8;
                                so->targets[0][strlen(so->targets[0]) - 4] = '\0';
                                for(int i = 0;i < 9; i++) {
                                        new_target = NULL;
                                        char i_string[8];
                                        snprintf(i_string, 8, "%d", i);
                                        if((new_target = malloc(strlen(so->targets[0])+strlen(i_string)+1)) != NULL){
                                                new_target[0] = '\0';
                                                strcat(new_target, base_target);
                                                strcat(new_target, i_string);
                                        }
                                        else {
                                                printf(" Could not allocate new target\n");
                                                exit(1);
                                        }
                                        so->targets[i] = new_target;
                                }
                                break;

                        case 30:
                                so->target_count = 4;
                                so->targets[0][strlen(so->targets[0]) - 4] = '\0';
                                for(int i = 0;i < 5; i++) {
                                        new_target = NULL;
                                        char i_string[8];
                                        snprintf(i_string, 8, "%d", i);
                                        if((new_target = malloc(strlen(so->targets[0])+strlen(i_string)+1)) != NULL){
                                                new_target[0] = '\0';
                                                strcat(new_target, base_target);
                                                strcat(new_target, i_string);
                                        }
                                        else {
                                                printf(" Could not allocate new target\n");
                                                exit(1);
                                        }
                                        so->targets[i] = new_target;
                                }
                                break;

                        case 31:
                                so->target_count = 2;
                                so->targets[0][strlen(so->targets[0]) - 4] = '\0';
                                for(int i = 0;i < 3; i++) {
                                        new_target = NULL;
                                        char i_string[8];
                                        snprintf(i_string, 8, "%d", i);
                                        if((new_target = malloc(strlen(so->targets[0])+strlen(i_string)+1)) != NULL){
                                                new_target[0] = '\0';
                                                strcat(new_target, base_target);
                                                strcat(new_target, i_string);
                                        }
                                        else {
                                                printf(" Could not allocate new target\n");
                                                exit(1);
                                        }
                                        so->targets[i] = new_target;
                                }
                                break;

                        case 32:
                                // For /32 the target IP given is the one
                                // used as the target.
                                so->target_count = 1;
                                so->targets[0][strlen(so->targets[0]) - 3] = '\0';
                                break;

                
                        default:
                                break;
                }
        }       
}

void timeout(struct ScanOptions *so) {
        // Timeout defaults (check first if user specified timout
        // options have been applied)
        if (so->timeout == 0) {
                if (so->scan_type == CONNECT) {
                        so->timeout = 100000;
                        // Micro delay is as low as possible without triggering a
                        // pthread detach error
                        so->micro_delay = 2550;
                        so->connect_port_delay = 5000;
                } 
                else {
                        so->timeout = 100000;
                        so->micro_delay = 1000;
        
                        // When the non-connect scan loop runs, it can
                        // out-pace the socket being created. For this
                        // reason a delay is introduced to ensure a high 
                        // percentage of packets are actually being sent.
                        // Aiming for 99% consistency, +500us is repeatedly  
                        // added for more than 5 targets. 

                        //1 hosts: *500 stops at ~ 65.9/66k packets
                        //2 hosts: *750 stops at ~ 64.9/65k packets
                        //3 hosts: *1250 stops at ~ 64.7/65k packets
                        //4 hosts: *1750 stops at ~ 64.5/65k packets
                        //5 hosts: *2500 stops at ~ 64.9/65k packets
                        //6 hosts: *3000 stops at ~ 64.6/65k packets
                        //7 hosts: *3500 stops at ~ 64.0/65k packets
                        //10 hosts: *5000 stops at ~ 64.8/65k packets  

                        switch (so->target_count) {
                                case 1:
                                        so->port_delay = 500;
                                        break;
                                case 2:
                                        so->port_delay = 750;
                                        break;
                                case 3:
                                        so->port_delay = 1250;
                                        break;
                                case 4:
                                        so->port_delay = 1750;
                                        break;
                                case 5:
                                        so->port_delay = 2500;
                                default:
                                        so->port_delay = 2500;
                                        for (int i = 5;i < so->target_count; i++) {
                                                so->port_delay += 500;
                                        }
                        }
                }
        }
}

bool handle_inputs(struct ScanOptions *so) {
        if (so->targets[0] == NULL) {
                printf("\n Target not detected.\n\n");
                printf(" For help on how to use this program use:\n"
                       "        -h for the short help menu\n"
                       "        -H for the full help menu\n");
                return false;
        }
        
        if (so->port == 0 && (so->port_min == 0 && so->port_max == 0)) {
                printf("\n Port not detected.\n\n");
                printf(" For help on how to use this program use:\n"
                       "        -h for the short help menu\n"
                       "        -H for the full help menu\n");
                return false;
        }
        if (so->interface == NULL) {
                printf("\n Interface not detected.\n\n");
                printf(" For help on how to use this program use:\n"
                       "        -h for the short help menu\n"
                       "        -H for the full help menu\n");
                return false;
        }

        return true;
}

void init(struct ScanOptions *so) {
        so->targets[0] = NULL;
        so->target_count = 0;
        so->port = 0;
        so->scan_type = HALF_OPEN;
        so->scan_finished = false;
        so->targets_scanned = 0;
        so->current_target = 0;
        so->no_of_ports = 0;
        so->connect_port_delay = 0;
        so->port_delay = 0;
        so->timeout = 0;
        so->subnet = false;
        so->verbose = false;
        so->time_to_live = 0;
        so->output_file = NULL;
        so->source_ip = NULL;


        // True randomness is not important for this application.
        srand((unsigned int)time(NULL));
}

int main(int argc, char **argv) {
        struct ScanOptions *so = malloc(sizeof(struct ScanOptions));

        printf("\n\n *******************************************************\n");
        printf(" *                    Bolt Scanner                     *\n");
        printf(" *                       v1.0.0                        *\n");
        printf(" *                                                     *\n");
        printf(" * Bolt Scanner is to be used ONLY for legal purposes. *\n");
        printf(" *                                                     *\n");
        printf(" *******************************************************\n");

        init(so);
        apply_flags(argc, argv, so);

        if (handle_inputs(so) != true) {
                printf("\n");
                exit(1);
        }

        resolve_subnet(so);
        timeout(so);
        
        // Results struct size init
        so->no_of_ports = (so->port_max - so->port_min) + 1;
        so->target_ip_addr = malloc(sizeof(struct Results) + sizeof(struct Port) + (sizeof(so->target_count * so->no_of_ports)));

        // Start the elapsed-time timer
        gettimeofday(&so->timer_start, NULL);
        set_packet_details(so);


        // Wait for all targets to be scanned, then start timeout
        while(1) {
                if (so->targets_scanned == so->target_count) {
                        // Waiting for connections back before ending the scan.
                        usleep(so->timeout);
                        so->scan_finished = true;

                        // Ok to join the listener thread as the loop inside
                        // has now finished. As this adds delay to the program,
                        // the thread is simply canceled for now.
                        //pthread_join(so->listener_thread,NULL);
                        pthread_cancel(so->listener_thread);


                        // Stop the timer - the elapsed time will be printed 
                        // in the print_output function.
                        gettimeofday(&so->timer_stop, NULL);
                        so->elapsed_time = (so->timer_stop.tv_sec - so->timer_start.tv_sec) * 1;
                        so->elapsed_time_ms = (so->timer_stop.tv_usec - so->timer_start.tv_usec) / 1000;

                        printf(" ...scan Complete.\n");
                        
                        print_output(so);
                        free_mem(so);
                        printf ("\n");
                        return 0;
                        
                }
        }
}
