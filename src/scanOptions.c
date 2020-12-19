#include "main.h"

void print_help() {
        printf(
        " Syntax ./a.out -t [target] -p [port] -i [interface]                              \n"
        "                                                                                  \n"
        " Options:                                                                         \n"
        "       -t  target                                                                 \n"
        "       -T  target (multiple)                                                      \n"
        "               \"-T tar=x.x.x.x,tar=x.x.x.x\"                                     \n"
        "       -p  port (single)                                                          \n"
        "       -P  port (range min/max)                                                   \n"
        "               \"-P min=x,max=x\"                                                 \n"
        "       -i  interface                                                              \n"
        "                                                                                  \n"
        "       -sC  TCP connect scan                                                      \n"
        "                                                                                  \n"
        " Examples                                                                         \n"
        " ./a.out -t <target IP> -p 53 -i eth0                                             \n"
        " ./a.out --target <target IP> -P min=10,max=100 -i eth0 --sA -o scan1.txt         \n"
        " ./a.out -T tar=<target IP>,tar=<target IP> -P min=50,max=100 -i eth0             \n"
        "                                                                                  \n"
        " Tips                                                                             \n"
        " Getting \"Too many open files\" error?                                           \n"
        " Try increasing your ulimit: [\"ulimit -n\" to see maximum open file descriptors] \n"
        "                                                                                  \n"
        " When specifying a maximum port range make sure to add 1 as the final port is     \n"
        " not included.                                                                  \n\n"
        );
        exit(0);
}

void print_extended_help() {
        printf(
        " Syntax ./a.out -t [target] -p [port] -i [interface]                              \n"
        "                                                                                  \n"
        " Options:                                                                         \n"
        "        target (single)                                                           \n"
        "                -t                                                                \n"
        "                --target                                                          \n"
        "                                                                                  \n"
        "        target (multiple)                                                         \n"
        "                -T                                                                \n"
        "                --target-list                                                     \n"
        "             \" -T tar=x.x.x.x,tar=x.x.x.x,tar=x.x.x.x \"                         \n"
        "                                                                                  \n"
        "        target (subnet)                                                           \n"
        "                 -t x.x.x.x/24 (0-255)                                            \n"
        "                 (*currently only ranges 24-32 are supported)                     \n"
        "                                                                                  \n"
        "        port (single)                                                             \n"
        "                -p                                                                \n"
        "                --port                                                            \n"
        "                                                                                  \n"
        "        port range                                                                \n"
        "                -P                                                                \n"
        "                --port-range                                                      \n"
        "              \"-P min=x,max=x\"                                                  \n"
        "                                                                                  \n"
        "        interface                                                                 \n"
        "                -i                                                                \n"
        "                --interface                                                       \n"
        "                                                                                  \n"
        "        scans                                                                     \n"
        "                --sS  half-open scan (default)                                    \n"
        "                --sC  TCP connect scan                                            \n"
        "                --sA  ACK scan                                                    \n"
        "                --sF  FIN scan                                                    \n"
        "                --sX  XMAS scan                                                   \n"
        "                --sN  NULL scan                                                   \n"
        "                                                                                  \n"
        "                A scan with custom flags can be set via:                          \n"
        "                --flags [ceuaprsf]                                                \n"
        "                                                                                  \n"
        "        packet timeout (ms)                                                       \n"
        "                -m                                                                 \n"
        "                --max-timeout                                                     \n"
        "                                                                                  \n"
        "        Packet time to live (ms) (Defaults: Linux = 64 (default)| Windows = 128)  \n"
//      "                --t                                                               \n"
        "                --time-to-live                                                    \n"
        "                                                                                  \n"
        "        Output                                                                    \n"
        "                -o                                                                \n"
        "                --output                                                          \n"
        "                                                                                  \n"
        "        Verbosity                                                                 \n"
        "                -v                                                                \n"
        "                --verbose                                                         \n"
        "                                                                                  \n"
        " Examples                                                                         \n"
        " ./a.out -t <target IP> -p 53 -i eth0                                             \n"
        " ./a.out --target <target IP> -P min=10,max=100 -i eth0 --sA -o scan1.txt         \n"
        " ./a.out -T tar=<target IP>,tar=<target IP> -P min=50,max=100 -i eth0             \n"
        "                                                                                  \n"
        " Tips                                                                             \n"
        " Getting \"Too many open files\" error?                                           \n"
        " Try increasing your ulimit: [\"ulimit -n\" to see maximum open file descriptors] \n"
        "                                                                                  \n"
        " When specifying a maximum port range make sure to add 1 as the final port is     \n"
        " not included.                                                                  \n\n"
        );
        exit(0);
}

void apply_flags(int argc, char **argv, struct ScanOptions *so) {

        int opt;
        int option_index = 0;
        char *subopts, *value;

        // Port input options
        int port, port_min, port_max;
        int max_timeout, ttl;

        enum {
                PORT_MIN,
                PORT_MAX,
        };

        char *port_opts[] = {
                [PORT_MIN] = "min", 
                [PORT_MAX] = "max",
        };

        // Target input options
        enum {
                FROM,
                TO,
                TARGETS,
        };

        char *target_opts[] = {
                [FROM]    = "from",
                [TO]      = "to",
                [TARGETS] = "tar",
        };

        static struct option long_options[] = {
        {"verbose",     no_argument,       0, 'v'},
        {"sS",          no_argument,       0,  1},
        {"sC",          no_argument,       0,  2 },
        {"sA",          no_argument,       0,  3 },
        {"sF",          no_argument,       0,  4 },
        {"sX",          no_argument,       0,  5 },
        {"sN",          no_argument,       0,  6 },
        {"flags",       required_argument, 0, 'c'},
        {"target",      required_argument, 0, 't'},
        {"target-list", required_argument, 0, 'T'},
        {"port",        required_argument, 0, 'p'},
        {"port-range",  required_argument, 0, 'P'},
        {"interface",   required_argument, 0, 'i'},
        {"max-timeout", required_argument, 0, 'm'},
        {"time-to-live",required_argument, 0, 'l'},
        {"ttl",         required_argument, 0, 'n'},
        {"help",        no_argument,       0, 'h'},
        {"help-full",   no_argument,       0, 'H'},
        {"output",      required_argument, 0, 'o'},
        {0,             0,                 0,  0 }
        };

        while ((opt = getopt_long(argc, argv, "vc:t:T:p:P:i:m:l:n:hHo:", long_options, &option_index)) != -1) {
                switch (opt) {
                        case 'v':
                                so->verbose = true;
                                break;
                        case 1:
                                so->scan_type = HALF_OPEN;
                                break;
                        case 2:
                                so->scan_type = CONNECT;
                                break;
                        case 3:
                                so->scan_type = ACK;
                                break;
                        case 4:
                                so->scan_type = FIN;
                                break;
                        case 5:
                                so->scan_type = XMAS;
                                break;
                        case 6:
                                so->scan_type = NULL_scan;
                                break;
                        case 'c':
                                so->scan_type = CUSTOM;
                                so->flags = optarg;
                                break;

                        case 't': 
                                so->targets[0] = optarg;
                                so->target_count = 1;
                                break;
                        
                        case 'T':
                                subopts = optarg;
                                int i = 0;
                                so->target_count = 0;
                                while(*subopts != '\0') {
                                        switch(getsubopt (&subopts, target_opts, &value)) {
                                                case TARGETS:
                                                        so->targets[i] = value;
                                                        i++;
                                                        so->target_count++;
                                                        break;

                                                default:
                                                        exit(EXIT_FAILURE);
                                        }
                                }
                        case 'p':                        
                                port = atoi(optarg);
                                //if (isdigit(port)) {
                                so->port = port;
                                //}
                                //else {
                                //        printf(" \n Please enter a valid integer for the port.\n");
                                //        exit(1);
                                //}
                                break;

                        case 'P':
                                subopts = optarg;
                                while(*subopts != '\0')
                                        switch (getsubopt (&subopts, port_opts, &value)) {
                                                case PORT_MIN:
                                                        port_min = atoi(value);
                                                        //if (isdigit(port_min)) {
                                                        so->port_min = port_min;
                                                        //}
                                                        //else {
                                                        //        printf(" \n Please enter valid integers when setting the port.\n\n");
                                                        //        exit(1);
                                                        //}
                                                        break;
                                                case PORT_MAX:
                                                        port_max = atoi(value);
                                                        //if (isdigit(port_max)) {
                                                        so->port_max = port_max;
                                                        //}
                                                        //else {
                                                        //       printf(" \n Please enter valid integer when setting the ports.\n\n");
                                                        //       exit(1);
                                                        //}
                                                        break;
                                                default: 
                                                        exit(EXIT_FAILURE);
                                        }
                                break;
                        
                        case 'i':
                                so->interface = optarg;
                                break;

                        case 'm':
                                max_timeout = atoi(optarg) * 1000;
                                so->timeout = max_timeout;
                                break;

                        case 'l':
                                so->time_to_live = atoi(optarg);
                                break;

                        case 'n':
                                so->time_to_live = atoi(optarg);
                                break;

                        case 'h':
                                print_help();
                                break;

                        case 'H':
                                print_extended_help();
                                break;

                        case 'o':
                                so->output_file = optarg;
                                break;

                        case '?':
                                if (optopt == 'c' || optopt == 't' || 
                                optopt == 'T' || optopt == 'p' || 
                                optopt == 'P' || optopt == 'i' ||
                                optopt == 'm' || optopt == 'l' ||
                                optopt == 'n' || optopt == 'o')
                                        fprintf(stderr, "Option -%c requires an argument. \n", optopt);
                                else if (isprint (optopt))
                                        fprintf(stderr, "Unknown option '-%c'.\n", optopt);
                                else
                                        fprintf(stderr, "Unknown character '\\x%x'.\n", optopt);

                        default: 
                        exit(1);
                }
        }
}
