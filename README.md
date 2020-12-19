# Bolt Scanner v1.0.0
 A rapid port scanner.   
 
 Scan types supported:
 
 * SYN HALF-OPEN
 
 * TCP CONNECT
 
 * ACK
 
 * FIN
 
 * XMAS
 
 * NULL
 
 * CUSTOM

## Development platforms
Arch Linux - 4.20.6 <br>
gcc version 8.2.1

Ubunutu 18.10 - 4.18.0 (Virtual machine) <br>
gcc version 8.2.0

## Install instructions
To compile

    cd /src
    gcc main.a -lpthread -o boltscanner.c

To run:

    ./boltscanner.c

## Usage
    # ./boltscanner.c -t [target] -p [port] -i [interface]                              
                                                                                          
         Options:                                                                         
                target (single)                                                           
                        -t                                                                
                        --target                                                          
                                                                                          
                target (multiple)                                                         
                        -T                                                                
                        --target-list                                                     
                        example: "-T tar=x.x.x.x,tar=x.x.x.x,tar=x.x.x.x"                      
                                                                                          
                target (subnet)                                                           
                         -t x.x.x.x/24 (0-255)                                            
                         (*currently only ranges 24-32 are supported)                     
                                                                                          
                port (single)                                                             
                        -p                                                                
                        --port                                                            
                                                                                          
                port range                                                                
                        -P                                                                
                        --port-range                                                      
                        example: "-P min=x,max=x"                                                  
                                                                                          
                interface                                                                 
                        -i                                                                
                        --interface                                                       
                                                                                          
                scans                                                                     
                        --sS  half-open scan (default)                                    
                        --sC  TCP connect scan                                            
                        --sA  ACK scan                                                    
                        --sF  FIN scan                                                    
                        --sX  XMAS scan                                                   
                        --sN  NULL scan                                                   
                                                                                          
                        A scan with custom flags can be set via:                          
                        --flags [ceuaprsf]                                                
                                                                                          
                timeout                                                                   
                        -m                                                                
                        --max-timeout                                                     
                                                                                          
                Packet time to live (Defaults: Linux = 64 (default)| Windows = 128)       
                        --time-to-live                                                    
                                                                                          
                Output                                                                    
                        -o                                                                
                        --output                                                          
                                                                                          
                Verbosity                                                                 
                        -v                                                                
                        --verbose                                                         
                                                                                          
         Examples                                                                         
         # ./boltscanner.c -t <target IP> -p 53 -i eth0                                             
         # ./boltscanner.c --target <target IP> -P min=10,max=100 -i eth0 --sA -o scan1.txt         
         # ./boltscanner.c -T tar=<target IP>,tar=<target IP> -P min=50,max=100 -i eth0             
