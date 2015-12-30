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

#define MAXS 1024

void parse_ip();
void parse_version_ip(char *filename, char *addr);
void ctrlc_handler();
void ctrlz_handler();
void ctrlbslash_handler();
void safe_printf(const char *format, ...);

int fo = -1;
pid_t  pid;
int status;

char *nmapoutname = "nmapout.txt";
char ipfilename[100];
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
    int mark = 0;
    strcpy(ipfilename, "ip.txt");
    strcpy(port, "23");
    strcpy(irand, "1000");
    
    if (argc == 1) {
        isdiscover = 1;
        isknock = 1;
    }
    
    for (int i=1; i<argc; i++) {
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
            isdiscover = 0;
            isknock = 0;
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
            pid = fork();
            if (pid == 0) {
                fo = open(nmapoutname, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IRGRP | S_IWGRP | S_IWUSR);
                dup2(fo, 1);
                close(fo);
                char *execArgs[] = {"nmap", "-n", "-Pn", "-sV", "-p", port, token, NULL};
                
                int versionSpawn = execvp(execArgs[0], execArgs);
                
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
            if (!strcmp(port, "22")) {
                execArgs[0] = "ssh";
            } else if (!strcmp(port, "21")) {
                execArgs[0] = "ftp";
            } else {
                execArgs[0] = "telnet";
            }
            execArgs[1] = token;
            pid = fork();
            if (pid == 0) {
                int knockSpawn = execvp(execArgs[0], execArgs);
            } else {
                waitpid(-1, &status, 0);
            }
        }
    }
    
    return 0;
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
    //safe_printf("\nCTRL-C HIT!!\n");
    exit(0);
}

void ctrlz_handler() {
    safe_printf("\n");
    kill(pid, SIGINT);
}

void parse_version_ip(char *filename, char *addr) {
    waitpid(-1, &status, 0);
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