/*
 * Copyright (C) 2015 Nils Kuhnhenn
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <math.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>

#include "fork_connector.c"

#define PROCESS_MATCHER_COMM 0
#define PROCESS_MATCHER_PATH 1

typedef struct CONFIG_ARGUMENT {
    char* NAME;
    char* VALUE;
} CONFIG_ARGUMENT;

typedef struct PROCESS_MATCHER {
    int TYPE;
    char *MATCHER;
    struct PROCESS_MATCHER* NEXT;
} PROCESS_MATCHER;

typedef struct CPU_ENTRY {
    int CPU;
    struct CPU_ENTRY* NEXT;
} CPU_ENTRY;

typedef struct PROCESS_CONFIG {
    char *NAME;
    PROCESS_MATCHER* MATCH;
    CPU_ENTRY* CPU;
    int PRIO;
} PROCESS_CONFIG;

typedef struct CONFIG_ENTRY {
    struct PROCESS_CONFIG* CONFIG;
    struct CONFIG_ENTRY* NEXT;
} CONFIG_ENTRY;

CONFIG_ENTRY* first_config_entry = NULL; 

static int numbers_only(const char *s){
    while (*s) {
        if (isdigit(*s++) == 0) return 0;
    }

    return 1;
}

static void configure_process(pid_t pid, CPU_ENTRY* cpus, int priority){
    cpu_set_t cpu_set;
    CPU_ENTRY* current_entry;

    CPU_ZERO(&cpu_set);
    
    current_entry = cpus;

    while (current_entry != NULL) {
        CPU_SET(current_entry->CPU, &cpu_set);
        current_entry = cpus->NEXT;
    }
      
    if (cpus != NULL) {
        if(sched_setaffinity(pid, sizeof(cpu_set), &cpu_set)){
            printf("Failed to set CPU affinity!\n");
        }
    }

    if (setpriority(PRIO_PROCESS, pid, priority)) {
        printf("Failed to set priority!\n");
    }
}

static void add_config_entry(PROCESS_CONFIG* config){
    CONFIG_ENTRY* new_entry = (CONFIG_ENTRY*) malloc(sizeof(CONFIG_ENTRY));
    new_entry->CONFIG = config;
    new_entry->NEXT = NULL;
    
    CONFIG_ENTRY** current = &first_config_entry; 

    while(*current != NULL){
        current = &(*current)->NEXT;
    }

    *current = new_entry;
}

static char* proc_file_name(pid_t pid, const char* sub){
    char* fname = (char*) malloc(256); 

    sprintf(fname, "/proc/%i/%s", pid, sub);

    return fname;
}

static int read_file_string(char* fname, char *buff, int len){
    int fd, numread;

    fd = open(fname, O_RDONLY);

    if(fd <= 0) return 1;

    numread = read(fd, buff, len - 1);
    close(fd);
  
    if(numread <= 0) return 1;

    buff[numread] = 0;

    return 0;
}

static int read_comm_of_pid(pid_t pid, char *buff, int len){
    int ret;
    char *fname;
    int i;

    fname = proc_file_name(pid, "comm");
    ret = read_file_string(fname, buff, len);
    
    i = 0;
    while(i < len){
        if(buff[i] == '\n' || buff[i] == '\r') buff[i] = '\0';
        i++;
    }

    free(fname);
    return ret;
}

static int read_exe_of_pid(pid_t pid, char *buff, int len){
    int res;
    char *fname;
    
    fname = proc_file_name(pid, "exe");

    if((res = readlink(fname, buff, len - 1)) < 0){
        return res;
    }

    free(fname);

    buff[res] = 0;

    return 0;
}

static int check_matching(PROCESS_MATCHER* match, char* comm, char* path){
    if(match->TYPE == PROCESS_MATCHER_PATH){
        return !strcmp(match->MATCHER, path);
    }
    if(match->TYPE == PROCESS_MATCHER_COMM){
        return !strcmp(match->MATCHER, comm);
    }
    return 0;
}

static PROCESS_CONFIG* match_process_config(char* comm, char* path){
    CONFIG_ENTRY* current_config = first_config_entry;
    PROCESS_MATCHER* current_matcher = NULL;

    int matches = 0;

    while(current_config != NULL){
        matches = 1;
        
        current_matcher = current_config->CONFIG->MATCH;
        
        while(current_matcher != NULL){
            matches = check_matching(current_matcher, comm, path); 
            if(!matches) break;
            current_matcher = current_matcher->NEXT;
        }

        if(matches){
            return current_config->CONFIG;
        }

        current_config = current_config->NEXT;
    }

    return NULL;
}

static void handle_running_process(pid_t pid){
    char* name;

    char comm[16];
    char path[1024];

    PROCESS_CONFIG* config;

    if(read_comm_of_pid(pid, comm, 16)) return;
    if(read_exe_of_pid(pid, path, 1024)) return;

    config = match_process_config(comm, path);
    
    if(config == NULL) return;

    configure_process(pid, config->CPU, config->PRIO);

    name = config->NAME;

    if(name == NULL) name = comm;

    printf("Matched \"%s\" with PID %i\n", name, pid);
}

static void handle_stopped_process(pid_t pid){
    char buff[256];

    if(read_comm_of_pid(pid, buff, 256)) return;
}

static void handle_msg(struct cn_msg *cn_hdr){
  struct proc_event *ev = (struct proc_event *) cn_hdr->data;

  pid_t pid = ev->event_data.exec.process_pid;

  if(ev->what == PROC_EVENT_COMM ||
     ev->what == PROC_EVENT_EXEC) {
    handle_running_process(pid);
  }

  if(ev->what == PROC_EVENT_EXIT){
    handle_stopped_process(pid);
  }
}

static void read_proc_dir(){
    DIR* dirp;
    struct dirent* dp;

    dirp = opendir("/proc/");

    while ((dp = readdir(dirp)) != NULL){
        if (numbers_only(dp->d_name)) {
            handle_running_process((pid_t) atoi(dp->d_name));
        }
    }
        
    closedir(dirp);
}

static int parse_argument(char* line, int* line_pointer, CONFIG_ARGUMENT* arg){
    int name_start, 
        name_end,
        name_length,
        value_start,
        value_end,
        value_length;

    int linep = *line_pointer;
    char c;

    char *name, *value;

    // Eliminate spaces
    
    c = line[linep];

    while(1) {
        if(c != ' '){
            if(c == '\0'){
                *line_pointer = -1;
                return 0;
            }
            break;
        }

        c = line[++linep];
    }

    name_start = linep;

    // Find '='
    
    while(1){
        c = line[++linep];

        if(c == '\0') return linep;
        if(c == '=') break;
    }
    
    name_end = linep;

    
    c = line[++linep];
    if(c == '\0') return linep;

    if(c == '"'){
        // If the next character is a '"', walk until the next '"'
        value_start = linep + 1;
        
        while(1){
            c = line[++linep];

            if(c == '\0') return linep;
            if(c == '"') break;
        }
    
        value_end = linep;
        linep++;
    } else {
        // Otherwise just walk to the next space or end of string

        value_start = linep;
        
        while(1){
            c = line[++linep];
            if(c == '\r' || c== '\n' || c == '\0' || c == ' ') break;
        }

        value_end = linep;
    }

    name_length = name_end-name_start;
    name = (char*) malloc(name_length+1);
    memcpy(name, line+name_start, name_length);
    name[name_length] = 0;
    
    value_length = value_end-value_start;
    value = (char*) malloc(value_length+1);
    memcpy(value, line+value_start, value_length);
    value[value_length] = 0;
    
    arg->NAME = name;
    arg->VALUE = value;

    *line_pointer = linep;

    return 0;
}

static void add_matcher(PROCESS_CONFIG* conf, int type, char* value){
    PROCESS_MATCHER* match = (PROCESS_MATCHER*) malloc(sizeof(PROCESS_MATCHER));

    match->TYPE = type;
    match->MATCHER = value;
    match->NEXT = NULL;

    PROCESS_MATCHER **target;

    target = &conf->MATCH;
    while(*target != NULL){
       target = &(*target)->NEXT;
    }
    
    *target = match;
}

static void add_cpu(PROCESS_CONFIG* conf, int cpu){
    CPU_ENTRY* entry = (CPU_ENTRY*) malloc(sizeof(CPU_ENTRY));

    entry->CPU = cpu;

    CPU_ENTRY **target;

    target = &conf->CPU;
    while(*target != NULL){
       target = &(*target)->NEXT;
    }
    
    *target = entry;
}

static int modify_from_argument(PROCESS_CONFIG* conf, CONFIG_ARGUMENT* arg){
    char *value = (char*) malloc(strlen(arg->VALUE) + 1);

    memcpy(value, arg->VALUE, strlen(arg->VALUE) + 1);

    if(!strcmp(arg->NAME, "NAME")){
        conf->NAME = value;
    } else if(!strcmp(arg->NAME, "NICE")){
        conf->PRIO = atoi(value);
        free(value);
    } else if(!strcmp(arg->NAME, "COMM")){
        add_matcher(conf, PROCESS_MATCHER_COMM, value);
    } else if(!strcmp(arg->NAME, "PATH")){
        add_matcher(conf, PROCESS_MATCHER_PATH, value);
    } else if(!strcmp(arg->NAME, "CPU")){
        add_cpu(conf, atoi(value));
        free(value);
    } else {
        return 1;
        free(value);
    }

    return 0;

}

static int parse_config_line(char* line){
    int len, result;
    int line_pointer = 0;
    int old_line_pointer = 0;
    int had_any_rule = 0;

    len = strlen(line);

    if(len == 0 ||
       line[0] == '#') return 0;

    CONFIG_ARGUMENT* arg = (CONFIG_ARGUMENT*) malloc(sizeof(CONFIG_ARGUMENT));
    PROCESS_CONFIG* conf = (PROCESS_CONFIG*) malloc(sizeof(PROCESS_CONFIG));

    conf->CPU = NULL;
    conf->MATCH = NULL;
    conf->NAME = NULL;
    
    while(line_pointer != -1 && line_pointer < len - 1){
        old_line_pointer = line_pointer;
        result = parse_argument(line, &line_pointer, arg);

        if(result){
            free(arg);
            free(conf);
            return result;
        }
        
        if(line_pointer != -1){
            had_any_rule = 1;

            if(modify_from_argument(conf, arg)){
                free(arg->VALUE);
                free(arg->NAME);
                free(arg);
                free(conf);
                return old_line_pointer;
            }
        }
        
        free(arg->VALUE);
        free(arg->NAME);

    }

    free(arg);

    if(had_any_rule){
        add_config_entry(conf);
    }

    return 0;
}

static int read_config(const char* path){
    FILE * fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    int line_num = 0;
    int result;

    fp = fopen(path, "r");

    if (fp == NULL){
        return 1;
    }

    printf("Reading config: %s\n", path);

    while ((read = getline(&line, &len, fp)) != -1) {
        line_num++; 
        if((result = parse_config_line(line))){
            printf("Parse error on line %i in file %s: %s",
                        line_num, path, line);
        }
    }

    fclose(fp);

    if (line) {
        free(line);
    }

    return 0;
}

int main(){
	if (getuid() != 0) {
		printf("Run this program as root\n");
		return 1;
	}

    if(read_config("./nicedaemon.conf") && read_config("/etc/nicedaemon.conf")){
        printf("Could not read any config file! (Looked for ./nicedaemon.conf and /etc/nicedaemon.conf)\n"); 
        return 1;
    }
    
    read_proc_dir();
    
    return fork_connector_loop(handle_msg);
}

