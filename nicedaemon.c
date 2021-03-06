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

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/stat.h>

#include <unistd.h>
#include <sched.h>

#include "fork_connector.c"

#define PROCESS_MATCHER_COMM 0
#define PROCESS_MATCHER_PATH 1

typedef struct _CONFIG_ARGUMENT {
  char *name;
  char *value;
} CONFIG_ARGUMENT;

typedef struct _PROCESS_MATCHER {
  int type;
  char *value;
  struct _PROCESS_MATCHER *next;
} PROCESS_MATCHER;

typedef struct _CPU_ENTRY {
  int cpu;
  struct _CPU_ENTRY *next;
} CPU_ENTRY;

typedef struct _PROCESS_CONFIG {
  int id;
  char *name;
  PROCESS_MATCHER *match;
  CPU_ENTRY *cpu;
  char *cgroup;
  int prio;
} PROCESS_CONFIG;

typedef struct _CONFIG_ENTRY {
  struct _PROCESS_CONFIG *config;
  struct _CONFIG_ENTRY *next;
} CONFIG_ENTRY;

CONFIG_ENTRY *first_config_entry = NULL;

static int numbers_only(const char *s) {
  while (*s) {
    if (isdigit(*s++) == 0)
      return 0;
  }

  return 1;
}

static DIR *open_pid_dir(const char *dir) { return opendir(dir); }

static pid_t read_pid(DIR *dirp) {
  struct dirent *dp;

  while ((dp = readdir(dirp)) != NULL) {
    if (numbers_only(dp->d_name)) {
      return (pid_t)atoi(dp->d_name);
    }
  }

  closedir(dirp);

  return -1;
}

static void add_to_cgroup(pid_t pid, char *cgroup) {
  char tasks[128];
  char pid_str[16];

  sprintf(tasks, "%s/tasks", cgroup);
  sprintf(pid_str, "%i\n", pid);

  int fp = open(tasks, O_WRONLY | O_APPEND);

  if (!fp) {
    return;
  }

  write(fp, pid_str, strlen(pid_str));

  close(fp);
}

static void configure_pid(pid_t pid, int priority) {
  if (setpriority(PRIO_PROCESS, pid, priority)) {
    printf("Failed to set priority!\n");
  }
}

static void configure_process(pid_t pid, char *cgroup, int priority) {
  char task_path[256];

  DIR *dirp;

  pid_t thread_pid;

  sprintf(task_path, "/proc/%i/task/", pid);

  configure_pid(pid, priority);

  if (cgroup != NULL) {
    add_to_cgroup(pid, cgroup);
  }

  dirp = open_pid_dir(task_path);

  if (!dirp)
    return;

  while ((thread_pid = read_pid(dirp)) != -1) {
    configure_pid(thread_pid, priority);
  }
}

static void add_config_entry(PROCESS_CONFIG *config) {
  CONFIG_ENTRY *new_entry = (CONFIG_ENTRY *)malloc(sizeof(CONFIG_ENTRY));
  new_entry->config = config;
  new_entry->next = NULL;

  CONFIG_ENTRY **current = &first_config_entry;

  int id = 0;

  while (*current != NULL) {
    current = &(*current)->next;
    id++;
  }

  new_entry->config->id = id;

  *current = new_entry;
}

static int read_file_string(char *fname, char *buff, int len) {
  int fd, numread;

  fd = open(fname, O_RDONLY);

  if (fd <= 0)
    return 1;

  numread = read(fd, buff, len - 1);
  close(fd);

  if (numread <= 0)
    return 1;

  buff[numread] = 0;

  return 0;
}

static int read_comm_of_pid(pid_t pid, char *buff, int len) {
  int ret;
  int i;
  char fname[256];

  sprintf(fname, "/proc/%i/comm", pid);

  ret = read_file_string(fname, buff, len);

  i = 0;
  while (i < len) {
    if (buff[i] == '\n' || buff[i] == '\r')
      buff[i] = '\0';
    i++;
  }

  return ret;
}

static int read_exe_of_pid(pid_t pid, char *buff, int len) {
  int res;
  char fname[256];

  sprintf(fname, "/proc/%i/exe", pid);

  if ((res = readlink(fname, buff, len - 1)) < 0) {
    return res;
  }

  buff[res] = 0;

  return 0;
}

static int check_matching(PROCESS_MATCHER *match, char *comm, char *path) {
  if (match->type == PROCESS_MATCHER_PATH) {
    return !strcmp(match->value, path);
  }
  if (match->type == PROCESS_MATCHER_COMM) {
    return !strcmp(match->value, comm);
  }
  return 0;
}

static PROCESS_CONFIG *match_process_config(char *comm, char *path) {
  CONFIG_ENTRY *current_config = first_config_entry;
  PROCESS_MATCHER *current_matcher = NULL;

  int matches = 0;

  while (current_config != NULL) {
    matches = 1;

    current_matcher = current_config->config->match;

    while (current_matcher != NULL) {
      matches = check_matching(current_matcher, comm, path);
      if (!matches)
        break;
      current_matcher = current_matcher->next;
    }

    if (matches) {
      return current_config->config;
    }

    current_config = current_config->next;
  }

  return NULL;
}

static void handle_running_process(pid_t pid) {
  char *name;

  char comm[16];
  char path[1024];

  PROCESS_CONFIG *config;

  if (read_comm_of_pid(pid, comm, 16))
    return;
  if (read_exe_of_pid(pid, path, 1024))
    return;

  config = match_process_config(comm, path);

  if (config == NULL)
    return;

  configure_process(pid, config->cgroup, config->prio);

  name = config->name;

  if (name == NULL)
    name = comm;

  printf("Matched \"%s\" with PID %i\n", name, pid);
}

static void handle_msg(struct cn_msg *cn_hdr) {
  struct proc_event *ev = (struct proc_event *)cn_hdr->data;

  pid_t pid = ev->event_data.exec.process_pid;

  if (ev->what == PROC_EVENT_COMM || ev->what == PROC_EVENT_EXEC) {
    handle_running_process(pid);
  }
}

static void read_proc_dir() {
  DIR *dirp;
  pid_t pid;

  dirp = open_pid_dir("/proc/");

  if (!dirp)
    return;

  while ((pid = read_pid(dirp)) != -1) {
    handle_running_process(pid);
  }
}

static int parse_argument(char *line, int *line_pointer,
                          CONFIG_ARGUMENT *arg) {
  int name_start, name_end, name_length, value_start, value_end, value_length;

  int linep = *line_pointer;
  char c;

  char *name, *value;

  // Eliminate spaces

  c = line[linep];

  while (1) {
    if (c != ' ' && c != '\t') {
      if (c == '\0') {
        *line_pointer = -1;
        return 0;
      }
      break;
    }

    c = line[++linep];
  }

  name_start = linep;

  // Find '='

  while (1) {
    c = line[++linep];

    if (c == '\0')
      return linep;
    if (c == '=')
      break;
  }

  name_end = linep;

  c = line[++linep];
  if (c == '\0')
    return linep;

  if (c == '"') {
    // If the next character is a '"', walk until the next '"'
    value_start = linep + 1;

    while (1) {
      c = line[++linep];

      if (c == '\0')
        return linep;
      if (c == '"')
        break;
    }

    value_end = linep;
    linep++;
  } else {
    // Otherwise just walk to the next space or end of string

    value_start = linep;

    while (1) {
      c = line[++linep];
      if (c == '\r' || c == '\n' || c == '\0' || c == ' ' || c == '\t')
        break;
    }

    value_end = linep;
  }

  name_length = name_end - name_start;
  name = (char *)malloc(name_length + 1);
  memcpy(name, line + name_start, name_length);
  name[name_length] = 0;

  value_length = value_end - value_start;
  value = (char *)malloc(value_length + 1);
  memcpy(value, line + value_start, value_length);
  value[value_length] = 0;

  arg->name = name;
  arg->value = value;

  *line_pointer = linep;

  return 0;
}

static void add_matcher(PROCESS_CONFIG *conf, int type, char *value) {
  PROCESS_MATCHER *match = (PROCESS_MATCHER *)malloc(sizeof(PROCESS_MATCHER));

  match->type = type;
  match->value = value;
  match->next = NULL;

  PROCESS_MATCHER **target;

  target = &conf->match;
  while (*target != NULL) {
    target = &(*target)->next;
  }

  *target = match;
}

static void add_cpu(PROCESS_CONFIG *conf, int cpu) {
  CPU_ENTRY *entry = (CPU_ENTRY *)malloc(sizeof(CPU_ENTRY));

  entry->cpu = cpu;
  entry->next = NULL;

  CPU_ENTRY **target;

  target = &conf->cpu;
  while (*target != NULL) {
    target = &(*target)->next;
  }

  *target = entry;
}

static int modify_from_argument(PROCESS_CONFIG *conf, CONFIG_ARGUMENT *arg) {
  char *value = (char *)malloc(strlen(arg->value) + 1);

  memcpy(value, arg->value, strlen(arg->value) + 1);

  if (!strcmp(arg->name, "NAME")) {
    conf->name = value;
  } else if (!strcmp(arg->name, "NICE")) {
    conf->prio = atoi(value);
    free(value);
  } else if (!strcmp(arg->name, "COMM")) {
    add_matcher(conf, PROCESS_MATCHER_COMM, value);
  } else if (!strcmp(arg->name, "PATH")) {
    add_matcher(conf, PROCESS_MATCHER_PATH, value);
  } else if (!strcmp(arg->name, "CPU")) {
    add_cpu(conf, atoi(value));
    free(value);
  } else {
    return 1;
    free(value);
  }

  return 0;
}

static int parse_config_line(char *line) {
  int len, result;
  int line_pointer = 0;
  int old_line_pointer = 0;
  int had_any_rule = 0;

  len = strlen(line);

  if (len == 0 || line[0] == '#')
    return 0;

  CONFIG_ARGUMENT *arg = (CONFIG_ARGUMENT *)malloc(sizeof(CONFIG_ARGUMENT));
  PROCESS_CONFIG *conf = (PROCESS_CONFIG *)malloc(sizeof(PROCESS_CONFIG));

  conf->cpu = NULL;
  conf->match = NULL;
  conf->name = NULL;
  conf->id = 0;
  conf->cgroup = NULL;

  while (line_pointer != -1 && line_pointer < len - 1) {
    old_line_pointer = line_pointer;
    result = parse_argument(line, &line_pointer, arg);

    if (result) {
      free(arg);
      free(conf);
      return result;
    }

    if (line_pointer != -1) {
      had_any_rule = 1;

      if (modify_from_argument(conf, arg)) {
        free(arg->value);
        free(arg->name);
        free(arg);
        free(conf);
        return old_line_pointer;
      }
    }

    free(arg->value);
    free(arg->name);
  }

  free(arg);

  if (had_any_rule) {
    add_config_entry(conf);
  }

  return 0;
}

static int read_config(const char *path) {
  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  int line_num = 0;
  int result;

  fp = fopen(path, "r");

  if (fp == NULL) {
    return 1;
  }

  printf("Reading config: %s\n", path);

  while ((read = getline(&line, &len, fp)) != -1) {
    line_num++;
    if ((result = parse_config_line(line))) {
      printf("Parse error on line %i in file %s: %s", line_num, path, line);
    }
  }

  fclose(fp);

  if (line) {
    free(line);
  }

  return 0;
}

static int create_cgroup(PROCESS_CONFIG *config) {
  char *cgroup = (char *)malloc(128);

  char cpus[128];
  char mems[128];
  char cpustring[512];

  int fp;

  sprintf(cgroup, "/sys/fs/cgroup/cpuset/nicedaemon_%i", config->id);
  sprintf(cpus, "%s/cpuset.cpus", cgroup);
  sprintf(mems, "%s/cpuset.mems", cgroup);

  mkdir(cgroup, 0x777);

  CPU_ENTRY *current_cpu;
  current_cpu = config->cpu;

  cpustring[0] = 0;

  while (current_cpu != NULL) {
    sprintf(cpustring, "%s%i", cpustring, current_cpu->cpu);

    current_cpu = current_cpu->next;

    if (current_cpu) {
      sprintf(cpustring, "%s,", cpustring);
    }
  }

  sprintf(cpustring, "%s\n", cpustring);

  fp = open(cpus, O_WRONLY);
  if (!fp) {
    return 1;
  }
  write(fp, cpustring, strlen(cpustring));
  close(fp);

  fp = open(mems, O_WRONLY);
  if (!fp) {
    return 1;
  }
  write(fp, "0\n", 2);
  close(fp);

  config->cgroup = cgroup;

  return 0;
}

static int remove_cgroup(char *d_name) {
  char d_path[512];
  char t_path[512];

  char line[512];

  FILE *source;
  FILE *target;

  sprintf(d_path, "/sys/fs/cgroup/cpuset/%s", d_name);
  sprintf(t_path, "%s/tasks", d_path);

  source = fopen(t_path, "r");

  if (source == NULL) {
    return 1;
  }

  target = fopen("/sys/fs/cgroup/cpuset/tasks", "w");

  if (target == NULL) {
    return 1;
  }

  while (fgets(line, sizeof line, source) != NULL) {
    fprintf(target, "%s", line);
    fflush(target);
  }

  fclose(source);
  fclose(target);

  return rmdir(d_path);
}

static int remove_cgroups() {
  DIR *dirp;
  struct dirent *dp;

  dirp = opendir("/sys/fs/cgroup/cpuset/");

  if (!dirp) {
    return 1;
  }

  while ((dp = readdir(dirp)) != NULL) {
    if (!strncmp("nicedaemon_", dp->d_name, 11)) {
      if (remove_cgroup(dp->d_name)) {
        return 1;
      }
    }
  }

  closedir(dirp);

  return 0;
}

static int create_cgroups() {
  CONFIG_ENTRY *current_config = first_config_entry;

  while (current_config != NULL) {
    if (current_config->config->cpu != NULL) {
      create_cgroup(current_config->config);
    }

    current_config = current_config->next;
  }

  return 0;
}

int main() {
  if (getuid() != 0) {
    printf("Run this program as root\n");
    return 1;
  }

  if (read_config("./nicedaemon.conf") &&
      read_config("/etc/nicedaemon.conf")) {
    printf("Could not read any config file! (Looked for ./nicedaemon.conf and "
           "/etc/nicedaemon.conf)\n");
    return 1;
  }

  if (remove_cgroups()) {
    printf("Could not remove cgroups.\n");
    return 1;
  };

  if (create_cgroups()) {
    printf("Could not create cgroups.\n");
    return 1;
  };

  printf("Now running.\n");

  read_proc_dir();

  return fork_connector_loop(handle_msg);
}
