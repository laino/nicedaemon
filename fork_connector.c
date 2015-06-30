/*
 * Copyright (C) Nils Kuhnhenn, 2015
 * Derived from exec-notify.c by Matth Helsley
 * Original copyright notice follows:
 *
 * Copyright (C) Matt Helsley, IBM Corp. 2005
 * Derived from fcctl.c by Guillaume Thouvenin
 * Original copyright notice follows:
 *
 * Copyright (C) 2005 BULL SA.
 * Written by Guillaume Thouvenin <guillaume.thouvenin@bull.net>
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

#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <linux/connector.h>
#include <linux/netlink.h>
#include <linux/cn_proc.h>

#include <sys/resource.h>

#define SEND_MESSAGE_LEN                                                      \
  (NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op)))
#define RECV_MESSAGE_LEN                                                      \
  (NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(struct proc_event)))

#define SEND_MESSAGE_SIZE (NLMSG_SPACE(SEND_MESSAGE_LEN))
#define RECV_MESSAGE_SIZE (NLMSG_SPACE(RECV_MESSAGE_LEN))

#define max(x, y) ((y) < (x) ? (x) : (y))
#define min(x, y) ((y) > (x) ? (x) : (y))

#define BUFF_SIZE (max(max(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE), 1024))
#define MIN_RECV_SIZE (min(SEND_MESSAGE_SIZE, RECV_MESSAGE_SIZE))

#define PROC_CN_MCAST_LISTEN (1)
#define PROC_CN_MCAST_IGNORE (2)

int fork_connector_loop(void (*callback)(struct cn_msg *)) {
  int sk_nl;
  int err;
  struct sockaddr_nl my_nla, kern_nla, from_nla;
  socklen_t from_nla_len;
  char buff[BUFF_SIZE];
  int rc = 0;
  struct nlmsghdr *nl_hdr;
  struct cn_msg *cn_hdr;
  enum proc_cn_mcast_op *mcop_msg;
  size_t recv_len = 0;

  setvbuf(stdout, NULL, _IONBF, 0);

  /*
   * Create an endpoint for communication. Use the kernel user
   * interface device (PF_NETLINK) which is a datagram oriented
   * service (SOCK_DGRAM). The protocol used is the connector
   * protocol (NETLINK_CONNECTOR)
   */
  sk_nl = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
  if (sk_nl == -1) {
    printf("socket sk_nl error");
    return rc;
  }
  my_nla.nl_family = AF_NETLINK;
  my_nla.nl_groups = CN_IDX_PROC;
  my_nla.nl_pid = getpid();

  kern_nla.nl_family = AF_NETLINK;
  kern_nla.nl_groups = CN_IDX_PROC;
  kern_nla.nl_pid = 1;

  err = bind(sk_nl, (struct sockaddr *)&my_nla, sizeof(my_nla));
  if (err == -1) {
    printf("binding sk_nl error");
    goto close_and_exit;
  }
  nl_hdr = (struct nlmsghdr *)buff;
  cn_hdr = (struct cn_msg *)NLMSG_DATA(nl_hdr);
  mcop_msg = (enum proc_cn_mcast_op *)&cn_hdr->data[0];

  memset(buff, 0, sizeof(buff));
  *mcop_msg = PROC_CN_MCAST_LISTEN;

  /* fill the netlink header */
  nl_hdr->nlmsg_len = SEND_MESSAGE_LEN;
  nl_hdr->nlmsg_type = NLMSG_DONE;
  nl_hdr->nlmsg_flags = 0;
  nl_hdr->nlmsg_seq = 0;
  nl_hdr->nlmsg_pid = getpid();
  /* fill the connector header */
  cn_hdr->id.idx = CN_IDX_PROC;
  cn_hdr->id.val = CN_VAL_PROC;
  cn_hdr->seq = 0;
  cn_hdr->ack = 0;
  cn_hdr->len = sizeof(enum proc_cn_mcast_op);

  if (send(sk_nl, nl_hdr, nl_hdr->nlmsg_len, 0) != nl_hdr->nlmsg_len) {
    printf("failed to send proc connector mcast ctl op!\n");
    goto close_and_exit;
  }

  if (*mcop_msg == PROC_CN_MCAST_IGNORE) {
    rc = 0;
    goto close_and_exit;
  }

  for (memset(buff, 0, sizeof(buff)), from_nla_len = sizeof(from_nla);;
       memset(buff, 0, sizeof(buff)), from_nla_len = sizeof(from_nla)) {
    struct nlmsghdr *nlh = (struct nlmsghdr *)buff;
    memcpy(&from_nla, &kern_nla, sizeof(from_nla));
    recv_len = recvfrom(sk_nl, buff, BUFF_SIZE, 0,
                        (struct sockaddr *)&from_nla, &from_nla_len);
    if (from_nla.nl_pid != 0)
      continue;
    if (recv_len < 1)
      continue;
    while (NLMSG_OK(nlh, recv_len)) {
      cn_hdr = NLMSG_DATA(nlh);
      if (nlh->nlmsg_type == NLMSG_NOOP)
        continue;
      if ((nlh->nlmsg_type == NLMSG_ERROR) ||
          (nlh->nlmsg_type == NLMSG_OVERRUN))
        break;
      callback(cn_hdr);
      if (nlh->nlmsg_type == NLMSG_DONE)
        break;
      nlh = NLMSG_NEXT(nlh, recv_len);
    }
  }

close_and_exit:

  close(sk_nl);

  return rc;
}
