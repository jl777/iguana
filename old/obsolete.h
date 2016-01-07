//
//  obsolete.h
//  pnacl
//
//  Created by jimbo laptop on 10/27/15.
//  Copyright (c) 2015 jl777. All rights reserved.
//

#ifndef pnacl_obsolete_h
#define pnacl_obsolete_h

if ( 0 )
{
    sleep(3);
    char *str,*jsonstr = clonestr("{\"plugin\":\"relay\",\"method\":\"busdata\"}"); uint32_t nonce;
    if ( (str= busdata_sync(&nonce,jsonstr,"allnodes",0)) != 0 )
    {
        fprintf(stderr,"busdata.(%s)\n",str);
        free(str);
    } else printf("null return from busdata sync.(%s)\n",jsonstr);
        getchar();exit(1);
        }

int32_t nn_stripctrl(int32_t *clenp,uint8_t *ctrl,int32_t ctrlsize,uint8_t *buf)
{
    int32_t clen,offset;
    offset = 1;
    if ( (clen= buf[0]) > 0 )
    {
        if ( clen == 0xfd )
        {
            clen = buf[1] | (buf[2] << 8);
            offset += 2;
        }
        printf("nn_stripctrl: clen.%d offset.%d\n",clen,offset);
        if ( clen > ctrlsize )
        {
            printf("too much control data.%d vs %d, truncate\n",clen,(int32_t)sizeof(ctrl));
            memcpy(ctrl,&buf[offset],ctrlsize);
            *clenp = ctrlsize;
            errno = MSG_CTRUNC;
        }
        else
        {
            memcpy(ctrl,&buf[offset],clen);
            *clenp = clen;
        }
        //printf("copied (%d).%d bytes of control from nbytes.%d\n",clen,offset-clen,(int32_t)nbytes);
    } else *clenp = 0;
    offset += clen;
    return(offset);
}

static bool nc_conn_ip_active(struct net_child_info *nci,const unsigned char *ip)
{
	unsigned int i;
	for (i = 0; i < nci->conns->len; i++)
    {
		struct nc_conn *conn;
		conn = parr_idx(nci->conns, i);
		if (!memcmp(conn->peer.addr.ip, ip, 16))
			return true;
	}
	return false;
}

static bool nc_conn_group_active(struct net_child_info *nci,const struct peer *peer)
{
	// FIXME
	return false;
	unsigned int group_len = peer->group_len;
	unsigned int i;
	for (i = 0; i < nci->conns->len; i++)
    {
		struct nc_conn *conn;
		conn = parr_idx(nci->conns, i);
		if ((group_len == conn->peer.group_len) && !memcmp(peer->group, conn->peer.group, group_len))
			return true;
	}
	return false;
}

static struct nc_conn *nc_conn_new(const struct peer *peer)
{
	struct nc_conn *conn;
	conn = calloc(1, sizeof(*conn));
	if (!conn)
		return NULL;
	conn->fd = -1;
	peer_copy(&conn->peer, peer);
	bn_address_str(conn->addr_str, sizeof(conn->addr_str), conn->peer.addr.ip);
	return conn;
}

static void nc_conn_kill(struct net_child_info *nci,struct nc_conn *conn)
{
	assert(conn->dead == false);
	conn->dead = true;
	event_base_loopbreak(conn->nci->eb);
}

static void nc_conn_free(struct net_child_info *nci,struct nc_conn *conn)
{
	if (!conn)
		return;
	if (conn->write_q)
    {
		clist *tmp = conn->write_q;
		while (tmp)
        {
			struct buffer *buf;
			buf = tmp->data;
			tmp = tmp->next;
			free(buf->p);
			free(buf);
		}
		clist_free(conn->write_q);
	}
	if (conn->ev)
    {
		event_del(conn->ev);
		event_free(conn->ev);
	}
	if (conn->write_ev)
    {
		event_del(conn->write_ev);
		event_free(conn->write_ev);
	}
	if (conn->fd >= 0)
		close(conn->fd);
	free(conn->msg.data);
	memset(conn, 0, sizeof(*conn));
	free(conn);
}

static bool nc_conn_start(struct net_child_info *nci,struct nc_conn *conn)
{
	char errpfx[64];
	/* create socket */
    printf("start connection.(%s)\n",conn->addr_str);
	conn->ipv4 = is_ipv4_mapped(conn->peer.addr.ip);
	conn->fd = socket(conn->ipv4 ? AF_INET : AF_INET6,SOCK_STREAM,IPPROTO_TCP);
	if ( conn->fd < 0 )
    {
		sprintf(errpfx, "socket %s", conn->addr_str);
		perror(errpfx);
		return false;
	}
	/* set non-blocking */
	int flags = fcntl(conn->fd,F_GETFL,0);
	if ( (flags < 0) || (fcntl(conn->fd,F_SETFL,flags | O_NONBLOCK) < 0) )
    {
		sprintf(errpfx, "socket fcntl %s", conn->addr_str);
		perror(errpfx);
		return false;
	}
	struct sockaddr *saddr;
	struct sockaddr_in6 saddr6;
	struct sockaddr_in saddr4;
	socklen_t saddr_len;
	/* fill out connect(2) address */
	if (conn->ipv4)
    {
		memset(&saddr4, 0, sizeof(saddr4));
		saddr4.sin_family = AF_INET;
		memcpy(&saddr4.sin_addr.s_addr,&conn->peer.addr.ip[12],4);
		saddr4.sin_port = htons(conn->peer.addr.port);
		saddr = (struct sockaddr *) &saddr4;
		saddr_len = sizeof(saddr4);
	}
    else
    {
		memset(&saddr6, 0, sizeof(saddr6));
		saddr6.sin6_family = AF_INET6;
		memcpy(&saddr6.sin6_addr.s6_addr,&conn->peer.addr.ip[0], 16);
		saddr6.sin6_port = htons(conn->peer.addr.port);
		saddr = (struct sockaddr *) &saddr6;
		saddr_len = sizeof(saddr6);
	}
	// initiate TCP connection
	if ( connect(conn->fd,saddr,saddr_len) < 0 )
    {
		if ( errno != EINPROGRESS )
        {
			sprintf(errpfx, "socket connect %s", conn->addr_str);
			perror(errpfx);
			return false;
		}
	}
	return true;
}

static bool nc_conn_got_header(struct net_child_info *nci,struct nc_conn *conn)
{
	parse_message_hdr(&conn->msg.hdr, conn->hdrbuf);
	unsigned int data_len = conn->msg.hdr.data_len;
	if (data_len > (16 * 1024 * 1024))
    {
		free(conn->msg.data);
		conn->msg.data = NULL;
		return false;
	}
	conn->msg.data = malloc(data_len);
	/* switch to read-body state */
	conn->msg_p = conn->msg.data;
	conn->expected = data_len;
	conn->reading_hdr = false;
	return true;
}

static bool nc_conn_got_msg(struct net_child_info *nci,struct nc_conn *conn)
{
	if (!message_valid(&conn->msg)) {
		fprintf(nci->plog, "llnet: %s invalid message\n",conn->addr_str);
		return false;
	}
	if (!nc_conn_message(nci,conn))
		return false;
	free(conn->msg.data);
	conn->msg.data = NULL;
	/* switch to read-header state */
	conn->msg_p = conn->hdrbuf;
	conn->expected = P2P_HDR_SZ;
	conn->reading_hdr = true;
	return true;
}

static void nc_conn_read_evt(int fd, short events, void *priv)
{
	struct nc_conn *conn = priv;
    struct net_child_info *nci = conn->nci;
    ssize_t rrc = read(fd, conn->msg_p, conn->expected);
	if (rrc <= 0)
    {
		if (rrc < 0)
			fprintf(nci->plog, "llnet: %s read: %s\n",conn->addr_str,strerror(errno));
		else fprintf(nci->plog, "llnet: %s read EOF\n", conn->addr_str);
		goto err_out;
	}
	conn->msg_p += rrc;
	conn->expected -= rrc;
	/* execute our state machine at most twice */
	unsigned int i;
	for (i = 0; i < 2; i++)
    {
		if (conn->expected == 0)
        {
			if (conn->reading_hdr)
            {
				if (!nc_conn_got_header(nci,conn))
					goto err_out;
			}
            else
            {
				if (!nc_conn_got_msg(nci,conn))
					goto err_out;
			}
		}
	}
	return;
err_out:
	nc_conn_kill(nci,conn);
}

static cstring *nc_version_build(struct net_child_info *nci)
{
	struct msg_version mv;
	msg_version_init(&mv);
	mv.nVersion = PROTO_VERSION;
	mv.nServices = nci->blocks_fp != 0 ? NODE_NETWORK : 0;
	mv.nTime = (int64_t)time(NULL);
	mv.nonce = nci->instance_nonce;
	sprintf(mv.strSubVer,"/nano/");
	mv.nStartingHeight = nci->db.best_chain ? nci->db.best_chain->height : 0;
	cstring *rs = ser_msg_version(&mv);
	msg_version_free(&mv);
	return rs;
}

static bool nc_conn_read_enable(struct net_child_info *nci,struct nc_conn *conn)
{
	if (conn->ev)
		return true;
	conn->ev = event_new(conn->nci->eb, conn->fd, EV_READ | EV_PERSIST,(void *)nc_conn_read_evt, conn);
	if (!conn->ev)
		return false;
	if (event_add(conn->ev, NULL) != 0)
    {
		event_free(conn->ev);
		conn->ev = NULL;
		return false;
	}
	return true;
}

static bool nc_conn_read_disable(struct net_child_info *nci,struct nc_conn *conn)
{
	if (!conn->ev)
		return true;
	event_del(conn->ev);
	event_free(conn->ev);
	conn->ev = NULL;
	return true;
}

static bool nc_conn_write_enable(struct net_child_info *nci,struct nc_conn *conn)
{
	if (conn->write_ev)
		return true;
	conn->write_ev = event_new(conn->nci->eb, conn->fd,EV_WRITE | EV_PERSIST,(void *)nc_conn_write_evt, conn);
	if (!conn->write_ev)
		return false;
	if (event_add(conn->write_ev, NULL) != 0)
    {
		event_free(conn->write_ev);
		conn->write_ev = NULL;
		return false;
	}
	return true;
}

static bool nc_conn_write_disable(struct net_child_info *nci,struct nc_conn *conn)
{
	if (!conn->write_ev)
		return true;
	event_del(conn->write_ev);
	event_free(conn->write_ev);
	conn->write_ev = NULL;
	return true;
}

static void nc_conn_evt_connected(int fd, short events, void *priv)
{
	struct nc_conn *conn = priv;
    struct net_child_info *nci = conn->nci;
    if ((events & EV_WRITE) == 0) {
		fprintf(nci->plog, "net: %s connection timeout\n", conn->addr_str);
		goto err_out;
	}
	int err = 0;
	socklen_t len = sizeof(err);
	/* check success of connect(2) */
	if ((getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) || (err != 0))
    {
		fprintf(nci->plog, "net: connect %s failed: %s\n",conn->addr_str, strerror(err));
		goto err_out;
	}
	if (nci->debugging)
		fprintf(nci->plog, "net: connected to %s\n", conn->addr_str);
	conn->connected = true;
	/* clear event used for watching connect(2) */
	event_free(conn->ev);
	conn->ev = NULL;
	/* build and send "version" message */
	cstring *msg_data = nc_version_build(nci);
	bool rc = nc_conn_send(nci,conn, "version", msg_data->str, msg_data->len);
	cstr_free(msg_data, true);
	if (!rc)
    {
		fprintf(nci->plog, "net: %s !conn_send\n", conn->addr_str);
		goto err_out;
	}
	/* switch to read-header state */
	conn->msg_p = conn->hdrbuf;
	conn->expected = P2P_HDR_SZ;
	conn->reading_hdr = true;
	if (!nc_conn_read_enable(nci,conn))
    {
		fprintf(nci->plog, "net: %s read not enabled\n", conn->addr_str);
		goto err_out;
	}
	return;
err_out:
	nc_conn_kill(nci,conn);
}

static void nc_conns_gc(struct net_child_info *nci, bool free_all)
{
	clist *dead = NULL;
	unsigned int n_gc = 0;
	/* build list of dead connections */
	unsigned int i;
	for (i = 0; i < nci->conns->len; i++)
    {
		struct nc_conn *conn = parr_idx(nci->conns, i);
		if (free_all || conn->dead)
			dead = clist_prepend(dead, conn);
	}
	/* remove and free dead connections */
	clist *tmp = dead;
	while (tmp)
    {
		struct nc_conn *conn = tmp->data;
		tmp = tmp->next;
        
		parr_remove(nci->conns, conn);
		nc_conn_free(nci,conn);
		n_gc++;
	}
	clist_free(dead);
	if (nci->debugging)
		fprintf(nci->plog, "net: gc'd %u connections\n", n_gc);
}

static void nc_conns_open(struct net_child_info *nci)
{
	if (nci->debugging)
		fprintf(nci->plog, "net: open connections (have %zu, want %zu more)\n",nci->conns->len,NC_MAX_CONN - nci->conns->len);
    printf("nc_conns_open\n");
	while ((bp_hashtab_size(nci->peers->map_addr) > 0) && (nci->conns->len < NC_MAX_CONN))
    {
        // delete peer from front of address list.  it will be re-added before writing peer file, if successful
		struct peer *peer = peerman_pop(nci->peers);
		struct nc_conn *conn = nc_conn_new(peer);
		conn->nci = nci;
        peer_free(peer);
        free(peer);
        fprintf(stderr, "net: connecting to [%s]\n",conn->addr_str);
		if (nc_conn_ip_active(nci, conn->peer.addr.ip)) // are we already connected to this IP?
        {
			fprintf(nci->plog, "net: already connected to %s\n",conn->addr_str);
			goto err_loop;
		}
 		if (nc_conn_group_active(nci, &conn->peer)) // are we already connected to this network group?
        {
			fprintf(nci->plog, "net: already grouped to %s\n",conn->addr_str);
			goto err_loop;
		}
		if (!nc_conn_start(nci,conn)) // initiate non-blocking connect(2)
        {
			fprintf(nci->plog, "net: failed to start connection to %s\n",conn->addr_str);
			goto err_loop;
		}
		// add to our list of monitored event sources
		conn->ev = event_new(nci->eb, conn->fd, EV_WRITE,(void *)nc_conn_evt_connected, conn);
		if ( !conn->ev )
        {
			fprintf(nci->plog, "net: event_new failed on %s\n",conn->addr_str);
			goto err_loop;
		}
		struct timeval timeout = { net_conn_timeout, };
		if (event_add(conn->ev, &timeout) != 0)
        {
			fprintf(nci->plog, "net: event_add failed on %s\n",conn->addr_str);
			goto err_loop;
		}
		parr_add(nci->conns, conn); // add to our list of active connections
		continue;
    err_loop:
		nc_conn_kill(nci,conn);
	}
}

static void nc_conns_process(struct net_child_info *nci)
{
	nc_conns_gc(nci, false);
	nc_conns_open(nci);
}

static bool parse_kvstr(const char *s, char **key, char **value)
{
	char *eql;
	eql = strchr(s, '=');
	if (eql)
    {
		uint32_t keylen = (uint32_t)((long)eql - (long)s);
		*key = strndup(s, keylen);
		*value = strdup(s + keylen + 1);
	}
    else
    {
		*key = strdup(s);
		*value = strdup("");
	}
	/* blank keys forbidden; blank values permitted */
	if (!strlen(*key))
    {
		free(*key);
		free(*value);
		*key = NULL;
		*value = NULL;
		return false;
	}
	return true;
}

static bool read_config_file(struct net_child_info *nci,const char *cfg_fn)
{
	FILE *cfg = fopen(cfg_fn, "r");
	if (!cfg)
		return false;
	bool rc = false;
	char line[1024];
	while (fgets(line, sizeof(line), cfg) != NULL)
    {
		char *key, *value;
		if (line[0] == '#')
			continue;
		while (line[0] && (isspace(line[strlen(line) - 1])))
			line[strlen(line) - 1] = 0;
		if (!parse_kvstr(line, &key, &value))
			continue;
        
		bp_hashtab_put(nci->settings, key, value);
	}
	rc = ferror(cfg) == 0;
	fclose(cfg);
	return rc;
}

static bool do_setting(struct net_child_info *nci,const char *arg)
{
	char *key, *value;
	if (!parse_kvstr(arg, &key, &value))
		return false;
	bp_hashtab_put(nci->settings, key, value);
	// trigger special setting-specific behaviors
	if (!strcmp(key, "debug"))
		nci->debugging = true;
	else if (!strcmp(key, "config") || !strcmp(key, "c"))
		return read_config_file(nci,value);
	return true;
}

static bool preload_settings(struct net_child_info *nci)
{
	unsigned int i;
	/* preload static settings */
	for (i = 0; i < ARRAY_SIZE(const_settings); i++)
		if (!do_setting(nci,const_settings[i]))
			return false;
	return true;
}
/*unsigned int arg;
 for (arg = 1; arg < argc; arg++)
 {
 const char *argstr = argv[arg];
 if ( do_setting(nci,argstr) == 0 )
 return 1;
 }*/
/*
 * properly capture TERM and other signals
 */

static void nc_conn_write_evt(int fd, short events, void *priv)
{
	struct nc_conn *conn = priv;
    
	struct iovec *iov = NULL;
	unsigned int iov_len = 0;
    struct net_child_info *nci = conn->nci;
	/* build list of outgoing data buffers */
	nc_conn_build_iov(conn->write_q, conn->write_partial, &iov, &iov_len);
    printf("send data to network\n");
	/* send data to network */
	ssize_t wrc = mywritev(conn->fd, iov, iov_len);
	free(iov);
	if (wrc < 0)
    {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			goto err_out;
		return;
	}
	/* handle partially and fully completed buffers */
	nc_conn_written(conn, wrc);
	/* thaw read, if write fully drained */
	if (!conn->write_q)
    {
		nc_conn_write_disable(nci,conn);
		nc_conn_read_enable(nci,conn);
	}
	return;
err_out:
	nc_conn_kill(nci,conn);
}

static void nc_conn_build_iov(clist *write_q, unsigned int partial,struct iovec **iov_, unsigned int *iov_len_)
{
	*iov_ = NULL;
	*iov_len_ = 0;
	unsigned int i, iov_len = (uint32_t)clist_length(write_q);
	struct iovec *iov = calloc(iov_len, sizeof(struct iovec));
	clist *tmp = write_q;
	i = 0;
	while (tmp)
    {
		struct buffer *buf = tmp->data;
        
		iov[i].iov_base = buf->p;
		iov[i].iov_len = buf->len;
		if (i == 0)
        {
			iov[0].iov_base += partial;
			iov[0].iov_len -= partial;
		}
		tmp = tmp->next;
		i++;
	}
	*iov_ = iov;
	*iov_len_ = iov_len;
}

static void nc_conn_written(struct nc_conn *conn, size_t bytes)
{
	while (bytes > 0)
    {
		clist *tmp;
		struct buffer *buf;
		uint32_t left;
		tmp = conn->write_q;
		buf = tmp->data;
		left = (uint32_t)(buf->len - conn->write_partial);
		/* buffer fully written; free */
		if (bytes >= left)
        {
			free(buf->p);
			free(buf);
			conn->write_partial = 0;
			conn->write_q = clist_delete(tmp, tmp);
			bytes -= left;
		}
		/* buffer partially written; store state */
		else
        {
			conn->write_partial += bytes;
			break;
		}
	}
}

ssize_t mywritev(int fildes, const struct iovec *iov, int iovcnt)
{
    int i;
    int32_t bytes_written = 0;
    for (i = 0; i < iovcnt; i++)
    {
        int len = (int32_t)send(fildes,iov[i].iov_base,iov[i].iov_len,0);
        if (len < 0)
        {
            //DWORD err = GetLastError();
            //errno = ewin_to_posix_error(err);
            bytes_written = -1;
            break;
        }
        bytes_written += len;
    }
    return bytes_written;
}

static bool nc_msg_version(struct net_child_info *nci,struct nc_conn *conn)
{
	if (conn->seen_version)
		return false;
	conn->seen_version = true;
	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };
	struct msg_version mv;
	bool rc = false;
	msg_version_init(&mv);
	if (!deser_msg_version(&mv, &buf))
		goto out;
	if (nci->debugging)
    {
		char fromstr[64], tostr[64];
		bn_address_str(fromstr, sizeof(fromstr), mv.addrFrom.ip);
		bn_address_str(tostr, sizeof(tostr), mv.addrTo.ip);
		fprintf(nci->plog, "net: %s version(%u, 0x%llx, %lld, To:%s, From:%s, %s, %u)\n",
                conn->addr_str,
                mv.nVersion,
                (unsigned long long) mv.nServices,
                (long long) mv.nTime,
                tostr,
                fromstr,
                mv.strSubVer,
                mv.nStartingHeight);
	}
	if (!(mv.nServices & NODE_NETWORK))	/* require NODE_NETWORK */
		goto out;
	if (mv.nonce == nci->instance_nonce)		/* connected to ourselves? */
		goto out;
	conn->protover = (mv.nVersion < PROTO_VERSION) ? mv.nVersion : PROTO_VERSION;
	/* acknowledge version receipt */
	if (!nc_conn_send(nci,conn, "verack", NULL, 0))
		goto out;
	rc = true;
    out:
	msg_version_free(&mv);
	return rc;
}

static bool nc_conn_send(struct net_child_info *nci,struct nc_conn *conn, const char *command,const void *data, size_t data_len)
{
	/* build wire message */
	cstring *msg = message_str(nci->chain->netmagic, command, data, (uint32_t)data_len);
	if (!msg)
		return false;
	/* buffer now owns message data */
	struct buffer *buf = calloc(1, sizeof(struct buffer));
	buf->p = msg->str;
	buf->len = msg->len;
	cstr_free(msg, false);
	/* if write q exists, write_evt will handle output */
	if (conn->write_q)
    {
		conn->write_q = clist_append(conn->write_q, buf);
		return true;
	}
	/* attempt optimistic write */
	ssize_t wrc = write(conn->fd, buf->p, buf->len);
	if (wrc < 0)
    {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
			free(buf->p);
			free(buf);
			return false;
		}
		conn->write_q = clist_append(conn->write_q, buf);
		goto out_wrstart;
	}
	/* message fully sent */
	if (wrc == buf->len)
    {
		free(buf->p);
		free(buf);
		return true;
	}
	/* message partially sent; pause read; poll for writable */
	conn->write_q = clist_append(conn->write_q, buf);
	conn->write_partial = (uint32_t)wrc;
out_wrstart:
	nc_conn_read_disable(nci,conn);
	nc_conn_write_enable(nci,conn);
	return true;
}


static void init_daemon(struct net_child_info *nci,char *coin)
{
    strcpy(nci->coin,coin);
    //init_log(nci);
    //init_blkdb(nci);
    //printf("utxo\n");
    //bp_utxo_set_init(&nci->uset);
    //printf("init_blocks\n");
    //init_blocks(nci);
    //printf("init_orphans\n");
	init_orphans(nci);
	//readprep_blocks_file(nci);
    init_nci(nci);
}

int32_t iguana_verack(struct net_child_info *nci,struct bp_address *addr)
{
    struct msg_getblocks gb; int32_t rc,numsent; time_t now,cutoff; cstring *s,*msg;
    if ( addr->seen_verack )
    {
        printf("addr->seen_verack %d\n",addr->seen_verack);
  		return(-1);
    }
	addr->seen_verack = 1;
	addr->nTime = (uint32_t)time(NULL);
	addr->n_ok++;
	//peerman_add(conn->nci->peers, &conn->peer,true);
	if ( addr->protover >= CADDR_TIME_VERSION )
    {
        msg = message_str(nci->chain->netmagic,"getaddr",NULL,0);
	    if ( (numsent= (int32_t)send(addr->usock,msg->str,msg->len,0)) != msg->len )
        {
            cstr_free(msg,true);
            return -1;
        }
        cstr_free(msg,true);
    } else printf("protover.%d vs %d CADDR_TIME_VERSION\n",addr->protover,CADDR_TIME_VERSION);
    rc = 0;
    now = time(NULL);
    cutoff = now - (24 * 60 * 60);
	if ( nci->last_getblocks < cutoff )
    {
		msg_getblocks_init(&gb);
		blkdb_locator(&nci->db,NULL,&gb.locator);
		s = ser_msg_getblocks(&gb);
        oldsend_getblocks(nci);
        msg = message_str(nci->chain->netmagic,"getblocks",s->str,(uint32_t)s->len);
		cstr_free(s,true);
		msg_getblocks_free(&gb);
		nci->last_getblocks = now;
	}
	return(rc);
}


static void init_peers(struct net_child_info *nci)
{
	struct peer_manager *peers = 0;
    peers = peerman_read(setting(nci,"peers"));
    printf("init_peers.%p\n",peers);
	if (!peers)
    {
		PostMessage( "net: initializing empty peer list\n");
		peers = peerman_seed(nci->chain->default_port,1,1);//setting(nci,"dns") != 0 ? true : false,nci->debugging);
		if ( !peerman_write(nci->chain,peers,setting(nci,"peers"),nci->debugging) )
        {
			PostMessage( "net: failed to write peer list\n");
			exit(1);
		}
	}
	char *addnode = setting(nci,"addnode");
	if (addnode)
		peerman_addstr(nci->chain->default_port,peers,addnode,nci->debugging);
	peerman_sort(peers);
	if (nci->debugging)
		PostMessage( "net: have %u/%zu peers\n",bp_hashtab_size(peers->map_addr),clist_length(peers->addrlist));
	nci->peers = peers;
}

static void init_nci(struct net_child_info *nci)
{
	nci->read_fd = -1;
	nci->write_fd = -1;
    //nci->blocks_fd = -1;
    //init_peers(nci);
	nci->conns = parr_new(NC_MAX_CONN, NULL);
	//nci->eb = event_base_new();
    nci->daemon_running = true;
}

void oldsend_getblocks(struct net_child_info *nci)
{
    struct msg_getblocks gb;
    msg_getblocks_init(&gb);
    blkdb_locator(&nci->db, NULL, &gb.locator);
    cstring *s = ser_msg_getblocks(&gb);
    printf("oldsend_getblocks\n");
    nc_conn_send(nci,0, "getblocks", s->str, s->len);
    cstr_free(s, true);
    msg_getblocks_free(&gb);
}


static bool nc_msg_inv(struct net_child_info *nci,struct nc_conn *conn)
{
	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };
	struct msg_vinv mv, mv_out;
	bool rc = false;
	msg_vinv_init(&mv);
	msg_vinv_init(&mv_out);
	if (!deser_msg_vinv(&mv, &buf))
		goto out;
	if (nci->debugging && mv.invs && mv.invs->len == 1)
    {
		struct bp_inv *inv = parr_idx(mv.invs, 0);
		char hexstr[BU256_STRSZ];
		bu256_hex(hexstr, &inv->hash);
		char typestr[32];
		switch (inv->type)
        {
            case MSG_TX: strcpy(typestr, "tx"); break;
            case MSG_BLOCK: strcpy(typestr, "block"); break;
            default: sprintf(typestr, "unknown 0x%x", inv->type); break;
		}
		PostMessage( "net: %s inv %s %s\n",conn->addr_str, typestr, hexstr);
	}
	else if (nci->debugging && mv.invs)
		PostMessage( "net: %s inv (%zu sz)\n",conn->addr_str, mv.invs->len);
	if (!mv.invs || !mv.invs->len)
		goto out_ok;
	/* scan incoming inv's for interesting material */
	unsigned int i;
	for (i = 0; i < mv.invs->len; i++)
    {
		struct bp_inv *inv = parr_idx(mv.invs, i);
		switch (inv->type)
        {
            case MSG_BLOCK:
                if (!blkdb_lookup(&nci->db, &inv->hash) && !have_orphan(nci,&inv->hash))
                    msg_vinv_push(&mv_out, MSG_BLOCK, &inv->hash);
                break;
            case MSG_TX:
            default:
                break;
		}
	}
	/* send getdata, if they have anything we want */
	if (mv_out.invs && mv_out.invs->len)
    {
		cstring *s = ser_msg_vinv(&mv_out);
		rc = nc_conn_send(nci,conn, "getdata", s->str, s->len);
		cstr_free(s, true);
	}
out_ok:
	rc = true;
    out:
	msg_vinv_free(&mv);
	msg_vinv_free(&mv_out);
	return rc;
}

ssize_t fwritev(FILE *fp,const struct iovec *iov,int iovcnt)
{
    int i; int32_t bytes_written = 0;
    fprintf(stderr,"fwritev.%d from %ld: ",iovcnt,(long)ftell(fp));
    for (i = 0; i < iovcnt; i++)
    {
        int len = (int32_t)fwrite(iov[i].iov_base,1,iov[i].iov_len,fp);
        if ( len != iov[i].iov_len )
        {
            printf("len.%d != %d iov[i].iov_len\n",len,(int32_t)iov[i].iov_len);
            //DWORD err = GetLastError();
            //errno = ewin_to_posix_error(err);
            bytes_written = -1;
            break;
        }
        bytes_written += len;
    }
    fprintf(stderr,"%d bytes\n",bytes_written);
    return bytes_written;
}

static bool nc_msg_verack(struct net_child_info *nci,struct nc_conn *conn)
{
	if (conn->seen_verack)
		return false;
	conn->seen_verack = true;
	if (nci->debugging)
		PostMessage( "net: %s verack\n",conn->addr_str);
	/*
	 * When a connection attempt is made, the peer is deleted
	 * from the peer list.  When we successfully connect,
	 * the peer is re-added.  Thus, peers are immediately
	 * forgotten if they fail, on the first try.
	 */
	conn->peer.last_ok = time(NULL);
	conn->peer.n_ok++;
	conn->peer.addr.nTime = (uint32_t) conn->peer.last_ok;
	peerman_add(conn->nci->peers, &conn->peer, true);
	/* request peer addresses */
	if ((conn->protover >= CADDR_TIME_VERSION) && (!nc_conn_send(nci,conn, "getaddr", NULL, 0)))
		return false;
	/* request blocks */
	bool rc = true;
	time_t now = time(NULL);
	time_t cutoff = now - (24 * 60 * 60);
	if (conn->nci->last_getblocks < cutoff)
    {
		struct msg_getblocks gb;
		msg_getblocks_init(&gb);
		blkdb_locator(&nci->db, NULL, &gb.locator);
		cstring *s = ser_msg_getblocks(&gb);
		rc = nc_conn_send(nci,conn, "getblocks", s->str, s->len);
		cstr_free(s, true);
		msg_getblocks_free(&gb);
		conn->nci->last_getblocks = now;
	}
	return rc;
}
static bool nc_conn_send(struct net_child_info *nci,struct nc_conn *conn, const char *command,const void *data, size_t data_len)
{
    int32_t i;
	cstring *msg = message_str(nci->chain->netmagic, command, data, (uint32_t)data_len);
    for (i=0; i<msg->len; i++)
        printf("%02x ",msg->str[i] & 0xff);
    printf("nc_conn_send cmd.(%s) len.%d\n",command,(int32_t)msg->len);
    return(0);
}

static bool nc_msg_addr(struct net_child_info *nci,struct nc_conn *conn)
{
	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };
	struct msg_addr ma;
	bool rc = false;
	msg_addr_init(&ma);
	if (!deser_msg_addr(conn->protover, &ma, &buf))
		goto out;
	unsigned int i;
	time_t cutoff = time(NULL) - (7 * 24 * 60 * 60);
	if (nci->debugging)
    {
		unsigned int old = 0;
		for (i = 0; i < ma.addrs->len; i++)
        {
			struct bp_address *addr = parr_idx(ma.addrs, i);
			if (addr->nTime < cutoff)
				old++;
		}
		PostMessage( "net: %s addr(%zu addresses, %u old)\n",conn->addr_str, ma.addrs->len, old);
	}
	/* ignore ancient addresses */
	if (conn->protover < CADDR_TIME_VERSION)
		goto out_ok;
	/* feed addresses to peer manager */
	for (i = 0; i < ma.addrs->len; i++) {
		struct bp_address *addr = parr_idx(ma.addrs, i);
		if (addr->nTime > cutoff)
			peerman_add_addr(conn->nci->peers, addr, false);
	}
out_ok:
	rc = true;
    out:
	msg_addr_free(&ma);
	return rc;
}
/*libevent stubs
 #define EV_READ 1
 #define EV_WRITE 2
 #define EV_PERSIST 4
 struct event *event_new(struct event_base *evbase,int32_t fd,int32_t flags,void *funcp,void *conn) { return(0); }
 void event_base_loopbreak(struct event_base *evbase) {}
 void event_base_dispatch(struct event_base *evbase) {}
 void event_base_free(struct event_base *evbase) {}
 
 struct event_base *event_base_new() { return(0); }
 void event_del(struct event *ev) {}
 void event_free(struct event *ev) {}
 int32_t event_add(struct event *ev,struct timeval *tval) { return(-1); }
 // end stubs */

enum { NC_MAX_CONN		= 8, };

//static unsigned int net_conn_timeout = 11;
/*
 static void nc_conn_kill(struct net_child_info *nci,struct nc_conn *conn);
 static bool nc_conn_read_enable(struct net_child_info *nci,struct nc_conn *conn);
 static bool nc_conn_read_disable(struct net_child_info *nci,struct nc_conn *conn);
 static bool nc_conn_write_enable(struct net_child_info *nci,struct nc_conn *conn);
 static bool nc_conn_write_disable(struct net_child_info *nci,struct nc_conn *conn);*/

static bool nc_conn_message(struct net_child_info *nci,struct nc_conn *conn)
{
	char *command = conn->msg.hdr.command;
	/* verify correct network */
    printf("got message.(%s)\n",command);
	if (memcmp(conn->msg.hdr.netmagic, nci->chain->netmagic, 4))
    {
		PostMessage( "net: %s invalid network\n",conn->addr_str);
		return false;
	}
	/* incoming message: version */
	//if ( !strncmp(command,"version",12) )
	//	return nc_msg_version(nci,conn);
	/* "version" must be first message */
	if (!conn->seen_version)
    {
		PostMessage( "net: %s 'version' not first\n",conn->addr_str);
		return false;
	}
	/* incoming message: verack */
	if (!strncmp(command,"verack",12))
		return nc_msg_verack(nci,conn);
	/* "verack" must be second message */
	if (!conn->seen_verack)
    {
		PostMessage( "net: %s 'verack' not second\n",conn->addr_str);
		return false;
	}
	/* incoming message: addr */
	if (!strncmp(command, "addr", 12))
		return nc_msg_addr(nci,conn);
	/* incoming message: inv */
	else if (!strncmp(command, "inv", 12))
		return nc_msg_inv(nci,conn);
	/* incoming message: block */
	else if (!strncmp(command, "block", 12))
		return nc_msg_block(nci,conn);
	if (nci->debugging)
		PostMessage( "net: %s unknown message %s\n",conn->addr_str,command);
	/* ignore unknown messages */
	return true;
}

static void init_log(struct net_child_info *nci)
{
	char *log_fn = setting(nci,"log");
	if (!log_fn || !strcmp(log_fn, "-"))
		nci->plog = stdout;
	else {
		nci->plog = fopen(log_fn, "a");
		if (!nci->plog) {
			perror(log_fn);
			exit(1);
		}
	}
	setvbuf(nci->plog, NULL, _IONBF, BUFSIZ);
}

static void init_blkdb(struct net_child_info *nci)
{
	if (!blkdb_init(&nci->db, nci->chain->netmagic, &nci->chain_genesis))
    {
		PostMessage( "blkdb init failed\n");
		exit(1);
	}
    
	char *blkdb_fn = 0;//setting(nci,"blkdb");
	if (!blkdb_fn)
		return;
	if ((access(blkdb_fn, F_OK) == 0) && !blkdb_read(nci->chain->hastimestamp,&nci->db, blkdb_fn))
    {
		PostMessage( "blkdb read failed\n");
		exit(1);
	}
    if ( (nci->db.fp= fopen(blkdb_fn,"rb+")) == 0 )
        nci->db.fp= fopen(blkdb_fn,"wb+");
    if ( nci->db.fp == 0 )
    {
        PostMessage( "blkdb file open failed: %s\n", strerror(errno));
        exit(1);
    }
	//nci->db.fd = open(blkdb_fn,O_WRONLY | O_APPEND | O_CREAT | O_LARGEFILE, 0666);
	//if (nci->db.fd < 0) {
	//	PostMessage( "blkdb file open failed: %s\n", strerror(errno));
	//	exit(1);
	//}
}

static void init_blocks(struct net_child_info *nci)
{
	char blocks_fn[512];
    sprintf(blocks_fn,"%s.blocks",nci->coin);
	if ( (nci->blocks_fp= fopen(blocks_fn,"rb+")) == 0 )// O_RDWR | O_CREAT | O_LARGEFILE, 0666);
        nci->blocks_fp = fopen(blocks_fn,"wb+");
	if ( nci->blocks_fp == 0 )
    {
		PostMessage( "blocks file open failed: %s\n", strerror(errno));
		exit(1);
	}
    fseek(nci->blocks_fp,0,SEEK_END);
	off64_t flen = ftell(nci->blocks_fp);
    printf("opened.(%s) flen.%llu\n",blocks_fn,(long long)flen);
    if ( flen == (off64_t)-1 )
    {
		PostMessage( "blocks file lseek64 failed: %s\n", strerror(errno));
		exit(1);
	}
	if ( flen == 0 )
		init_block0(nci);
}

static void shutdown_daemon(struct net_child_info *nci)
{
    if ( nci->blocks_fp != 0 )
        fclose(nci->blocks_fp);
    bool rc = peerman_write(nci->chain,nci->peers,setting(nci,"peers"),nci->debugging);
	PostMessage( "net: %s %u/%zu peers\n",rc ? "wrote" : "failed to write",bp_hashtab_size(nci->peers->map_addr),clist_length(nci->peers->addrlist));
	if ( nci->plog != stdout && nci->plog != stderr )
    {
		fclose(nci->plog);
		nci->plog = NULL;
	}
	if ( setting(nci,"free") )
    {
		shutdown_nci(nci);
		bp_hashtab_unref(nci->orphans);
		bp_hashtab_unref(nci->settings);
		blkdb_free(&nci->db);
		bp_utxo_set_free(&nci->uset);
	}
}


static bool nc_msg_block(struct net_child_info *nci,struct nc_conn *conn)
{
	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };
    struct iovec iov[2]; char hexstr[BU256_STRSZ]; struct bp_block block; bool rc = false;
	bp_block_init(&block);
	if ( !deser_bp_block(nci->chain->hastimestamp,&block,&buf) )
		goto out;
	bp_block_calc_sha256(&block);
	bu256_hex(hexstr,&block.sha256);
	if ( nci->debugging )
		PostMessage("net: %s block %s\n",conn->addr_str,hexstr);
	if ( !bp_block_valid(&block) )
    {
		PostMessage("net: %s invalid block %s\n",conn->addr_str,hexstr);
		goto out;
	}
	if ( blkdb_lookup(&nci->db,&block.sha256) || have_orphan(nci,&block.sha256) )
		goto out_ok;
	iov[0].iov_base = &conn->msg.hdr;
	iov[0].iov_len = sizeof(conn->msg.hdr);
	iov[1].iov_base = (void *)buf.p;
	iov[1].iov_len = conn->msg.hdr.data_len;
    printf("hdr.%d len.%d\n",(int32_t)sizeof(conn->msg.hdr),(int32_t)buf.len);
	size_t total_write = iov[0].iov_len + iov[1].iov_len;
	//off64_t fpos64 = lseek64(nci->blocks_fd, 0, SEEK_CUR);
    //fseek(nci->blocks_fp, 0, SEEK_CUR);
    off64_t fpos64 = ftell(nci->blocks_fp);
	if ( fpos64 == (off64_t)-1 )
    {
		PostMessage( "blocks: lseek64 failed %s\n",
                    strerror(errno));
		goto out;
	}
	//errno = 0;
	ssize_t bwritten = fwritev(nci->blocks_fp,iov,ARRAY_SIZE(iov));
	if ( bwritten != total_write )
    {
		PostMessage( "blocks: write failed %s\n",strerror(errno));
		goto out;
	}
	if ( !process_block(nci,&block,fpos64) )
    {
		PostMessage( "blocks: process-block failed\n");
		goto out;
	}
out_ok:
	rc = true;
    out:
	bp_block_free(&block);
	return rc;
}

static bool spend_tx(bool script_verf,struct bp_utxo_set *uset, const struct bp_tx *tx,unsigned int tx_idx, unsigned int height)
{
	bool is_coinbase = (tx_idx == 0);
	struct bp_utxo *coin;
	int64_t total_in = 0, total_out = 0;
	unsigned int i;
	/* verify and spend this transaction's inputs */
	if (!is_coinbase)
    {
		for (i = 0; i < tx->vin->len; i++)
        {
			struct bp_txin *txin;
			struct bp_txout *txout;
			txin = parr_idx(tx->vin, i);
			coin = bp_utxo_lookup(uset, &txin->prevout.hash);
			if (!coin || !coin->vout)
				return false;
			if (coin->is_coinbase && ((coin->height + COINBASE_MATURITY) > height))
				return false;
			txout = NULL;
			if (txin->prevout.n >= coin->vout->len)
				return false;
			txout = parr_idx(coin->vout, txin->prevout.n);
			total_in += txout->nValue;
			if (script_verf && !bp_verify_sig(coin, tx, i, /* SCRIPT_VERIFY_P2SH */ 0, 0))
				return false;
			if (!bp_utxo_spend(uset, &txin->prevout))
				return false;
		}
	}
	for (i = 0; i < tx->vout->len; i++)
    {
		struct bp_txout *txout;
		txout = parr_idx(tx->vout, i);
		total_out += txout->nValue;
	}
	if (!is_coinbase)
    {
		if (total_out > total_in)
			return false;
	}
	/* copy-and-convert a tx into a UTXO */
	coin = calloc(1, sizeof(*coin));
	bp_utxo_init(coin);
	if (!bp_utxo_from_tx(coin, tx, is_coinbase, height))
		return false;
	/* add unspent outputs to set */
	bp_utxo_set_add(uset, coin);
	return true;
}

static bool spend_block(struct net_child_info *nci,const struct bp_block *block,unsigned int height)
{
    struct bp_tx *tx;
    unsigned int i;
	for (i = 0; i < block->vtx->len; i++)
    {
		tx = parr_idx(block->vtx, i);
		if (!spend_tx(nci->script_verf,&nci->uset, tx, i, height))
        {
			char hexstr[BU256_STRSZ];
			bu256_hex(hexstr, &tx->sha256);
			PostMessage( "brd: spent_block tx fail %s\n", hexstr);
			return false;
		}
	}
	return true;
}

static bool process_block(struct net_child_info *nci,const struct bp_block *block,int64_t fpos)
{
	struct blkdb_reorg reorg; struct blkinfo *bi = bi_new();
    fprintf(stderr,"process_block sha256 %llx\n",*(long long *)&block->sha256);
	bu256_copy(&bi->hash, &block->sha256);
	bp_block_copy_hdr(&bi->hdr, block);
	bi->n_file = 0;
	bi->n_pos = fpos;
	if ( blkdb_add(&nci->db,bi,&reorg) == 0 )
    {
		PostMessage( "brd: blkdb add fail fpos.%ld\n",(long)fpos);
		goto err_out;
	}
	/* FIXME: support reorg */
	assert(reorg.conn == 1);
	assert(reorg.disconn == 0);
	if ( bu256_equal(&nci->db.best_chain->hash,&bi->hdr.sha256) ) // if best chain, mark TX's as spent
    {
		if ( spend_block(nci,block,bi->height) == 0 )
        {
			char hexstr[BU256_STRSZ];
			bu256_hex(hexstr, &bi->hdr.sha256);
			PostMessage("brd: block spend fail %u %s\n",bi->height, hexstr);
			// FIXME: bad record is now in blkdb
			goto err_out;
		}
	}
	return true;
err_out:
	bi_free(bi);
	return false;
}

static bool read_block_msg(struct net_child_info *nci,struct p2p_message *msg, int64_t fpos)
{
	struct const_buffer buf = { msg->data, msg->hdr.data_len };
    struct bp_block block; bool rc = false;
    // unknown records are invalid
    printf("read_block_msg\n");
	if ( strncmp(msg->hdr.command,"block",sizeof(msg->hdr.command)) )
    {
        printf("invalid cmd.(%s) != block\n",msg->hdr.command);
		return false;
    }
	bp_block_init(&block);
	if ( deser_bp_block(nci->chain->hastimestamp,&block,&buf) == 0 )
    {
		PostMessage( "brd: block deser fail\n");
		goto out;
	}
    bp_block_calc_sha256(&block);
    if (!bp_block_valid(&block))
    {
        PostMessage( "brd: block not valid\n");
        goto out;
    }
    printf("call process_block\n");
    rc = process_block(nci,&block,fpos);
    out:
	bp_block_free(&block);
	return rc;
}

static void read_blocks(struct net_child_info *nci)
{
	//int fd = nci->blocks_fd;
	int32_t n = 0; FILE *fp = nci->blocks_fp;
	struct p2p_message msg = {};
	bool read_ok = true;
	int64_t fpos = 0;
    printf("read_blocks from pos %ld\n",(long)ftell(fp));
    while ( fread_message(fp,&msg,&read_ok) )
    {
        printf("iter.%d netmagic.%x\n",n++,*(int32_t *)nci->chain->netmagic);
		if ( memcmp(msg.hdr.netmagic,nci->chain->netmagic,4) )
        {
			PostMessage("blocks file: invalid network magic\n");
			exit(1);
		}
        //strcpy(msg.hdr.command,"block");
		if ( !read_block_msg(nci,&msg,fpos) )
			exit(1);
		fpos += P2P_HDR_SZ;
		fpos += msg.hdr.data_len;
        fpos = ftell(fp);
	}
    printf("read_blocks finished loop\n");
    if ( !read_ok )
    {
		PostMessage("blocks file: read failed\n");
		exit(1);
	}
	free(msg.data);
}

static void readprep_blocks_file(struct net_child_info *nci)
{
	// if no blk index, but blocks are present, read and index all block data (several gigabytes)
    if ( nci->blocks_fp != 0 )
    {
        rewind(nci->blocks_fp);
		if ( nci->db.fp == 0 )
			read_blocks(nci);
		else
        {
            printf("seek to end\n");
			// TODO: verify that blocks file offsets are present in blkdb
			//if ( lseek(nci->blocks_fd, 0, SEEK_END) == (off_t)-1 )
            if ( fseek(nci->blocks_fp,0,SEEK_END) == (off_t)-1 )
            {
				PostMessage( "blocks file: seek failed: %s\n",strerror(errno));
				exit(1);
			}
		}
	}
}

static void init_orphans(struct net_child_info *nci)
{
	nci->orphans = bp_hashtab_new_ext(bu256_hash, bu256_equal_,(bp_freefunc) bu256_free, (bp_freefunc) buffer_free);
}

static bool have_orphan(struct net_child_info *nci,const bu256_t *v)
{
	return bp_hashtab_get(nci->orphans, v);
}

bool add_orphan(struct net_child_info *nci,const bu256_t *hash_in, struct const_buffer *buf_in)
{
	if (have_orphan(nci,hash_in))
		return false;
	bu256_t *hash = bu256_new(hash_in);
	if (!hash) {
		PostMessage( "OOM\n");
		return false;
	}
	struct buffer *buf = buffer_copy(buf_in->p, buf_in->len);
	if (!buf) {
		bu256_free(hash);
		PostMessage( "OOM\n");
		return false;
	}
	bp_hashtab_put(nci->orphans, hash, buf);
	return true;
}

struct nc_conn
{
	bool			dead;
	int			fd;
	struct peer		peer;
	char			addr_str[64];
	bool			ipv4;
	bool			connected;
	struct event		*ev;
	struct net_child_info	*nci;
	struct event		*write_ev;
	clist			*write_q;	/* of struct buffer */
	unsigned int		write_partial;
	struct p2p_message	msg;
	void			*msg_p;
	unsigned int		expected;
	bool			reading_hdr;
	unsigned char		hdrbuf[P2P_HDR_SZ];
	bool			seen_version;
	bool			seen_verack;
	uint32_t		protover;
};

static bool process_block(struct net_child_info *nci,const struct bp_block *block, int64_t fpos);
static bool have_orphan(struct net_child_info *nci,const bu256_t *v);
static bool add_orphan(struct net_child_info *nci,const bu256_t *hash_in, struct const_buffer *buf_in);

/*struct bp_hashtab *settings;
 //const struct chain_info *chain = NULL;
 bu256_t chain_genesis;
 uint64_t instance_nonce;
 bool debugging = false;
 FILE *plog = NULL;
 
 static const char *const_settings[] =
 {
 "net.connect.timeout=11",
 "addnode=127.0.0.1",
 "peers=brd.peers",
 "dns=1",
 //"blkdb=brd.blkdb",
 "blocks=brd.blocks",
 //"log=brd.log",
 };*/

static void init_block0(struct net_child_info *nci)
{
    if ( nci->blocks_fp != 0 )
    {
        cstring *msg0 = message_str(nci->chain->netmagic,"block",nci->chain->genesis_hashdata,(int32_t)sizeof(nci->chain->genesis_hashdata));
        ssize_t bwritten = fwrite(msg0->str,1,msg0->len,nci->blocks_fp);
        if ( bwritten != msg0->len )
        {
            PostMessage( "blocks write0 failed: %s\n", strerror(errno));
            exit(1);
        }
        cstr_free(msg0,true);
        off64_t fpos64 = ftell(nci->blocks_fp);
        if ( fpos64 == (off64_t)-1 )
        {
            PostMessage( "blocks lseek0 failed: %s\n", strerror(errno));
            exit(1);
        }
        PostMessage("blocks: genesis block written\n");
    }
}

static void shutdown_nci(struct net_child_info *nci)
{
	peerman_free(nci->peers);
	//nc_conns_gc(nci, true);
	assert(nci->conns->len == 0);
	//parr_free(nci->conns, true);
	//event_base_free(nci->eb);
}int32_t iguana_send(struct iguana_info *coin,void *_conn,uint8_t *serialized,char *cmd,int32_t len)
{
    return(nc_conn_send(coin,_conn,cmd,&serialized[sizeof(struct iguana_msghdr)],len));
    int32_t numsent; struct nc_conn *conn = _conn;
    len = iguana_sethdr((void *)serialized,coin->chain->netmagic,cmd,&serialized[sizeof(struct iguana_msghdr)],len);
    if ( (numsent= (int32_t)send(conn->addr.usock,serialized,len,0)) < 0 )
    {
        printf("%s: numsent.%d vs len.%d errno.%d usock.%d\n",cmd,numsent,len,errno,conn->addr.usock);
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            printf("bad errno.%d\n",errno);
            return(-errno);
        }
        if ( 0 )
        {
            /*struct buffer *buf = calloc(1, sizeof(struct buffer));
             buf->p = malloc(len), memcpy(buf->p,serialized,len);
             buf->len = len;
             conn->write_q = clist_append(conn->write_q,buf);
             nc_conn_read_disable(coin,conn);
             nc_conn_write_enable(coin,conn);*/
        }
    }
    else if ( numsent < len )
    {
        if ( 0 )
        {
            /*conn->write_q = clist_append(conn->write_q, buf);
             conn->write_partial = (uint32_t)numsent;
             buf->p = malloc(len), memcpy(buf->p,serialized,len);
             buf->len = len;
             conn->write_q = clist_append(conn->write_q,buf);
             nc_conn_read_disable(coin,conn);
             nc_conn_write_enable(coin,conn);*/
        }
        //int32_t i;
        //for (i=0; i<numsent; i++)
        //    printf("%02x ",serialized[i]);
        printf("Sent.%d of %d for %s\n",numsent,len,cmd);
    }
    printf("iguana send.%d\n",numsent);
    return(numsent);
}
/*struct net_child_info
 {
 struct peer_manager	*peers;
 void *conns;
 struct event_base *eb;
 struct bp_hashtab *settings;
 struct wallet *cur_wallet;
 const struct chain_info *chain;
 bits256 chain_genesis;
 uint64_t instance_nonce;
 int32_t debugging;
 FILE *plog;
 struct iguana_blocks blocks;
 struct bp_hashtab *orphans;
 //struct bp_utxo_set uset;
 //int blocks_fd;
 FILE *blocks_fp;
 //bool script_verf;
 //bool daemon_running;
 // int32_t lbsock;
 char coin[16];
 time_t last_getblocks;
 };*/

///struct iguana_peer addrs[10];
while ( bestheight > 0 && bestheight > oldbestheight )
{
    prevhash = iguana_prevblockhash(blocks,new_best);
    if ( (prev= iguana_findblock(&space,blocks,prevhash)) != 0 && prev->height > 0 )
    {
        new_best = prevhash;
        bestheight = prev->height;
        reorg_info->conn++;
        printf("connect.%d: newbest.%s oldheight.%d newheight.%d\n",reorg_info->conn,bits256_str(new_best),oldbestheight,bestheight);
    } else break;
}
// unlikely case: old best chain has greater height
while ( oldbestheight > 0 && bestheight > 0 && oldbestheight > bestheight )
{
    old_best = iguana_prevblockhash(blocks,old_best);
    if ( (prev= iguana_findblock(&space,blocks,prevhash)) != 0 && prev->height > 0 )
    {
        oldbestheight = prev->height;
        reorg_info->disconn++;
        printf("unlikely case: disconn.%d %s\n",reorg_info->disconn,bits256_str(old_best));
    } else break;
}
// height matches, but we are still walking parallel chains
while ( oldbestheight > 0 && bestheight > 0 && memcmp(old_best.bytes,new_best.bytes,sizeof(old_best)) != 0 )
{
    new_best = iguana_prevblockhash(blocks,new_best);
    bestheight = iguana_height(blocks,new_best);
    reorg_info->conn++;
    old_best = iguana_prevblockhash(blocks,old_best);
    oldbestheight = iguana_height(blocks,old_best);
    reorg_info->disconn++;
    printf("parallel case\n");
}

/*bits256 iguana_PoW(struct iguana_info *coin,int32_t height)
 {
 int32_t h; bits256 sum; struct iguana_block *ptr,space;
 if ( height > 0 )
 {
 h = (height / 1000);
 sum = coin->blocks.PoW[h];
 h *= 1000;
 while ( ++h <= height )
 {
 if ( (ptr= iguana_block(&space,coin,h)) != 0 )
 sum = bits256_add(sum,bits256_from_compact(ptr->bits));
 else
 {
 printf("error getting block[%u]\n",h);
 break;
 }
 }
 }
 else
 {
 iguana_block(&space,coin,0);
 sum = bits256_from_compact(space.bits);
 }
 return(sum);
 }*/
/*BIGNUM cur_work,test; bits256 x,sum; char ystr[512],xstr[512];
 BN_init(&cur_work);
 BN_init(&test);
 u256_from_compact(&cur_work,0x1d00ffff);
 PoW_str(ystr,sizeof(ystr),&cur_work);
 printf("y.(%s) ",ystr);
 BN_add(&test,&cur_work,&cur_work);
 PoW_str(ystr,sizeof(ystr),&test);
 printf("sum.(%s) ",ystr);
 PoW_conv(&test,0x1d00ffff);
 PoW_str(xstr,sizeof(xstr),&test);
 x = bits256_from_compact(0x1d00ffff);
 sum = bits256_add(x,x);
 printf("xstr.(%s) x.(%s) sum.(%s)\n",xstr,bits256_str(x),bits256_lstr(sum));
 getchar();*/
void u256_from_compact(BIGNUM *vo,uint32_t c);

int32_t PoW_conv(BIGNUM *PoW,uint32_t nBits)
{
    BN_init(PoW);
    u256_from_compact(PoW,nBits);
    return(0);
}

int32_t PoW_add(BIGNUM *sum,BIGNUM *a,BIGNUM *b)
{
    if ( BN_add(sum,a,b) == 0 )
        return(-1);
    return(0);
}

void PoW_free(BIGNUM *a) { BN_clear_free(a); }

int32_t PoW_cmp(BIGNUM *test,BIGNUM *hwm) { return(BN_cmp(test,hwm)); }
void PoW_str(char *str,int32_t maxlen,BIGNUM *v);

/*static void nc_conns_gc(struct parr *conns,bool free_all)
 {
 struct nc_conn *conn; clist *dead = NULL; uint32_t i,n_gc = 0;
 // build list of dead connections
 for (i=0; i<conns->len; i++)
 {
 conn = parr_idx(conns,i);
 if ( free_all || conn->dead )
 dead = clist_prepend(dead,conn);
 }
 // remove and free dead connections
 clist *tmp = dead;
 while ( tmp )
 {
 struct nc_conn *conn = tmp->data;
 tmp = tmp->next;
 parr_remove(conns,conn);
 nc_conn_free(conn);
 n_gc++;
 }
 clist_free(dead);
 fprintf(stderr,"net: gc'd %u connections\n",n_gc);
 }*/

/*static struct nc_conn *nc_conn_new(const struct peer *peer)
 {
 struct nc_conn *conn;
 conn = calloc(1, sizeof(*conn));
 if (!conn)
 return NULL;
 conn->fd = -1;
 peer_copy(&conn->peer, peer);
 bn_address_str(conn->addr_str, sizeof(conn->addr_str), conn->peer.addr.ip);
 return conn;
 }*/

/*static bool nc_conn_start(struct iguana_info *coin,struct nc_conn *conn)
 {
 char errpfx[64];
 printf("start connection.(%s)\n",conn->addr_str);
 conn->ipv4 = 1;//is_ipv4_mapped(conn->peer.addr.ip);
 conn->fd = socket(conn->ipv4 ? AF_INET : AF_INET6,SOCK_STREAM,IPPROTO_TCP);
 if ( conn->fd < 0 )
 {
 sprintf(errpfx, "socket %s", conn->addr_str);
 perror(errpfx);
 return false;
 }
 int flags = fcntl(conn->fd,F_GETFL,0);
 if ( (flags < 0) || (fcntl(conn->fd,F_SETFL,flags | O_NONBLOCK) < 0) )
 {
 sprintf(errpfx, "socket fcntl %s", conn->addr_str);
 perror(errpfx);
 return false;
 }
 struct sockaddr *saddr;
 struct sockaddr_in6 saddr6;
 struct sockaddr_in saddr4;
 socklen_t saddr_len;
 if (conn->ipv4)
 {
 memset(&saddr4, 0, sizeof(saddr4));
 saddr4.sin_family = AF_INET;
 memcpy(&saddr4.sin_addr.s_addr,&conn->peer.addr.ip[12],4);
 saddr4.sin_port = htons(conn->peer.addr.port);
 saddr = (struct sockaddr *) &saddr4;
 saddr_len = sizeof(saddr4);
 }
 else
 {
 memset(&saddr6, 0, sizeof(saddr6));
 saddr6.sin6_family = AF_INET6;
 memcpy(&saddr6.sin6_addr.s6_addr,&conn->peer.addr.ip[0], 16);
 saddr6.sin6_port = htons(conn->peer.addr.port);
 saddr = (struct sockaddr *) &saddr6;
 saddr_len = sizeof(saddr6);
 }
 // initiate TCP connection
 if ( connect(conn->fd,saddr,saddr_len) < 0 )
 {
 if ( errno != EINPROGRESS )
 {
 sprintf(errpfx, "socket connect %s", conn->addr_str);
 perror(errpfx);
 return false;
 }
 }
 return true;
 }*/
int32_t rc,lbsock=-1,timeout=1000,priority=1; uint8_t magic[4] = { 0xf9, 0xbe, 0xb4, 0xd9 };
if ( 0 )
{
    int32_t testsock,testsock2; char buf[512];
    testsock2 = nn_socket(AF_SP,NN_CRYPTO);
    testsock = nn_socket(AF_SP,NN_CRYPTO);
    rc = nn_setsockopt(testsock,NN_SOL_SOCKET,NN_CRYPTO_MAGIC,magic,4);
    rc = nn_setsockopt(testsock2,NN_SOL_SOCKET,NN_CRYPTO_MAGIC,magic,4);
    nn_bind(testsock2,"crypto://127.0.0.1:9999");
    nn_connect(testsock,"crypto://127.0.0.1:9999");
    nn_send(testsock,"hello",6,0);
    nn_recv(testsock2,buf,sizeof(buf),0);
    printf("bind side got.(%s)\n",buf);
    nn_send(testsock2,"gotmsg",7,0);
    nn_recv(testsock,buf,sizeof(buf),0);
    printf("connect side got.(%s)\n",buf);
    
    getchar();
}
//if ( (lbsock= nn_socket(AF_SP,NN_CRYPTO)) >= 0 )
{
    rc = nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_CRYPTO_MAGIC,magic,4);
    printf("rc.%d from NN_CRYPTO_MAGIC\n",rc);
    rc = nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_SNDPRIO,&priority,sizeof(priority));
    rc = nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_RCVTIMEO,&timeout,sizeof(timeout));
    rc = nn_setsockopt(lbsock,NN_SOL_SOCKET,NN_SNDTIMEO,&timeout,sizeof(timeout));
    printf("rc.%d from NN_SNDPRIO\n",rc);
    //if ( nn_connect(lbsock,"crypto://127.0.0.1:8883") >= 0 )
    //if ( nn_connect(lbsock,"tcp://127.0.0.1:50447") >= 0 )
    {
        iguana_main("bitcoin","BTC",1); //NODE_NETWORK);
        getchar();
    }
}

/*struct iguana_kvitem *iguana_kvitemptr(struct iguanakv *kv,void *value)
 {
 struct iguana_kvitem *item = 0;
 if ( kv != 0 && value != 0 )
 {
 value = (void *)((long)value - (kv)->keysize);
 item = (void *)((long)value - ((long)item->keyvalue - (long)item));
 }
 return(item);
 }*/

void iguana_savepeers(struct iguana_info *coin)
{
    uint32_t peerind,itemind; struct iguana_peer *addr,space; char ipaddr[64];
    for (peerind=1; peerind<=coin->latest.maxpeers; peerind++)
    {
        if ( iguana_RWmmap(0,&space,coin,coin->peers,peerind) == 0 )
        {
            strcpy(ipaddr,space.ipaddr);
            //printf("peerind.%d -> (%s)\n",peerind,ipaddr);
            if ( (addr= iguana_kvread(coin,&space,&itemind,coin->peers,space.A.ip)) != 0 )
            {
                if ( peerind == itemind )
                {
                    if ( iguana_RWmmap(1,addr,coin,coin->peers,peerind) != 0 )
                        printf("error RWmap.1 peerind.%d -> (%s)\n",peerind,ipaddr);
                } else printf("mismatched peerind.%d vs itemind.%d for (%s)\n",peerind,itemind,ipaddr);
            }
        } else printf("error reading peerind.%d\n",peerind);
    }
    iguana_syncmap(&coin->peers->state.M,0);
}
if ( strcmp("peers",kv->name) == 0 )
{
    struct iguana_peer *addr = (void *)sp->space;
    addr->seen_verack = 0;
    checkip[0] = 0;
    addr->peerind = itemind;
    if ( addr->ipaddr[0] != 0 )
    {
        ipbits = (uint32_t)calc_ipbits(addr->ipaddr);
        expand_ipbits(checkip,ipbits);
    }
    if ( addr->ipaddr[0] == 0 || strcmp(checkip,addr->ipaddr) != 0 )
    {
        printf("bad record.(%s) vs (%s) %d vs %d\n",checkip,addr->ipaddr,addr->peerind,itemind);
        i = keysize;
    }
    else printf("add n.%d skipped.%d (%s) vs (%s).%x i.%d\n",n,skipped,addr->ipaddr,checkip,ipbits,i);
        }

void *iguana_kvsavepeer(struct iguana_info *coin,struct iguanakv *kv,struct iguana_kvitem *item,uint64_t args,void *key,void *value,int32_t valuesize)
{
    FILE *fp = (FILE *)args; struct iguana_peer *addr; uint32_t data[4],ipbits,flag = 0;
    if ( args != 0 && (addr= value) != 0 )
    {
        printf("%p %s iterarg.%d verack.%d killed.%d\n",addr,addr->ipaddr,kv->iterarg,addr->seen_verack,addr->dead);
        if ( kv->iterarg == 0 && addr->seen_verack != 0 )
            flag = 1;
        else if ( kv->iterarg == 1 && addr->dead != 0 )
            flag = 1;
        else if ( kv->iterarg == 2 && (addr->seen_verack == 0 && addr->dead == 0) )
            flag = 1;
        if ( flag != 0 )
        {
            ipbits = (uint32_t)calc_ipbits(addr->ipaddr);
            data[0] = ipbits;
            data[1] = addr->lastcontact;
            data[2] = addr->nStartingHeight;
            data[3] = addr->pingtime;
            if ( fwrite(data,1,sizeof(data),fp) != sizeof(data) )
            {
                printf("Error saving key.[%x]\n",ipbits);
                return(key);
            }
        }
    }
    return(0);
}

long iguana_savepeers(struct iguana_info *coin)
{
    FILE *fp; long retval = -1; int32_t iter; char fname[512],*str = "good";
    for (iter=0; iter<3; iter++)
    {
        coin->peers->iterarg = iter;
        sprintf(fname,"%s.%s",coin->peers->name,str);
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            if ( iguana_kviterate(coin,coin->peers,(uint64_t)fp,iguana_kvsavepeer) == 0 )
            {
                printf("save %ld to HDD\n",ftell(fp));
                retval = ftell(fp);
            }
            else printf("error saving item at %ld\n",ftell(fp));
            fclose(fp);
        } else printf("error creating(%s)\n",fname);
        if ( iter == 0 )
            str = "errpeer";
        else str = "newpeer";
    }
    coin->updatedpeers = 0;
    return(retval);
}

/*void iguana_open_connection(struct iguana_info *coin,char *ipaddr)
 {
 int32_t i,n; struct iguana_peer addrs[10];
 memset(addrs,0,sizeof(addrs));
 n = iguana_connect(addrs,(int32_t)(sizeof(addrs)/sizeof(*addrs)),ipaddr,coin->chain->default_port);
 if ( n > 0 )
 {
 for (i=0; i<n; i++) // almost always n is just 1
 iguana_addpeer(coin,&addrs[i]);
 return;
 }
 }*/

void iguana_updatepeer(struct iguana_info *coin,struct iguana_peer *addr)
{
    printf("UPDATE PEER.(%s) total.%d relayers.%d\n",addr->ipaddr,coin->numpeers,coin->numrelayers);
    iguana_kvwrite(coin,coin->peers,addr->A.ip,addr,sizeof(*addr),(uint32_t *)&addr->peerind);
    coin->updatedpeers++;
}


void *iguana_kvpurgepeer(struct iguana_info *coin,struct iguanakv *kv,struct iguana_kvitem *item,uint64_t args,void *key,void *value,int32_t valuesize)
{
    struct iguana_peer *addr; int32_t lag;
    if ( args != 0 && (addr= value) != 0 && addr->sendtime != 0 )
    {
        if ( (lag= (kv->iteruarg - addr->sendtime)) == 0 )
            lag = 1;
        if ( kv->iterarg == 0 || lag > kv->iterarg )
        {
            kv->iterarg = lag;
            strcpy((char *)args,addr->ipaddr);
        }
    }
    return(0);
}

void *iguana_loop(void *_coin)
{
    struct iguana_info *coin = _coin;
    while ( 1 )
    {
        /*if ( 1 && (ipaddr= queue_dequeue(&coin->newpeersQ,1)) != 0 )
         {
         iguana_open_connection(coin,ipaddr);
         printf("check newpeer.(%s)\n",ipaddr);
         free_queueitem(ipaddr);
         }*/
        sleep(1);
    }
    return(0);
}

void shutdown_daemon(struct iguana_info *coin)
{
    if ( coin->blocks.db != 0 )
    {
        //iguana_kvsave(coin->blocks.db);
        iguana_kvfree(coin,coin->blocks.db);
    }
}

/*if ( coin->numpeers > 16 )
 {
 coin->peers->iteruarg = (uint32_t)time(NULL);
 coin->peers->iterarg = 0;
 if ( iguana_kviterate(coin,coin->peers,(uint64_t)ipaddr,iguana_kvpurgepeer) == 0 )
 printf("lag.%d (%s) peer purged\n",coin->peers->iterarg,ipaddr);
 else printf("error: lag.%d (%s) peer purged\n",coin->peers->iterarg,ipaddr);
 }
 */
//for (iter=0; iter<2; iter++)
{
    fpos = n = m = fixed = skipped = 0;
    if ( (fp= fopen(sp->fname,"rb")) != 0 )
    {
        fseek(fp,fpos,SEEK_SET);
        while ( fread(sp->space,2,valuesize,fp) == valuesize )
        {
            //printf("m.%d\n",m);
            itemind = m++;
            for (i=0; i<keysize; i++)
                if ( ((uint8_t *)sp->space)[kv->keyoffset + i] != 0 )
                    break;
            if ( i != keysize )
            {
                if ( itemind != n )
                {
                    fseek(fp,fpos,SEEK_SET);
                    memset((void *)((long)sp->space + valuesize),0,valuesize);
                    fwrite((void *)((long)sp->space + valuesize),1,valuesize,fp);
                    fseek(fp,(long)n * valuesize,SEEK_SET);
                    fwrite(sp->space,1,valuesize,fp);
                    fixed++;
                    //printf("itemind.%d vs n.%d skipped.%d\n",itemind,n,skipped);
                    itemind = n;
                }
                if ( iter == 1 )
                {
                    iguana_kvwrite(coin,kv,(void *)((long)sp->space + kv->keyoffset),sp->space,valuesize,&itemind);
                }
                n++;
            } skipped++;
            fseek(fp,(long)m * valuesize,SEEK_SET);
        }
        printf("iter.%d fixed.%d %s added %d items, skipped.%d keysize.%d keyoffset.%d valuesize.%d\n",iter,fixed,kv->name,n,skipped,kv->keysize,kv->keyoffset,kv->valuesize);
        fclose(fp);
        //getchar();
    }
}
void iguana_killpeer(struct iguana_info *coin,struct iguana_peer *addr)
{
    if ( addr->seen_verack != 0 )
    {
        addr->dead = 1;
        addr->seen_verack = 0;
        coin->numrelayers -= addr->relayflag;
        coin->numpeers--;
        printf("KILL PEER.(%s) peerind.%u total.%d relayers.%d\n",addr->ipaddr,addr->peerind,coin->numpeers,coin->numrelayers);
        iguana_kvwrite(coin,coin->peers,addr->A.ip,addr,sizeof(*addr),(uint32_t *)&addr->peerind);
        coin->updatedpeers++;
    }
}

/*for (j=0; j<addr->numreferrals; j++)
 if ( ipbits == addr->referrals[j] )
 break;
 if ( j == addr->numreferrals )
 {
 if ( addr->numreferrals < sizeof(addr->referrals)/sizeof(*addr->referrals) )
 addr->referrals[addr->numreferrals++] = ipbits;
 iguana_possible_peer(coin,ipaddr);
 }*/

int32_t iguana_blockchain(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgblock *blk,uint8_t *serialized,bits256 hash2,int32_t checkpointi)
{
    struct iguana_blocks *blocks; double PoW; struct iguana_block *prev,*check,space; int32_t i,height,firsttxidind;
    blocks = &coin->blocks;
    /*if ( (check= iguana_findblock(coin,&space,hash2)) != 0 )
     {
     if ( checkpointi >= 0 && check->height == coin->checktip_heights[checkpointi]+1 )
     {
     coin->checkpointips[checkpointi] = hash2;
     coin->checktip_heights[checkpointi]++;
     coin->rawblocks++;
     printf("iguana_blockchain: duplicate block height.%d checkpointi.%d tipheight.%d rawblocks.%d\n",check->height,checkpointi,coin->checktip_heights[checkpointi],coin->rawblocks);
     }
     return(check->height);
     }
     for (i=0; i<coin->chain->numcheckpoints; i++)
     {
     if ( memcmp(coin->chain->checkpoints_data[i].bytes,hash2.bytes,sizeof(hash2)) == 0 )
     {
     height = coin->chain->checkblocks[i];
     coin->checktip_heights[i] = height;
     printf("checkpointi.%d height.%d rawblocks.%d\n",i,height,coin->rawblocks);
     iguana_addblock(coin,hash2,blk,height,-1,0.); // add to block map, orphans and all
     return(0);
     }
     if ( memcmp(coin->chain->checkpoints_data[i].bytes,blk->H.prev_block.bytes,sizeof(blk->H.prev_block)) == 0 )
     {
     height = coin->chain->checkblocks[i] + 1;
     coin->checktip_heights[i] = height;
     coin->checkpointips[i] = hash2;
     coin->rawblocks++;
     printf("checkpointi.%d height.%d <- (%s) rawblocks.%d\n",i,height,bits256_str(hash2),coin->rawblocks);
     iguana_addblock(coin,hash2,blk,height,-1,0.); // add to block map, orphans and all
     return(0);
     }
     if ( memcmp(coin->checkpointips[i].bytes,blk->H.prev_block.bytes,sizeof(blk->H.prev_block)) == 0 )
     {
     height = ++coin->checktip_heights[i];
     coin->checkpointips[i] = hash2;
     coin->rawblocks++;
     printf("checkpointi.%d height.%d rawblocks.%d\n",i,height,coin->rawblocks);
     iguana_addblock(coin,hash2,blk,height,-1,0.); // add to block map, orphans and all
     return(0);
     }
     }*/
    if ( (prev= iguana_findblock(coin,&space,blk->H.prev_block)) == 0 )
    {
        fprintf(stderr,"iguana_blockchain no prev block.(%s)\n",bits256_str(blk->H.prev_block));
        return(-1);
    }
    else
    {
        height = prev->height + 1;
        PoW = (PoW_from_compact(blk->H.bits) + prev->PoW);
        firsttxidind = (prev->firsttxidind + prev->txn_count);
        if ( PoW <= coin->blocks.best_chain_work )
            height = 0;
    }
    //printf("NEWHT.%d (%s) PoW %.15f prev.%d prevPoW %.15f\n",height,bits256_str(hash2),blk->PoW,prev->height,prev->PoW);
    iguana_addblock(coin,addr,hash2,blk,height,firsttxidind,PoW); // add to block map, orphans and all
    if ( height == 0 )
    {
        printf("%s chain not best\n",bits256_str(hash2));
        return(-1);
    }
    if ( memcmp(blocks->best_chain.bytes,blk->H.prev_block.bytes,sizeof(blocks->best_chain)) != 0 )
    {
        printf("prev.(%s) doesnt connect to previous bestchain\n",bits256_str(blk->H.prev_block));
        printf("mark as orphans from old bestchain.(%s) till it connects to mainchain\n",bits256_str(blocks->best_chain));
        getchar();
    }
    return(height);
}

int32_t iguana_possible_peer(struct iguana_info *coin,char *ipaddr)
{
    struct iguana_peer *space,*addr,addrs[8]; uint32_t i,n,peerind = (uint32_t)-1;
    if ( strncmp("0.0.0",ipaddr,5) != 0 && strcmp("0.0.255.255",ipaddr) != 0 && strcmp("1.0.0.0",ipaddr) != 0 )
    {
        memset(addrs,0,sizeof(addrs));
        n = iguana_connect(addrs,(int32_t)(sizeof(addrs)/sizeof(*addrs)),ipaddr,coin->chain->default_port,0);
        if ( n > 0 )
        {
            for (i=0; i<1; i++) // n is almost always 1
            {
                strcpy(addrs[i].coinstr,coin->name);
                space = calloc(1,sizeof(*space));
                peerind = -1;
                //portable_mutex_lock(&coin->netmutex);
                if ( (addr= iguana_kvread(coin,space,(uint32_t *)&peerind,coin->peers,ipaddr)) == 0 )
                    memcpy(space,&addrs[i],sizeof(*space));
                else if ( addr->usock >= 0 || addr->pending != 0 )
                    break;
                peerind = -1;
                if ( iguana_kvwrite(coin,coin->peers,ipaddr,space,sizeof(*space),(uint32_t *)&peerind) != 0 )
                {
                    //portable_mutex_unlock(&coin->netmutex);
                    //printf("%p %s ADD PEER.(%s) peerind.%u max.%u total.%d relayers.%d numkeys.%d\n",&addrs[i],space->coinstr,space->ipaddr,peerind,coin->latest.maxpeers,coin->numpeers,coin->numrelayers,coin->peers->numkeys);
                    space->coin = coin;
                    if ( coin->numthreads < 3 || (coin->numthreads < IGUANA_MAXPEERS/2 && iguana_metric(space) > coin->avemetric) || (coin->numthreads >= IGUANA_MAXPEERS/2 && coin->numthreads < IGUANA_MAXPEERS) )
                    {
                        peerind = -1;
                        //portable_mutex_lock(&coin->netmutex);
                        if ( (addr= iguana_kvread(coin,space,(uint32_t *)&peerind,coin->peers,ipaddr)) != 0 )
                        {
                            coin->numthreads++;
                            //portable_mutex_unlock(&coin->netmutex);
                            addr->coin = coin;
                            if ( coin->chain->numcheckpoints > 0 )
                                addr->checkpointi = (coin->nextcheckpointi++ % coin->chain->numcheckpoints);
                            else addr->checkpointi = -1;
                            portable_thread_create(iguana_startconnection,addr);
                        } //else portable_mutex_unlock(&coin->netmutex);
                    }
                    //printf("possible.(%s)\n",ipaddr);
                }
                else
                {
                    //portable_mutex_unlock(&coin->netmutex);
                    printf("error writing?\n");
                }
            }
        }
    }
    return(0);
}
/*iguana_send_version(coin,addr,coin->myservices);
 if ( addr->dead == 0 && addr->usock >= 0 )
 {
 printf("connected and version sent to usock.%d (%s) numpings.%d\n",addr->usock,addr->ipaddr,addr->numpings);
 if ( coin->chain->numcheckpoints > 0 )
 addr->checkpointi = (coin->nextcheckpointi++ % coin->chain->numcheckpoints);
 printf("%s uses checkpointi.%d\n",addr->ipaddr,addr->checkpointi);
 //nexti = (coin->chain->numcheckpoints/IGUANA_MAXPEERS) * addr->checkpointi;
 iguana_advancechain(coin,addr,addr->checkpointi);//nexti++ % coin->chain->numcheckpoints);
 }*/

/*iguana_send_version(coin,addr,coin->myservices);
 if ( addr->dead == 0 && addr->usock >= 0 )
 {
 printf("connected and version sent to usock.%d (%s) numpings.%d\n",addr->usock,addr->ipaddr,addr->numpings);
 if ( coin->chain->numcheckpoints > 0 )
 addr->checkpointi = (coin->nextcheckpointi++ % coin->chain->numcheckpoints);
 printf("%s uses checkpointi.%d\n",addr->ipaddr,addr->checkpointi);
 //nexti = (coin->chain->numcheckpoints/IGUANA_MAXPEERS) * addr->checkpointi;
 iguana_advancechain(coin,addr,addr->checkpointi);//nexti++ % coin->chain->numcheckpoints);
 }*/


void iguana_pollconnection(struct iguana_info *coin,struct iguana_peer *addr)
{
    /*if ( addr->last_getblocks < time(NULL) - (24 * 60 * 60) )
     {
     memset(stophash.bytes,0,sizeof(stophash));
     n = iguana_locator(coin,hashes,(int32_t)(sizeof(hashes)/sizeof(*hashes)));
     iguana_send_hashes(coin,addr->protover < GETHEADERS_VERSION ? "getblocks" : "getheaders",addr,stophash,hashes,n);
     printf("send %s to %s\n",addr->protover < GETHEADERS_VERSION ? "getblocks" : "getheaders",addr->ipaddr);
     addr->last_getblocks = time(NULL);
     }*/
}

void iguana_checkpoint(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2,int32_t height)
{
    struct iguana_block block;
    memset(&block,0,sizeof(block));
    block.prev_block = hash2;
    block.height = (height + 1);
    //printf("write (%s) to %d\n",bits256_str(hash2),height+1);
    iguana_RWmmap(1,&block,coin,coin->blocks.db,height+1);
    //iguana_syncmap(coin->blocks.db,0);
}

int32_t iguana_addblockhash(struct iguana_info *coin,struct iguana_peer *addr,int32_t *heightp,bits256 hash2,bits256 nexthash)
{
    struct iguana_block *block,*next,space,nextspace;
    *heightp = -1;
    if ( (block= iguana_findblock(coin,&space,hash2)) != 0 )
    {
        *heightp = block->height;
        if ( (next= iguana_findblock(coin,&nextspace,nexthash)) == 0 )
        {
            iguana_checkpoint(coin,addr,nexthash,block->height + 1);
            //iguana_audit(coin);
            return(0);
        }
        else if ( next->height != block->height + 1 )
        {
            printf("iguana_addblockhash: mismatched next height.%d vs height.%d+1\n",next->height,block->height);
            //iguana_audit(coin);
            return(-1);
        }
        else
        {
            //iguana_audit(coin);
            return(iguana_blockdata(coin,block));
        }
    }
    //iguana_audit(coin);
    return(0);
}


int32_t iguana_advancecmp(bits256 hashes[2],int32_t n,int32_t cmpa,int32_t cmpb)
{
    //printf("n.%d cmpa.%d cmpb.%d\n",n,cmpa,cmpb);
    if ( bits256_nonz(hashes[0]) != 0 && bits256_nonz(hashes[1]) == 0 && (cmpa == 0 || n < cmpa) && (cmpb == 0 || n < cmpb) )
        return(1);
    //printf("failed cmp %d %d %d %d\n",bits256_nonz(hashes[0]) != 0,bits256_nonz(hashes[1]) == 0,(cmpa == 0 || n < cmpa),(cmpb == 0 || n < cmpb));
    return(0);
}

/*void iguana_advancechain(struct iguana_info *coin,struct iguana_peer *addr,int32_t checkpointi)
 {
 bits256 stophash,hashes[10]; int32_t islocal,n = 0; char *cmd = "";
 memset(stophash.bytes,0,sizeof(stophash));
 islocal = (strcmp("127.0.0.1",addr->ipaddr) == 0);
 //printf("blockhash %d, blockhdr.%d block.%d height.%d\n",addr->maxblockhash_height,addr->maxblockhdr_height,addr->maxblock_height,addr->height);
 if ( (islocal != 0 || addr->protover < GETHEADERS_VERSION) && iguana_advancecmp(addr->maxblockhash,addr->maxblockhash_height,addr->maxblockhdr_height+500,addr->height+2000) != 0 )
 {
 printf("request blockhashes islocal.%d\n",islocal);
 cmd = "getblocks";
 addr->maxblockhash[1] = hashes[n++] = coin->blocks.hwmchain;//addr->maxblockhash[0];
 }
 else if ( islocal != 0 && addr->protover >= GETHEADERS_VERSION && iguana_advancecmp(addr->maxblockhdr,addr->maxblockhdr_height,addr->maxblock_height+500,0) != 0 )
 {
 cmd = "getheaders";
 printf("request headers islocal.%d\n",islocal);
 addr->maxblockhdr[1] = hashes[n++] = addr->maxblockhdr[0];
 }
 else if ( memcmp(coin->blocks.hwmchain.bytes,addr->maxblock[1].bytes,sizeof(bits256)) != 0 ) //if ( iguana_advancecmp(addr->maxblock,addr->maxblock_height,addr->height,0) != 0 )
 {
 printf("request data\n");
 addr->maxblock[0] = addr->maxblock[1] = coin->blocks.hwmchain;
 iguana_request_data(coin,addr,coin->blocks.hwmchain,MSG_BLOCK);
 return;
 }
 else
 {
 //printf("nothing to advance %s\n",addr->ipaddr);
 return;
 }
 n = iguana_locator(coin,hashes,(int32_t)(sizeof(hashes)/sizeof(*hashes))-1,checkpointi);
 iguana_send_hashes(coin,cmd,addr,stophash,hashes,n);
 }*/


// got functions

void iguana_gotblockhash(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2,bits256 nexthash,int32_t i,int32_t n)
{
    int32_t height; struct iguana_block space; bits256 hashes[2001];
    /*if ( iguana_addblockhash(coin,addr,&height,hash2,nexthash) == 0 )
     {
     //if ( height > (coin->blocks.hwmheight-10) )
     //   iguana_request_data(coin,addr,nexthash,MSG_BLOCK);
     }
     if ( height > addr->maxblockhash_height )
     {
     addr->maxblockhash_height = height;
     addr->maxblockhash[0] = hash2;
     memset(addr->maxblockhash[1].bytes,0,sizeof(hash2));
     }*/
    //if ( i > 0 )
    //hashes[i-1] = hash2;
    iguana_request_data(coin,addr,&hash2,1,MSG_BLOCK);
    if ( i == n-1 )
    {
        hashes[i] = nexthash;
        iguana_request_data(coin,addr,&nexthash,1,MSG_BLOCK);
        //iguana_request_data(coin,addr,hashes,n,MSG_BLOCK);
        bits256 stophash;
        memset(stophash.bytes,0,sizeof(stophash));
        iguana_send_hashes(coin,"getblocks",addr,stophash,&nexthash,1);
    }
    height = iguana_height(coin,hash2);
    //printf("set gotblockhash.%s %d ht.%d -> %s from %s\n",bits256_str(hash2),height,iguana_height(coin,hash2),bits256_str2(nexthash),addr->ipaddr);
    //iguana_audit(coin);
}

int32_t iguana_gotblockhdr(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgblock *msg,uint8_t *serialized,int32_t len,bits256 hash2,int32_t checkpointi)
{
    int32_t n = 0,height = -1; struct iguana_block space,*block;
    //printf("got gotblockhdr.%s from %s, checkpointi.%d\n",bits256_str(hash2),addr->ipaddr,checkpointi);
    
    if ( (block= iguana_findblock(coin,&space,hash2)) != 0 && block->height < coin->blocks.hwmheight )
        return(block->height - coin->blocks.hwmheight);
    iguana_convblock(&space,msg,-1,0,0.);
    if ( (height= iguana_addblock(coin,addr,hash2,&space)) > 0 )
    {
        n = iguana_lookahead(coin,addr,&hash2,height + 1);
        //printf("lookahead.%d\n",n);
    }
    /*if ( height+1+n > addr->maxblockhdr_height )
     {
     printf("set new maxblockhdr.%d\n",height+1+n);
     addr->maxblockhdr_height = height+1+n;
     addr->maxblockhdr[0] = hash2;
     memset(addr->maxblockhdr[1].bytes,0,sizeof(hash2));
     }*/
    //iguana_audit(coin);
    return(height);
}
int32_t iguana_queue_ramchain(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2,int32_t txind,int32_t numtx,struct iguana_msgtx *tx,bits256 txid)
{
    int32_t height;
    addr->getdatamillis = 0;
    if ( addr != 0 && txind == 0 && (height= iguana_height(coin,hash2)) >= 0 )//&& height >= addr->maxblock_height )
    {
        //printf("got ramchain tx.%s from %s height.%d txind.%d\n",bits256_str(txid),addr!=0?addr->ipaddr:"local",height,txind);
        /*printf("set new maxblock.%d\n",height);
         addr->maxblock_height = height;
         addr->maxblock[0] = hash2;
         memset(addr->maxblock[1].bytes,0,sizeof(hash2));*/
    }
    return(0);
}
void iguana_gottxid(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2)
{
}

int32_t iguana_addblock(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2,struct iguana_block *newblock)
{
    int32_t h;
    //,firsttxidind,txn_count,hwm=0,equivalent = 0;
    //double PoW; struct iguana_block *block,space,prevspace;
    //height = newblock->height, firsttxidind = newblock->firsttxidind, PoW = newblock->PoW;
    //printf("iguana_addblock nBits.%x\n",newblock->bits);
    /*if ( (block= iguana_findblock(coin,&space,hash2)) != 0 )
     {
     if ( height >= 0 )
     {
     if ( height != block->height )
     printf("iguana_addblockhdr: height.%d mismatch vs %d\n",height,block->height);
     } else height = block->height;
     if ( firsttxidind > 0 )
     {
     if ( firsttxidind != block->firsttxidind )
     printf("iguana_addblockhdr: firsttxidind.%d mismatch vs %d\n",firsttxidind,block->firsttxidind);
     } else firsttxidind = block->firsttxidind;
     if ( PoW > SMALLVAL )
     {
     if ( fabs(PoW - block->PoW) > SMALLVAL )
     printf("iguana_addblockhdr: PoW.%.15f mismatch vs %.15f\n",PoW,block->PoW);
     } else PoW = block->PoW;
     if ( (flag= iguana_blockdata(coin,block)) == 0 )
     {
     printf("write out block.(%s) to %d\n",bits256_str(hash2),height);
     iguana_kvwrite(coin,coin->blocks.db,hash2.bytes,newblock,sizeof(*newblock),(uint32_t *)&height);
     }
     else if ( flag > 0 )
     {
     space2 = *block;
     space2.height = newblock->height;
     if ( memcmp(block,&space2,sizeof(*block)) != 0 )
     printf("newblock is different from oldblock (%d %d %f) vs (%d %d %f)\n",newblock->height,newblock->firsttxidind,newblock->PoW,block->height,block->firsttxidind,block->PoW);
     else
     {
     equivalent = 1;
     }
     }
     //printf("newblock (%d %d %f) vs old (%d %d %f)\n",newblock->height,newblock->firsttxidind,newblock->PoW,block->height,block->firsttxidind,block->PoW);
     //iguana_audit(coin);
     }
     if ( memcmp(coin->chain->genesis_hashdata,hash2.bytes,sizeof(hash2)) == 0 )
     {
     PoW = height = txn_count = 0;
     prev = 0;
     firsttxidind = 1;
     hwm = 1;
     block = newblock;
     printf("adding genesis\n");
     }
     else if ( (prev= iguana_findblock(coin,&prevspace,newblock->prev_block)) == 0 )
     {
     printf("hash2.(%s) ",bits256_str(hash2));
     fprintf(stderr,"iguana_blockchain no prev block.(%s)\n",bits256_str(newblock->prev_block));
     getchar();
     return(-1);
     }
     else
     {
     if ( height >= 0 && height != prev->height + 1 )
     printf("iguana_addblock: height.%d != prev.%d+1\n",height,prev->height);
     height = prev->height + 1;
     PoW = prev->PoW;
     firsttxidind = prev->firsttxidind;
     txn_count = prev->txn_count;
     }*/
    if ( (newblock->height= iguana_setchainvars(coin,addr,&newblock->firsttxidind,&newblock->PoW,hash2,newblock->prev_block,newblock->bits,newblock->txn_count)) != (uint32_t)-1 )
    {
        if ( newblock->PoW > coin->blocks.hwmPoW )
        {
            if ( newblock->height+1 > coin->blocks.maxblocks )
                coin->blocks.maxblocks = (newblock->height + 1);
            h = newblock->height;
            iguana_kvwrite(coin,coin->blocks.db,hash2.bytes,newblock,(uint32_t *)&h);
            if ( addr != 0 && newblock->height > addr->height )
                addr->height = newblock->height;
            coin->blocks.hwmheight = newblock->height;
            coin->blocks.hwmPoW = newblock->PoW;
            coin->blocks.hwmchain = hash2;
            coin->latest.blockhash = hash2;
            coin->latest.merkleroot = newblock->merkle_root;
            coin->latest.timestamp = newblock->timestamp;
            coin->latest.numblocks = coin->blocks.hwmheight+1;
            coin->latest.numtxidind = newblock->firsttxidind + newblock->txn_count;
            //iguana_syncmap(coin->blocks.db,0);
            //printf("%s height.%d PoW %f\n",bits256_str(hash2),block->height,block->PoW);
            if ( coin->initblocks != 0 )
                printf("ADD %d:%d:%d <- (%s) n.%u max.%u PoW %f\n",h,iguana_height(coin,coin->blocks.hwmchain),newblock->height,bits256_str(coin->blocks.hwmchain),coin->blocks.hwmheight+1,coin->blocks.maxblocks,newblock->PoW);
        }
    }
    if ( memcmp(hash2.bytes,coin->blocks.hwmchain.bytes,sizeof(hash2)) != 0 )
    {
        printf("ORPHAN.%s height.%d PoW %f vs best %f\n",bits256_str(hash2),newblock->height,newblock->PoW,coin->blocks.hwmPoW);
        newblock->height = -1;
    }
    //iguana_audit(coin);
    return(newblock->height);
}

/*int32_t iguana_locator(struct iguana_info *coin,bits256 *hashes,int32_t max)
 {
 int32_t i,n = 0; bits256 prevhash;
 hashes[n++] = coin->blocks.hwmchain;
 for (i=0; i<max&&n<10; i++)
 {
 prevhash = iguana_prevblockhash(coin,hashes[n-1]);
 if ( bits256_nonz(prevhash) != 0 )
 hashes[n++] = prevhash;
 else break;
 }
 printf("iguana_locator n.%d\n",n);
 return(n);
 }*/

/*bits256 iguana_blockkey(struct iguana_info *coin,struct iguana_block *block)
 {
 struct iguana_block blocks[2]; int32_t i,n; bits256 hash2;
 memset(hash2.bytes,0,sizeof(hash2));
 n = (int32_t)(1 + (coin->blocks.db->keyoffset + coin->blocks.db->keysize) / sizeof(struct iguana_block));
 if ( n > sizeof(blocks)/sizeof(*blocks) || coin->blocks.db->keysize != sizeof(bits256) )
 return(hash2);
 for (i=0; i<n; i++)
 if ( iguana_block(coin,&blocks[i],block->height+i) == 0 )
 return(hash2);
 memcpy(hash2.bytes,(void *)((long)&blocks[0] + coin->blocks.db->keyoffset),coin->blocks.db->keysize);
 return(hash2);
 }*/

int32_t iguana_blockdata(struct iguana_info *coin,struct iguana_block *block)
{
    bits256 key = iguana_blockkey(coin,block);
    if ( block->height+1 >= (coin->blocks.db->state.M.allocsize / sizeof(*block)) || bits256_nonz(key) == 0 )
        return(-1);
    else if ( block->height > 0 && (bits256_nonz(block->prev_block) == 0 || fabs(block->PoW) < SMALLVAL) )
    {
        printf("iguana_blockdata height.%d \n",block->height);
        return(0);
    }
    if ( block->firsttxidind > 0 )
        return(1);
    return(-1);
}
/*space = mycalloc(1,sizeof(*space));
 if ( (addr= iguana_kvread(coin,space,(uint32_t *)&peerind,coin->peers,ipaddr)) == 0 )
 {
 memcpy(space,&addrs[i],sizeof(*space));
 addr = space;
 iguana_clear_addrstate(coin,addr);
 }
 else if ( addr->usock >= 0 || addr->pending != 0 || addr->dead != 0 )
 {
 printf("%s usock.%d pending.%u dead.%d\n",addr->ipaddr,addr->usock,addr->pending,addr->dead);
 break;
 }
 addr->lastcontact = (uint32_t)time(NULL);
 if ( coin->numthreads < IGUANA_MAXTHREADS )//&& (coin->numactive < 3 || (coin->numactive < IGUANA_MAXPEERS/2 && iguana_metric(space) > coin->avemetric) || (coin->numactive >= IGUANA_MAXPEERS/2 && coin->numactive < IGUANA_MAXPEERS)) )
 {
 addr->pending = (uint32_t)time(NULL);
 addr->coin = coin;
 peerind = -1;
 iguana_kvwrite(coin,coin->peers,ipaddr,addr,(uint32_t *)&peerind);
 portable_thread_create(iguana_startconnection,addr);
 } else*/

{
    int32_t valuesize; void *checkptr;
    valuesize = iguana_valuesize(coin,kv);
    memset(kv->state.space,0,kv->RAMvaluesize);
    checkptr = kv->state.space;
    if ( (kv->flags & IGUANA_MAPPED_ITEM) != 0 )
    {
        value = (void *)((long)value + sizeof(UT_hash_handle));
        checkptr = (void *)((long)checkptr + sizeof(UT_hash_handle));
    }
    if ( iguana_RWmmap(0,kv->state.space,coin,kv,*itemindp) != 0 || memcmp(value,checkptr,valuesize) != 0 )
    {
        printf("iguana_RWmmap data mismatch after kvwrite\n");
        getchar();
    }
    
}
/*init_hexbytes_noT(hexstr,pk_script+1,pk_script[0]);
 //printf("(%s).%02x ",hexstr,pk_script[pk_script[0]]);
 if ( 1 && pk_script[1] == 4 )
 {
 pk[0] = 2 + (pk_script[pk_script[0]] & 1);
 memcpy(pk+1,pk_script+2,32);
 init_hexbytes_noT(hexstr,pk,33);
 printf("data.(%s).%d ",hexstr,pk_script[0]);
 vcalc_sha256(0,sha256,pk,33);
 calc_rmd160(0,rmd160,sha256,sizeof(sha256));
 init_hexbytes_noT(hexstr,rmd160,20);
 printf("rmd.(%s) ",hexstr);
 //decode_hex(rmd160,20,"e34498597d0d4d4be05db1bb7501da985e15aaa5");
 btc_convrmd160(coinaddr,coin->chain->addr_pubkey,rmd160);
 printf("(%s)\n",coinaddr);
 }*/
/*int32_t iguana_possible_peer(struct iguana_info *coin,char *ipaddr)
 {
 struct iguana_peer *addr=0,addrs[8]; uint32_t i,n;
 #ifdef IGUANA_DISABLEPEERS
 if ( strcmp(ipaddr,"127.0.0.1") != 0 )
 return(0);
 #endif
 if ( strncmp("0.0.0",ipaddr,5) != 0 && strcmp("0.0.255.255",ipaddr) != 0 && strcmp("1.0.0.0",ipaddr) != 0 )
 {
 //printf("possible peer.(%s)\n",ipaddr);
 memset(addrs,0,sizeof(addrs));
 n = iguana_connect(addrs,(int32_t)(sizeof(addrs)/sizeof(*addrs)),ipaddr,coin->chain->default_port,0);
 if ( n > 0 )
 {
 for (i=0; i<1; i++) // n is almost always 1
 {
 strcpy(addrs[i].coinstr,coin->name);
 addr = mycalloc('p',1,sizeof(*addr));
 *addr = addrs[i];
 iguana_clear_peerstate(coin,addr);
 queue_enqueue("connectionQ",&coin->peers.connectionQ,&addr->DL);
 return(0);
 }
 }
 }
 if ( addr != 0 )
 myfree(addr,sizeof(*addr));
 return(0);
 }*/
/*{
 for (i=0; i<n; i++)
 {
 //printf("%p coinstr.(%s)\n",coin,coin->name);
 //if ( addr->ipv6 != 0 )
 //    err = iguana_connectsocket(1,addr,(struct sockaddr *)&addr->saddr6,sizeof(addr->saddr6));
 //else err = iguana_connectsocket(1,addr,(struct sockaddr *)&addr->saddr4,sizeof(addr->saddr4));
 if ( err < 0 )
 {
 fprintf(stderr,"close connect %s: %s numpings.%d\n",addr->ipaddr,strerror(-err),addr->numpings);
 iguana_iAkill(coin,addr);
 }
 else
 {
 iguana_iAconnected(coin,addr);
 addr->ready = (uint32_t)time(NULL);
 }
 }
 }*/
void iguana_clear_peerstate(struct iguana_info *coin,struct iguana_peer *addr)
{
    addr->usock = -1;
    addr->pingnonce = 0;
    addr->ready = addr->dead = addr->pending = 0;
    addr->startsend = addr->startrecv = 0;
    addr->bufsize = 0; addr->buf = 0;
    strcpy(addr->symbol,coin->symbol);
    strcpy(addr->coinstr,coin->name);
    //memset(&addr->DL,0,sizeof(addr->DL));
    //memset(&addr->sendQ,0,sizeof(addr->sendQ));
    //memset(&addr->msgcounts,0,sizeof(addr->msgcounts));
}

/**/
/*
 void iguana_activate(struct iguana_info *coin,struct iguana_peer *addr)
 {
 int32_t i;//,peerind = -1;
 if ( coin->peers.numactive > 0 )
 {
 for (i=0; i<coin->peers.numactive; i++)
 if ( strcmp(coin->peers.active[i].ipaddr,addr->ipaddr) == 0 )
 break;
 if ( i != coin->peers.numactive )
 {
 printf("duplicate activation.%s rejected\n",addr->ipaddr);
 return;
 }
 }
 coin->peers.active[coin->peers.numactive] = *addr;
 myfree(addr,sizeof(*addr));
 addr = &coin->peers.active[coin->peers.numactive++];
 iguana_send_version(coin,addr,coin->myservices);
 printf("ACTIVE.%d peer.(%s) numthreads.%d\n",coin->peers.numactive,addr->ipaddr,coin->numthreads);
 //if ( strcmp(addr->ipaddr,"127.0.0.1") == 0 )
 //   portable_thread_create(iguana_localhost,addr);
 }
 
 void iguana_connections(struct iguana_info *coin)
 {
 int32_t i,j,firsti,peerind; uint32_t ipbits; struct iguana_peer *addr;
 if ( coin->numthreads < IGUANA_MAXTHREADS && (addr= queue_dequeue(&coin->peers.connectionQ,0)) != 0 )
 {
 if ( addr->pending == 0 )
 {
 for (i=0; i<sizeof(coin->peers.active)/sizeof(*coin->peers.active); i++)
 if ( strcmp(coin->peers.active[i].ipaddr,addr->ipaddr) == 0 )
 break;
 if ( i == coin->peers.numactive )
 {
 if ( coin->peers.numpending < sizeof(coin->peers.pending)/sizeof(*coin->peers.pending) )
 {
 ipbits = (uint32_t)calc_ipbits(addr->ipaddr);
 firsti = -1;
 for (i=0; i<sizeof(coin->peers.pending)/sizeof(*coin->peers.pending); i++)
 {
 if ( coin->peers.pending[i] == 0 )
 firsti = i;
 else if ( coin->peers.pending[i] == ipbits )
 break;
 }
 if ( i == sizeof(coin->peers.pending)/sizeof(*coin->peers.pending) )
 {
 printf("PENDING.%-16s pending.%u ready.%u numpending.%d\n",addr->ipaddr,addr->pending,addr->ready,coin->numiAddrs);
 coin->peers.pending[firsti] = ipbits;
 addr->pending = (uint32_t)time(NULL);
 strcpy(addr->symbol,coin->symbol);
 iguana_launch(coin,"connection",iguana_startconnection,addr,0);
 }
 }
 queue_enqueue("retryQ",&coin->peers.retryQ,&addr->DL);
 }
 }
 else
 {
 if ( addr->ready != 0 )
 iguana_activate(coin,addr);
 else if ( addr->dead == 0 )
 queue_enqueue("retryQ",&coin->peers.retryQ,&addr->DL);
 }
 }
 }*/

//printf("parsed.%d firstvout.%d+%d firstvin.%d+%d: %s got.%d %s v %d\n",coin->blocks.parsedblocks,block->firstvout,block->numvouts,block->firstvin,block->numvins,addr->ipaddr,block->height,bits256_str(block->hash2),coin->blocks.hwmheight);
/*if ( block->height == coin->blocks.parsedblocks )
 iguana_parseblock(coin,block,tx,numtx);
 else
 {
 printf("height.%d vs parsed.%d hwm.%d\n",block->height,coin->blocks.parsedblocks,coin->blocks.hwmheight);
 iguana_addpending(coin,addr->ipbits,block,tx,numtx);
 }*/

int32_t iguana_polliter(struct iguana_info *coin)
{
    struct pollfd fds[IGUANA_MAXPEERS];
    struct iguana_peer *addr,*addrs[IGUANA_MAXPEERS];
    int32_t i,n,nonz,flag,timeout=10;
    memset(fds,0,sizeof(*fds));
    memset(addrs,0,sizeof(*addrs));
    flag = 0;
    for (i=n=nonz=0; i<IGUANA_MAXPEERS; i++)
    {
        addr = &coin->peers.active[i];
        fds[i].fd = -1;
        if ( addr->usock < 0 || addr->dead != 0 || addr->ready == 0 )
        {
            if ( addr->pending == 0 )
                addrs[n++] = addr;
            continue;
        }
        if ( addr->startrecv == 0 )
        {
            fds[i].fd = addr->usock;
            fds[i].events |= POLLIN;
            nonz++;
        }
    }
    if ( nonz != 0 && poll(fds,IGUANA_MAXPEERS,timeout) > 0 )
    {
        for (i=0; i<IGUANA_MAXPEERS; i++)
        {
            addr = &coin->peers.active[i];
            if ( addr->usock < 0 || addr->dead != 0 || addr->ready == 0 )
                continue;
            //if ( addr->usock >= 0 && addr->ready > 0 )
            //    printf("%d/%d %d/%d startrecv.%u usock.%d dead.%d ready.%u\n",fds[i].events,fds[i].fd,POLLIN,POLLOUT,addr->startrecv,addr->usock,addr->dead,addr->ready);
            if ( addr->startrecv == 0 && (fds[i].revents & POLLIN) != 0 )
            {
                void iguana_processmsg(void *ptr);
                flag++;
                strcpy(addr->symbol,coin->symbol);
                if ( 0 )
                {
                    addr->startrecv = (uint32_t)time(NULL);
                    iguana_launch("processmsg",iguana_processmsg,addr,0);
                } else iguana_processmsg(addr);
            }
        }
    }
    return(flag);
}

int32_t oldiguana_getdata(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct iguana_overlap *ov = &addr->OV;
    int32_t height,flag,elapsed,j,n = 0; bits256 hash2; double reqpsec,kbpsec;
    //printf("iguana_getdata.(%s) ov.%p %p\n",addr->ipaddr,ov,addr);
    //printf("addr height.%d vs parsed.%d\n",addr->height,coin->blocks.parsedblocks);
    if ( ov->overlap == 0 )
    {
        if ( strcmp("127.0.0.1",addr->ipaddr) == 0 )
            ov->overlap = IGUANA_MAXOVERLAP/2;
        else ov->overlap = IGUANA_MAXOVERLAP/8;
        iguana_teststart(coin,addr);
    }
    if ( addr != 0 && addr->dead == 0 && addr->usock >= 0 && addr->height >= coin->blocks.parsedblocks )
    {
        for (flag=0; flag<ov->overlap; flag++)
        {
            if ( addr->waiting[flag] == 0 )
            {
                for (height=coin->blocks.parsedblocks; height<coin->longestchain&&height<coin->blocks.parsedblocks+IGUANA_MAXPENDING; height++)
                {
                    if ( coin->recvblocks != 0 && coin->recvblocks[height] != 0 )
                        continue;
                    if ( strcmp("127.0.0.1",addr->ipaddr) == 0 )
                    {
                        if ( height > coin->blocks.parsedblocks+IGUANA_MAXPENDING/2 )
                        {
                            if ( n == 0 )
                            {
                                hash2 = iguana_blockhash(coin,coin->blocks.parsedblocks);
                                iguana_request_data(coin,addr,&hash2,1,MSG_BLOCK);
                            }
                            return(n);
                        }
                    }
                    else
                    {
                        if ( height < coin->blocks.parsedblocks+IGUANA_MAXPENDING/2 )
                            continue;
                    }
                    hash2 = iguana_blockhash(coin,height);
                    for (j=0; j<IGUANA_MAXOVERLAP; j++)
                        if ( memcmp(addr->waitinghash[j].bytes,hash2.bytes,sizeof(hash2)) == 0 )
                            break;
                    if ( j != sizeof(addr->waitinghash)/sizeof(*addr->waitinghash) )
                        continue;
                    if ( height < coin->numwaitingbits && GETBIT(coin->waitingbits,height) == 0 )
                    {
                        if ( bits256_nonz(hash2) != 0 )
                        {
                            addr->waiting[flag] = (uint32_t)time(NULL);
                            addr->waitinghash[flag] = hash2;
                            if ( ov->numreqs++ >= ov->overlap )
                            {
                                if ( ov->numreqs == ov->overlap )
                                    ov->numreqs = ov->overlap;
                                elapsed = (uint32_t)(time(NULL) - ov->teststart) + 1;
                                reqpsec = (double)ov->numreqs / elapsed;
                                kbpsec = (double)ov->reqrecv / (1024 * elapsed);
                                dxblend(&ov->Rsec,reqpsec,0.99);
                                dxblend(&ov->KBsec,kbpsec,0.99);
                                if ( kbpsec*reqpsec >= (ov->Rsec * ov->KBsec) )
                                    ov->faster++;
                                else ov->slower++;
                                if ( ((ov->faster + ov->slower) % 1000) == 0 )
                                    printf("OV.%-2d i.%-2d +%-4d -%-4d | h.%d %u | %5.1f/sec %5.3f/kB vs %5.1f/sec %5.3f/kB %5.1f %s\n",ov->overlap,flag,ov->faster,ov->slower,height,addr->waiting[flag],ov->Rsec,ov->KBsec,reqpsec,kbpsec,reqpsec*kbpsec-ov->Rsec*ov->KBsec,addr->ipaddr);
                                if ( time(NULL) > ov->teststart+60 || (ov->faster+ov->slower > ov->overlap*2 && ov->faster > 10*ov->slower) )
                                    iguana_teststart(coin,addr);
                                elapsed = (uint32_t)(time(NULL) - coin->starttime) + 1;
                                reqpsec = (double)coin->totalpackets / elapsed;
                                kbpsec = (double)coin->totalrecv / (1024 * elapsed);
                                dxblend(&coin->Rsec,reqpsec,0.99);
                                dxblend(&coin->KBsec,kbpsec,0.99);
                            }
                            n++;
                            //printf("request.%d bit.%d\n",height,GETBIT(coin->waitingbits,height));
                            iguana_request_data(coin,addr,&hash2,1,MSG_BLOCK);
                            SETBIT(coin->waitingbits,height);
                            break;
                        }
                    }
                }
            }
        }
    }
    if ( strcmp(addr->ipaddr,"127.0.0.1") == 0 && n == 0 && coin->recvblocks != 0 && coin->recvblocks[height] == 0 )
    {
        hash2 = iguana_blockhash(coin,coin->blocks.parsedblocks);
        iguana_request_data(coin,addr,&hash2,1,MSG_BLOCK);
    }
    return(n);
    //printf("full.%d numactive.%d hwm.%d\n",coin->fullblocks,coin->numactive,coin->blocks.hwmheight);
}

void iguana_teststart(struct iguana_info *coin,struct iguana_peer *addr)
{
    static uint32_t lastdisp;
    int32_t dir; struct iguana_overlap *ov = &addr->OV;
    dir = (ov->overlap - ov->prevoverlap);
    ov->prevoverlap = ov->overlap;
    if ( dir != 0 )
    {
        if ( time(NULL) > lastdisp+60 )
        {
            lastdisp = (uint32_t)time(NULL);
            printf("ov.%-2d M%4.1f-> %5.1f/sec %6.2f/kb M%4.1f |fast.%-3d vs slow.%-3d d.%-2d | ",ov->overlap,ov->prevmetric,ov->Rsec,ov->KBsec,ov->Rsec*ov->KBsec,ov->faster,ov->slower,dir);
            printf("all %5.1f/sec, %6.2fKB %s\n",coin->Rsec,coin->KBsec,addr->ipaddr);
        }
        if ( ov->faster > ov->slower )
        {
            if ( (dir > 0 && ov->overlap < IGUANA_MAXOVERLAP) || (dir < 0 && ov->overlap > 1) )
                ov->overlap += dir;
            //else printf("max overlap\n");
            //printf("increase by dir.%d -> overlap.%d\n",dir,addr->overlap);
        }
        else if ( dir > 0 && ov->overlap > 1 )
        {
            ov->overlap--;
            //printf("since slower, reduce overlap to overlap.%d\n",addr->overlap);
        }
        else if ( dir < 0 && ov->overlap < IGUANA_MAXOVERLAP )
        {
            ov->overlap++;
            //printf("since faster, increase overlap to overlap.%d\n",addr->overlap);
        }
        //else printf("at lowest overlap, cant change\n");
        ov->prevmetric = (ov->Rsec * ov->KBsec);
        ov->reqrecv = 0;
        ov->numreqs = -ov->overlap;
        ov->faster = ov->slower = 0;
    }
    else ov->overlap = 1;
    ov->teststart = (uint32_t)time(NULL);
}

void iguana_localhost(void *ptr)
{
    struct iguana_info *coin; struct iguana_peer *addr = ptr;
    if ( addr != 0 && (coin= iguana_coin(addr->symbol)) != 0 )
    {
        while ( addr->dead == 0 )
            _iguana_processmsg(coin,addr);
    }
}
if ( (num= iguana_available(coin,availables)) > 0 )
{
    if ( (addr= availables[0]) != 0 )
    {
        m = iguana_needed(coin,coin->need[0],IGUANA_MAXPENDING/2,0);
        n = iguana_needed(coin,coin->need[1],IGUANA_MAXPENDING/2,IGUANA_MAXPENDING/2);
        if ( strcmp(addr->ipaddr,"127.0.0.1") == 0 || num == 1 )
        {
            //printf("m.%d n.%d num.%d\n",m,n,num);
            for (i=0; i<m; i++)
            {
                height = coin->need[0][i];
                //printf("%d ",height);
                hash2 = iguana_blockhash(coin,height);
                iguana_request_data(coin,addr,&hash2,1,MSG_BLOCK);
                SETBIT(coin->waitingbits,height);
            }
            if ( num > 1 )
            {
                for (i=0; i<n; i++)
                {
                    height = coin->need[1][i];
                    //printf("%d ",height);
                    hash2 = iguana_blockhash(coin,height);
                    iguana_request_data(coin,availables[(i+1) % (num-1)],&hash2,1,MSG_BLOCK);
                    SETBIT(coin->waitingbits,height);
                }
            }
        }
        else
        {
            for (i=0; i<m; i++)
            {
                height = coin->need[0][i];
                //printf("%d ",height);
                hash2 = iguana_blockhash(coin,height);
                iguana_request_data(coin,availables[i % num],&hash2,1,MSG_BLOCK);
                SETBIT(coin->waitingbits,height);
            }
        }
        if ( 0 && m+n > 0 )
            printf("requests\n");
        /*if ( m == 0 )
         sleep(3);
         if ( m+n == 0 )
         sleep(10);*/
            return(m+n);
    } else printf("null available[0]\n");
        }

int32_t iguana_needed(struct iguana_info *coin,int32_t *need,int32_t max,int32_t offset)
{
    int32_t nonz,m,height;
    if ( coin->recvblocks == 0 )
        return(0);
    nonz = m = 0;
    memset(need,0,sizeof(*need) * max);
    if ( (time(NULL) - coin->parsetime) > 3 )
        need[m++] = coin->blocks.parsedblocks;
    for (height=coin->blocks.parsedblocks+offset; height<coin->longestchain&&height<coin->blocks.parsedblocks+max+offset; height++)
    {
        if ( coin->recvblocks[height] != 0 )
            nonz++;
        else if ( GETBIT(coin->waitingbits,height) == 0 )
            need[m++] = height;
    }
    return(m);
}

int32_t iguana_available(struct iguana_info *coin,struct iguana_peer *availables[IGUANA_MAXPEERS])
{
    int32_t j,n; struct iguana_peer *addr;
    memset(availables,0,sizeof(*availables) * IGUANA_MAXPEERS);
    for (j=n=0; j<IGUANA_MAXPEERS; j++)
    {
        addr = &coin->peers.active[j];
        if ( addr->height < coin->blocks.parsedblocks || addr == coin->localaddr )
            continue;
        if ( addr->usock >= 0 && addr->dead == 0 && addr->ready > 0 && iguana_updatewaiting(coin,addr) > 0 )
            availables[n++] = addr;
    }
    return(n);
}

/*int32_t iguana_loadtx(struct iguana_info *coin,struct iguana_peer *addr,bits256 *blockhashp,int32_t txind,int32_t numtx,struct iguana_msgtx *tx,uint8_t *data,int32_t maxsize)
 {
 int32_t len; bits256 txid;
 memset(tx,0,sizeof(*tx));
 len = iguana_rwtx(0,data,tx,maxsize,&txid);
 if ( blockhashp != 0 )
 {
 //printf("parse.(%s)\n",bits256_str(*blockhashp));
 //if ( (blocknum= iguana_height(coin,*blockhashp)) >= 0 )
 if ( iguana_queue_ramchain(coin,addr,*blockhashp,txind,numtx,tx,txid) > 0 )
 return(len);
 //else printf("cant find blockhash.(%s)\n",bits256_str(*blockhashp));
 }
 iguana_purgetx(tx,0);
 return(len);
 }*/
/*for (i=0; i<sizeof(addr->waiting)/sizeof(*addr->waiting); i++)
 {
 if ( addr->waiting[i] != 0 && time(NULL) > (addr->waiting[i] + 60) )
 {
 if ( (height= iguana_height(coin,addr->waitinghash[i])) >= 0 )
 {
 printf("i.%d of %ld ipbits.%x timeout.%s height.%d\n",i,sizeof(addr->waiting)/sizeof(*addr->waiting),addr->ipbits,addr->ipaddr,height);
 CLEARBIT(coin->waitingbits,height);
 }
 addr->waiting[i] = 0;
 addr->waitinghash[i] = bits256_zero;
 }
 if ( addr->waiting[i] == 0 )
 n++;
 }*/

void *iguana_kvmetriciterator(struct iguana_info *coin,struct iguanakv *kv,struct iguana_kvitem *item,uint64_t args,void *key,void *value,int32_t valuesize)
{
    struct iguana_peer *addr = value; double *sortbuf = (double *)args;
    if ( addr->numpings > 0 && addr->pingsum > SMALLVAL && item->hh.itemind < kv->numkeys )
    {
        //printf("%p (%s).%d ind.%d msgs.%d pings.%d %.0fms [%.3f] last.%u lag.%d S.%llu R.%llu\n",sortbuf,addr->ipaddr,addr->usock,item->itemind,addr->numpackets,addr->numpings,addr->pingtime,addr->pingsum/addr->numpings,addr->lastcontact,kv->iteruarg - addr->lastcontact,(long long)addr->totalsent,(long long)addr->totalrecv);
        sortbuf = &sortbuf[item->hh.itemind << 1];
        sortbuf[0] = iguana_metric(addr);
        sortbuf[1] = item->hh.itemind;
    }
    return(0);
}

int32_t iguana_sendrequests(struct iguana_info *coin,struct iguana_peer *addrs[],int32_t n,int32_t *blocks,int32_t m)
{
    int32_t i,height; bits256 hash2;
    if ( n > 0 && m > 0 )
    {
        for (i=0; i<m; i++)
        {
            height = blocks[i];
            hash2 = iguana_blockhash(coin,height);
            iguana_request_data(coin,addrs[i % n],&hash2,1,MSG_BLOCK);
            SETBIT(coin->waitingbits,height);
        }
        return(m);
    }
    return(0);
}
int32_t iguana_getdata(struct iguana_info *coin)
{
    int32_t reqs[IGUANA_READAHEAD],height,i,j,m,readahead,offset,numpeers,limit,n = 0;  struct iguana_peer *addr,*addrs[IGUANA_MAXPEERS];
    if ( coin->R.waitingbits == 0 || coin->R.recvblocks == 0 )
        return(0);
    capacity = iguana_capacity(coin,&numpeers,addrs);
    if ( numpeers == 0 )
        return(0);
    if ( capacity < numpeers )
        capacity = numpeers;
    else if ( capacity > IGUANA_READAHEAD )
        capacity = IGUANA_READAHEAD;
    readahead = (coin->longestchain - coin->blocks.parsedblocks) / numpeers;
    for (j=m=0; j<IGUANA_MAXPEERS; j++)
    {
        //if ( coin->numwaiting > IGUANA_MAXWAITING ) makes it worse
        //    break;
        if ( coin->peers.numranked == 0 )
            addr = &coin->peers.active[j];
        else
        {
            if ( j >= coin->peers.numranked )
                break;
            if ( (addr= coin->peers.ranked[j]) == 0 )
                continue;
        }
        if ( addr->recvblocks == 0 )
            limit = 1;
        else
        {
            if ( addr == coin->peers.localaddr )
                limit = IGUANA_BUNDLESIZE;
            else limit = addr->rank <= 0 ? 1 : (IGUANA_BUNDLESIZE / sqrt(addr->rank));
            if ( limit < 1 )
                limit = 1;
        }
        height = coin->blocks.parsedblocks;
        if ( readahead < 1 )
            readahead = 1;
        if ( readahead > IGUANA_READAHEAD )
            readahead = IGUANA_READAHEAD;
        if ( addr->rank >= 0 && addr->ready > 0 && addr->usock >= 0 && addr->dead == 0 && addr->height > 0 )
        {
            m++;
            //printf("%s: addrht.%d %s p.%d getbit.%d rank.%d\n",addr->ipaddr,addr->height,addr->ipaddr,height,GETBIT(coin->waitingbits,height),addr->rank);
            for (i=n=0; i<100000&&n<limit; i++)
            {
                offset = (((addr->rank > 0) ? addr->rank-1 : m)) * readahead;
                height = (coin->blocks.parsedblocks + offset + i);
                if ( height > coin->blocks.hwmheight || height > addr->height )
                {
                    //printf("%s: height.%d > hwm.%d || addr %d\n",addr->ipaddr,height,coin->blocks.hwmheight,addr->height);
                    break;
                }
                if ( coin->R.numwaiting > IGUANA_MAXWAITING && height > coin->blocks.parsedblocks+100 )
                    break;
                if ( iguana_waitstart(coin,height,addr) == 0 )
                {
                    //printf("%-15s request block.%-6d parsed.%-6d offset.%-4d rank.%-3d numpeers.%d numwaiting.%d\n",addr->ipaddr,height,coin->blocks.parsedblocks,offset,addr->rank,numpeers,coin->R.numwaiting);
                    n++;
                }
            }
        }
    }
    return(n);
}

/*else if ( time(NULL) > coin->parsetime+1 )
 {
 coin->parsetime = (uint32_t)time(NULL);
 printf("backstop.%d %s\n",coin->blocks.parsedblocks,bits256_str(iguana_blockhash(coin,coin->blocks.parsedblocks)));
 iguana_waitclear(coin,coin->blocks.parsedblocks);
 iguana_waitstart(coin,coin->blocks.parsedblocks,0);
 iguana_updatewaiting(coin,coin->blocks.parsedblocks+1,100);
 }
 //else printf("ptr.%p height.%d\n",ptr,height);*/


/*if ( coin->blocks.parsedblocks > initialheight )
 initialheight = coin->blocks.parsedblocks;
 if ( coin->longestchain > initialheight )
 initialheight = coin->longestchain;
 iguana_recvinit(coin,coin->R.numwaitingbits);*/
//height = (coin->blocks.hwmheight / IGUANA_HDRSCOUNT) * IGUANA_HDRSCOUNT;
//iguana_queuehdrs(coin,height,iguana_blockhash(coin,height));

int32_t iguana_rwunspentind(struct iguana_info *coin,int32_t rwflag,struct iguana_unspent *U,uint32_t unspentind)
{
    if ( rwflag == 0 )
    {
        memset(U,0,sizeof(*U));
        if ( iguana_kvread(coin,coin->unspents,0,U,&unspentind) != 0 )
            return(0);
        else printf("error getting unspents[%u] when %d\n",unspentind,coin->latest.numunspents);
    }
    else if ( iguana_kvwrite(coin,coin->unspents,0,U,&unspentind) != 0 )
        return(0);
    return(-1);
}
void iguana_requests(void *arg)
{
    int32_t flag,i,j,n; double sum; struct iguana_peer *addr; struct iguana_info *coin,**coins = arg;
    n = (int32_t)coins[0];
    coins++;
    printf("iguana_requests N.%d\n",n);
    while ( 1 )
    {
        for (i=0; i<n; i++)
        {
            if ( (coin= coins[i]) != 0 )
            {
                //portable_mutex_lock(&coin->blocks.mutex);
                //if ( iguana_avail(coin,coin->blocks.parsedblocks,10000) < 10000 )
                else printf("skip getting data max packets allocated %s\n",mbstr(sum));
                //portable_mutex_unlock(&coin->blocks.mutex);
            }
        }
        if ( flag == 0 )
            usleep((uint32_t)coin->sleeptime + 1);
    }
}
else
{
    if ( coin->peers.numranked > 0 && time(NULL) > coin->backstop )
    {
        int32_t i; bits256 hash2; struct iguana_peer *addr;
        i = (rand() % coin->peers.numranked);
        hash2 = iguana_blockhash(coin,coin->blocks.parsedblocks);
        addr = coin->peers.ranked[i];
        if ( addr != 0 && memcmp(hash2.bytes,addr->backstop.bytes,sizeof(hash2)) != 0 )
        {
            iguana_waitclear(coin,coin->blocks.parsedblocks);
            if ( addr != 0 )
            {
                iguana_waitstart(coin,coin->blocks.parsedblocks,addr);
                printf("%s BACKSTOP.%d\n",addr->ipaddr,coin->blocks.parsedblocks);
                coin->backstop = (uint32_t)time(NULL);
            }
        }
    }
    /*if ( iguana_waitstart(coin,coin->blocks.parsedblocks,addr) == 0 )
     {
     printf("backstop request.%d to %s\n",coin->blocks.parsedblocks,addr->ipaddr);
     addr->backstop = hash2;
     }*/
    //printf("%s skip %d vs %d ptr.%p\n",addr->ipaddr,coin->blocks.parsedblocks,coin->numwaitingbits,ptr);
}

bits256 iguana_histo(struct iguana_info *coin)
{
    double sum = 0.; int32_t i; bits256 seed;
    for (i=0; i<0x100; i++)
        sum += coin->R.histo[i];
    sum /= i;
    memset(seed.bytes,0,sizeof(seed));
    if ( sum > 0. )
    {
        for (i=0; i<0x100; i++)
        {
            printf("%.2f ",coin->R.histo[i]/sum);
            if ( coin->R.histo[i] > sum )
                SETBIT(seed.bytes,i);
        }
    }
    printf("histo.(%s)\n",bits256_str(seed));
    return(seed);
}
struct iguana_state
{
    //char name[16];
    uint8_t sha256[256 >> 3]; struct sha256_vstate state;
    //struct iguana_mappedptr M; struct iguana_space MEM; //queue_t writeQ; portable_mutex_t ;
    void *table;
    //FILE *fp; uint8_t *space;
    //uint64_t maxitems; //uint32_t itemsize,flags;
};
/*struct iguana_overlap
 {
 double KBsec,Rsec,prevmetric;
 uint64_t reqrecv;
 uint32_t teststart;
 int32_t numreqs,overlap,faster,slower,prevoverlap;
 };*/


int32_t iguana_capacity(struct iguana_info *coin,int32_t *nump,struct iguana_peer *addrs[IGUANA_MAXPEERS])
{
    struct iguana_peer *addr; int32_t i,n,capacity = 0;
    for (i=n=0; i<IGUANA_MAXPEERS; i++)
    {
        addr = &coin->peers.active[i];
        //if ( addr->usock >= 0 )
        //    printf("%s ht.%d\n",addr->ipaddr,addr->height);
        if ( addr->ready > 0 && addr->dead == 0 && addr->usock >= 0 && addr->height > coin->blocks.parsedblocks )
        {
            capacity += addr->capacity;
            addrs[n++] = addr;
        }
    }
    *nump = n;
    return(capacity);
}

int32_t iguana_getdata(struct iguana_info *coin)
{
    int32_t reqs[IGUANA_READAHEAD],height,i,j,m,readahead,offset,numpeers,limit,n = 0;  struct iguana_peer *addr,*addrs[IGUANA_MAXPEERS];
    if ( coin->R.waitingbits == 0 || coin->R.recvblocks == 0 )
        return(0);
    for (i=numpeers=0; i<IGUANA_MAXPEERS; i++)
        if ( coin->peers.active[i].usock < 0 )
            numpeers++;
    if ( numpeers == 0 )
        return(0);
    readahead = (coin->longestchain - coin->blocks.parsedblocks) / numpeers;
    for (j=m=0; j<IGUANA_MAXPEERS; j++)
    {
        //if ( coin->numwaiting > IGUANA_MAXWAITING ) makes it worse
        //    break;
        if ( coin->peers.numranked == 0 )
            addr = &coin->peers.active[j];
        else
        {
            if ( j >= coin->peers.numranked )
                break;
            if ( (addr= coin->peers.ranked[j]) == 0 )
                continue;
        }
        if ( addr->recvblocks == 0 )
            limit = 1;
        else
        {
            if ( addr == coin->peers.localaddr )
                limit = IGUANA_EXPIREWINDOW;
            else limit = addr->rank <= 0 ? 1 : (IGUANA_EXPIREWINDOW / sqrt(addr->rank));
            if ( limit < 1 )
                limit = 1;
        }
        height = coin->blocks.parsedblocks;
        if ( readahead < 1 )
            readahead = 1;
        if ( readahead > IGUANA_EXPIREWINDOW )
            readahead = IGUANA_EXPIREWINDOW;
        if ( addr->rank >= 0 && addr->ready > 0 && addr->usock >= 0 && addr->dead == 0 && addr->height > 0 )
        {
            m++;
            //printf("%s: addrht.%d %s p.%d getbit.%d rank.%d\n",addr->ipaddr,addr->height,addr->ipaddr,height,GETBIT(coin->waitingbits,height),addr->rank);
            for (i=n=0; i<100000&&n<limit; i++)
            {
                offset = (((addr->rank > 0) ? addr->rank-1 : m)) * readahead;
                height = (coin->blocks.parsedblocks + offset + i);
                if ( height > coin->blocks.hwmheight || height > addr->height )
                {
                    //printf("%s: height.%d > hwm.%d || addr %d\n",addr->ipaddr,height,coin->blocks.hwmheight,addr->height);
                    break;
                }
                //if ( coin->R.numwaiting > IGUANA_MAXWAITING && height > coin->blocks.parsedblocks+100 )
                //   break;
                if ( iguana_waitstart(coin,height,addr) != 0 )
                {
                    addr->capacity--;
                    //printf("%-15s request block.%-6d parsed.%-6d offset.%-4d rank.%-3d numpeers.%d numwaiting.%d\n",addr->ipaddr,height,coin->blocks.parsedblocks,offset,addr->rank,numpeers,coin->R.numwaiting);
                    n++;
                }
            }
        }
    }
    return(n);
}

int32_t newiguana_getdata(struct iguana_info *coin)
{
    int32_t reqs[IGUANA_READAHEAD],height,i,j,count,capacity,numpeers,n = 0;  struct iguana_peer *addr,*addrs[IGUANA_MAXPEERS];
    if ( coin->R.waitingbits == 0 || coin->R.recvblocks == 0 )
        return(0);
    capacity = iguana_capacity(coin,&numpeers,addrs);
    if ( numpeers == 0 )
        return(0);
    if ( capacity < numpeers )
        capacity = numpeers;
    else if ( capacity > IGUANA_READAHEAD )
        capacity = IGUANA_READAHEAD;
    if ( iguana_avail(coin,coin->blocks.parsedblocks,IGUANA_READAHEAD) == IGUANA_READAHEAD )
        n = iguana_updatewaiting(coin,reqs,capacity,coin->blocks.parsedblocks + (coin->longestchain - coin->blocks.parsedblocks)/2);
    else n = iguana_updatewaiting(coin,reqs,IGUANA_READAHEAD,coin->blocks.parsedblocks);
    count = 0;
    height = coin->blocks.parsedblocks;
    //printf("capacity.%d reqs.%d numpeers.%d\n",capacity,n,numpeers);
    if ( n > 0 )
    {
        for (i=0; i<n; i++)
        {
            height = reqs[i];
            if ( coin->R.numwaiting > IGUANA_MAXWAITING )//&& height > coin->blocks.parsedblocks+100 )
                break;
            for (j=0; j<numpeers; j++)
            {
                if ( (addr= addrs[(i+j) % numpeers]) != 0 && addr->capacity > 0 && addr->height >= height )
                {
                    count += iguana_waitstart(coin,height,addr);
                    break;
                }
            }
            if ( j == numpeers )
            {
                //printf("leftover.%d n.%d\n",i,n);
                if ( (addr= addrs[(i+j) % numpeers]) != 0 && addr->height >= height )
                    count += iguana_waitstart(coin,height,addr);
                break;
            }
        }
    }
    //for (i=0; i<numpeers; i++)
    //  iguana_waitstart(coin,height+IGUANA_READAHEAD*(i+1),addrs[i]);
    return(count);
}

/*{
 if ( (flag= iguana_processhdrs(coin,blocks,n)) >= 0 )
 {
 if ( flag == 0 )
 {
 
 }
 printf("gotheaders flag.%d n.%d (%s) %d vs %d \n",flag,n,bits256_str(blocks[n-1].hash2),iguana_height(coin,blocks[n-1].hash2),coin->blocks.hwmheight);
 if ( n > 0 && iguana_height(coin,blocks[n-1].hash2) > coin->blocks.hwmheight-1000 )
 iguana_send_hashes(coin,strcmp(coin->name,"bitcoin") != 0 ? "getblocks" : "getheaders",addr,bits256_zero,&blocks[n-1].hash2,1);
 }
 printf("%s gotheaders.%d height.%d flag.%d\n",addr->ipaddr,n,coin->blocks.hwmheight,flag);
 //portable_mutex_unlock(&coin->blocks.mutex);
 }*/


//#define IGUANA_OVERLAP 64
//#define IGUANA_MAXWAITING (2 * IGUANA_MAXPEERS * IGUANA_OVERLAP)
//#define IGUANA_EXPIREWINDOW 1000
//#define IGUANA_READAHEAD (IGUANA_EXPIREWINDOW)

#ifndef IGUANA_DEDICATED_THREADS
limit = 1;
if ( addr->ipbits != 0 && addr->pendhdrs < limit && (hashstr= queue_dequeue(&coin->R.hdrsQ,1)) != 0 )
{
    decode_hex(hash2.bytes,sizeof(hash2),hashstr);
    iguana_send_hashes(coin,strcmp(coin->name,"bitcoin") != 0 ? "getblocks" : "getheaders",addr,bits256_zero,&hash2,1);
    queue_enqueue("pendinghdrsQ",&coin->R.pendinghdrsQ[0],(void *)((long)hashstr - sizeof(struct queueitem)),0);
    //printf("dequeue hdrsQ.(%s) -> %s pendinghdrsQ\n",hashstr,addr->ipaddr);
    addr->hdrmillis = milliseconds();
    addr->pendhdrs++;
    flag++;
}
if ( addr->recvblocks == 0 )
limit = 1;
else limit = IGUANA_MAXPENDING;
if ( addr->ipbits != 0 && addr->pendblocks < limit && (hashstr= queue_dequeue(&coin->blocksQ,1)) != 0 )
{
    //printf("dequeued.(%s) for %s\n",hashstr,addr->ipaddr);
    decode_hex(hash2.bytes,sizeof(hash2),hashstr);
    if ( memcmp(hash2.bytes,coin->chain->genesis_hashdata,sizeof(hash2)) != 0 )
    {
        iguana_request_data(coin,addr,&hash2,1,MSG_BLOCK,0);
        addr->pendblocks++;
        flag++;
    }
    free_queueitem(hashstr);
}
#endif

void newiguana_updatehdrs(struct iguana_info *coin)
{
    int32_t i,j,hdri,flag,iter; char *hashstr; struct iguana_hdrs *hdrs; bits256 hash2;
    portable_mutex_lock(&coin->R.hdrsmutex);
    if ( iguana_needhdrs(coin) == 0 )
        return;
    iguana_requesthdrs(coin,0);
    return;
    hdri = (coin->blocks.hwmheight / IGUANA_HDRSCOUNT);
    hdrs = &coin->R.hdrs[hdri];
    if ( time(NULL) > coin->R.lasthdrtime+3 && coin->blocks.hwmheight < coin->longestchain-500 )
    {
        for (iter=flag=0; iter<2; iter++)
        {
            while ( flag == 0 && (hashstr= queue_dequeue(&coin->R.pendinghdrsQ[iter],1)) != 0 )
            {
                //printf("timeout found pending.(%s)\n",hashstr);
                flag++;
                decode_hex(hash2.bytes,sizeof(hash2),hashstr);
                for (j=0; j<2; j++)
                    iguana_send_hashes(coin,strcmp(coin->name,"bitcoin") != 0 ? "getblocks" : "getheaders",0,bits256_zero,&hash2,1);
                //queue_enqueue("resubmit",&coin->R.pendinghdrsQ[iter ^ 1],(void *)((long)hashstr - sizeof(struct queueitem)),0);
                coin->R.lasthdrtime = (uint32_t)time(NULL);
                break;
            }
        }
        if ( hdrs->blocks == 0 && coin->peers.numranked > 2 )
        {
            hash2 = iguana_blockhash(coin,hdri * IGUANA_HDRSCOUNT);
            printf("hdrs backstop %d %s\n",hdri * IGUANA_HDRSCOUNT,bits256_str(hash2));
            for (j=0; j<3; j++)
                iguana_send_hashes(coin,strcmp(coin->name,"bitcoin") != 0 ? "getblocks" : "getheaders",coin->peers.ranked[j],bits256_zero,&hash2,1);
            coin->R.lasthdrtime = (uint32_t)time(NULL);
        }
    }
    if ( coin->blocks.hwmheight > 100000 && coin->R.savedhdrs < coin->blocks.hwmheight-501 )
        coin->R.savedhdrs = iguana_savehdrs(coin);
    //printf("hdri.%d height.%d n.%d %p coin->R.savedhdrs.%u\n",hdri,hdrs->height,hdrs->n,hdrs->blocks,coin->R.savedhdrs);
    if ( hdrs->blocks != 0 && (hdrs->height + hdrs->n) > coin->blocks.hwmheight )
        iguana_processhdrs(coin,hdrs->blocks,hdrs->n);
    for (i=0; i<hdri; i++)
    {
        hdrs = &coin->R.hdrs[i];
        if ( coin->blocks.hwmheight >= (hdrs->height + hdrs->n) )
        {
            if ( hdrs->blocks != 0 )
            {
                myfree(hdrs->blocks,hdrs->n * sizeof(*hdrs->blocks));
                hdrs->blocks = 0;
            }
            if ( hdrs->conflictblocks != 0 )
            {
                myfree(hdrs->conflictblocks,hdrs->n * sizeof(*hdrs->conflictblocks));
                hdrs->conflictblocks = 0;
            }
        }
    }
    portable_mutex_unlock(&coin->R.hdrsmutex);
}
void iguana_gotheadersM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n)
{
    int32_t i,iter,flag; char hexstr[65],*hashstr;
    addr->lastrequest = bits256_zero;
    addr->recvhdrs++;
    if ( addr->pendhdrs > 0 )
        addr->pendhdrs--;
    coin->R.lasthdrtime = (uint32_t)time(NULL);
    iguana_processhdrs(coin,blocks,n);
    return;
    //printf("hdrs.(%s) n.%d from %s\n",bits256_str(blocks[0].hash2),n,addr->ipaddr);
    portable_mutex_lock(&coin->R.hdrsmutex);
    for (i=0; i<coin->R.numhdrs; i++)
    {
        if ( memcmp(coin->R.hdrs[i].hash2.bytes,blocks[0].prev_block.bytes,sizeof(bits256)) == 0 )
        {
            init_hexbytes_noT(hexstr,blocks[0].prev_block.bytes,sizeof(bits256));
            for (iter=flag=0; iter<2; iter++)
            {
                while ( flag == 0 && (hashstr= queue_dequeue(&coin->R.pendinghdrsQ[iter],1)) != 0 )
                {
                    if( strcmp(hashstr,hexstr) == 0 )
                    {
                        free_queueitem(hashstr);
                        //printf("found pending.(%s) hdri.%d\n",hexstr,(coin->blocks.hwmheight / IGUANA_HDRSCOUNT));
                        flag++;
                        break;
                    }
                    queue_enqueue("requeue",&coin->R.pendinghdrsQ[iter ^ 1],(void *)((long)hashstr - sizeof(struct queueitem)),0);
                }
            }
            if ( coin->R.hdrs[i].blocks == 0 )
            {
                coin->R.hdrs[i].blocks = blocks;
                coin->R.hdrs[i].n = n;
                printf("got headers for %d[%d] from %s\n",coin->R.hdrs[i].height,n,addr->ipaddr);
                if ( addr != 0 && coin->R.hdrs[i].height+n > addr->height )
                    addr->height = coin->R.hdrs[i].height+n;
            }
            else if ( coin->R.hdrs[i].n == n && memcmp(coin->R.hdrs[i].blocks,blocks,n*sizeof(*blocks)) == 0 )
            {
                coin->R.hdrs[i].duplicates++;
                printf("duplicate.%d blocks for height.%d n.%d\n",coin->R.hdrs[i].duplicates,coin->R.hdrs[i].height,n);
                myfree(blocks,sizeof(*blocks) * n);
            }
            else
            {
                if ( coin->R.hdrs[i].conflictblocks != 0 )
                {
                    myfree(coin->R.hdrs[i].conflictblocks,coin->R.hdrs[i].conflictblocksn * sizeof(struct iguana_block));
                }
                coin->R.hdrs[i].conflicts++;
                printf("conflict.%d blocks for height.%d n.%d\n",coin->R.hdrs[i].conflicts,coin->R.hdrs[i].height,n);
                coin->R.hdrs[i].conflictblocks = blocks;
                coin->R.hdrs[i].conflictblocksn = n;
            }
            portable_mutex_unlock(&coin->R.hdrsmutex);
            return;
        }
    }
    printf("got unexpected hdrs[%d] prev  %s\n",n,bits256_str(blocks[0].prev_block));
    myfree(blocks,sizeof(*blocks) * n);
    portable_mutex_unlock(&coin->R.hdrsmutex);
}
void iguana_connections(void *arg)
{
    FILE *fp; uint8_t serialized[sizeof(struct iguana_msghdr)]; struct iguana_info *coin,**coins = arg;
    int32_t i,j,r,n,iter,flag; uint32_t now,lastrank; char fname[512];
    struct iguana_peer *addr;
    n = (int32_t)coins[0];
    lastrank = (uint32_t)time(NULL);
    coins++;
    for (i=0; i<n; i++)
    {
        coin = coins[i];
        for (iter=0; iter<2; iter++)
        {
            sprintf(fname,"%s_%s.txt",coin->symbol,(iter == 0) ? "peers" : "hdrs");
            if ( (fp= fopen(fname,"r")) != 0 )
                iguana_parseline(coin,iter,fp);
            fclose(fp);
        }
        //iguana_recvinit(coin,coin->R.numwaitingbits);
    }
    while ( 1 )
    {
        if ( time(NULL) > lastrank+60 )
        {
            for (i=0; i<n; i++)
            {
                portable_mutex_lock(&coin->peers.mutex);
                iguana_peermetrics(coins[i]);
                portable_mutex_unlock(&coin->peers.mutex);
            }
            lastrank = (uint32_t)time(NULL);
        }
        now = (uint32_t)time(NULL);
        for (i=flag=0; i<n; i++)
        {
            if ( (coin= coins[i]) != 0 )
            {
                r = rand();
                for (j=0; j<IGUANA_MAXPEERS; j++)
                {
                    addr = &coin->peers.active[(j + r) % IGUANA_MAXPEERS];
                    if ( addr->usock >= 0 && addr->ipbits != 0 )
                    {
                        if ( addr->dead == 0 && addr->ready > 0 )
                        {
                            if ( now > addr->lastblockrecv+60 && addr->pendblocks > 0 )
                                addr->pendblocks--;
                            if ( now > coin->peers.lastpeer+300 )
                                iguana_queue_send(coin,addr,serialized,"getaddr",0,0,0);
                        }
                        //printf("%s pend.(%d %d) dead.%u ready.%u relay.%d millis.%.0f hwm.%d\n",addr->ipaddr,addr->pendhdrs,addr->pendblocks,addr->dead,addr->ready,addr->relayflag,addr->hdrmillis,coin->blocks.hwmheight);
                    }
                }
                if ( now > coin->peers.lastpeer+300 )
                {
                    printf("lastpeer %u vs now.%u, startpeers\n",coin->peers.lastpeer,now);
                    coin->peers.lastpeer = now;
                }
            }
            iguana_shutdownpeers(coin,0); // closes dead peers to free up open spots
        }
        if ( flag == 0 )
            usleep(10000);
    }
}
&& ((packet= queue_dequeue(&addr->sendQ,0)) != 0 || (packet= queue_dequeue(&coin->sendQ,0)) != 0) )
{
    //printf("%d %s: usock.%d dead.%u ready.%u\n",i,addr->ipaddr,addr->usock,addr->dead,addr->ready);
    flag++;
    if ( (packet->addr != 0 && packet->addr != addr) || (packet->getdatablock > 0  && packet->getdatablock < coin->blocks.parsedblocks) || coin->R.recvblocks[packet->getdatablock] != 0 )
    {
        if ( coin->R.recvblocks[packet->getdatablock] == 0 )
            printf("peerloop: (%s).%d packetaddr.%p != %p || packet->getdatablock %d < %d coin->blocks.parsedblocks recv[%p]\n",packet->serialized+4,packet->datalen,packet->addr,addr,packet->getdatablock,coin->blocks.parsedblocks,coin->R.recvblocks[packet->getdatablock]);
            myfree(packet,sizeof(*packet) + packet->datalen);
            }
    else
    {
        if ( 1 && addr != coin->peers.localaddr )
        {
            if (  )
            {
                addr->startsend = (uint32_t)time(NULL);
                strcpy(addr->symbol,coin->symbol);
                strcpy(addr->coinstr,coin->name);
                iguana_launch("send_data",iguana_issue,packet,IGUANA_SENDTHREAD);
            } else printf("need to wait for pending sends %d\n",iguana_numthreads(1<<IGUANA_SENDTHREAD));
                }
        else //if ( addr != 0 )
        {
            iguana_send(coin,addr,packet->serialized,packet->datalen);
            if ( packet->getdatablock > 0 )
                iguana_setwaitstart(coin,packet->getdatablock);
                myfree(packet,sizeof(*packet) + packet->datalen);
                }
    }
    void iguana_queuehdrs(struct iguana_info *coin,int32_t height,bits256 hash2)
    {
        char hashstr[65]; //int32_t hdrsi;
        init_hexbytes_noT(hashstr,hash2.bytes,sizeof(hash2));
        queue_enqueue("hdrsQ",&coin->R.hdrsQ,queueitem(hashstr),1);
        //printf("try to queue hdr.(%s) height.%d vs %d\n",hashstr,height,coin->blocks.hwmheight);
        /*if ( (height % IGUANA_HDRSCOUNT) == 0 && height+1 >= coin->blocks.hwmheight )
         {
         hdrsi = (height / IGUANA_HDRSCOUNT);
         if ( (height == 0 || coin->R.hdrs[hdrsi].height == 0) && coin->R.hdrs[hdrsi].duplicates == 0 )
         {
         coin->R.hdrs[hdrsi].hash2 = hash2;
         coin->R.hdrs[hdrsi].height = height;
         if ( hdrsi >= coin->R.numhdrs )
         coin->R.numhdrs = hdrsi + 1;
         //printf("queued hdr.(%s)\n",hashstr);
         queue_enqueue("hdrsQ",&coin->R.hdrsQ,queueitem(hashstr),1);
         }
         }*/
    }
    
    int32_t iguana_queue_send(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *serialized,char *cmd,int32_t len,int32_t getdatablock,int32_t forceflag)
    {
        struct iguana_packet *packet; int32_t datalen;
        if ( addr == 0 )
        {
            printf("iguana_queue_send null addr\n");
            getchar();
            return(-1);
        }
        datalen = iguana_sethdr((void *)serialized,coin->chain->netmagic,cmd,&serialized[sizeof(struct iguana_msghdr)],len);
        if ( strcmp("getaddr",cmd) == 0 && time(NULL) < addr->lastgotaddr+300 )
            return(0);
        if ( strcmp("version",cmd) == 0 )
            return(iguana_send(coin,addr,serialized,datalen));
        packet = mycalloc('S',1,sizeof(struct iguana_packet) + datalen);
        packet->datalen = datalen;
        packet->addr = addr;
        if ( 1 && (packet->getdatablock = getdatablock) == 0 && strcmp((char *)&serialized[4],"getdata") == 0 )
        {
            printf("no need to request genesis\n");
            getchar();
        }
        memcpy(packet->serialized,serialized,datalen);
        //printf("%p queue send.(%s) %d to (%s) %x\n",packet,serialized+4,datalen,addr->ipaddr,addr->ipbits);
        queue_enqueue("sendQ",addr != 0 ? &addr->sendQ : &coin->sendQ,&packet->DL,0);
        //printf("queue send.(%s) datalen.%d addr.%p %s [%d]\n",cmd,len,addr,addr!=0?addr->ipaddr:"",getdatablock);
        if ( addr == 0 || (addr->dead == 0 && addr->ipbits != 0) )
        {
            if ( addr == 0 && getdatablock == 0 )
                addr = iguana_choosepeer(coin);
            if ( addr == coin->peers.localaddr || (getdatablock == 0 && strcmp(cmd,"getdata") != 0) )
                forceflag = 1;
            if ( forceflag != 0 )
            {
                if ( getdatablock >= coin->blocks.parsedblocks )
                    len = iguana_send(coin,addr!=0?addr:iguana_choosepeer(coin),serialized,datalen);
                else len = -1;
            }
            else
            {
                packet = mycalloc('S',1,sizeof(struct iguana_packet) + datalen);
                packet->datalen = datalen;
                packet->addr = addr;
                if ( 1 && (packet->getdatablock = getdatablock) == 0 && strcmp((char *)&serialized[4],"getdata") == 0 )
                {
                    printf("no need to request genesis\n");
                    getchar();
                }
                memcpy(packet->serialized,serialized,datalen);
                //printf("%p queue send.(%s) %d to (%s) %x\n",packet,serialized+4,datalen,addr->ipaddr,addr->ipbits);
                queue_enqueue("sendQ",addr != 0 ? &addr->sendQ : &coin->sendQ,&packet->DL,0);
            }
        } else printf("cant send.(%s) len.%d datalen.%d to null addr or dead.%u\n",&serialized[4],len,datalen,addr->dead);
        return(len);
    }
    while ( (packet= queue_dequeue(&addr->sendQ,0)) != 0 )
    {
        if ( packet->getdatablock > 0 && packet->getdatablock < coin->blocks.parsedblocks )
        {
            packet->addr = 0;
            printf("recycle pending sendQ block.%d\n",packet->getdatablock);
            queue_enqueue("shutdown_sendQ",&coin->blocksQ,&packet->DL,0);
        } else myfree(packet,sizeof(*packet) + packet->datalen);
            }

void iguana_dedicatedrecv(void *arg)
{
    struct iguana_info *coin = 0; uint8_t *buf; int32_t bufsize; struct iguana_peer *addr = arg;
    if ( addr == 0 || (coin= iguana_coin(addr->symbol)) == 0 )
    {
        printf("iguana_dedicatedrecv nullptrs addr.%p coin.%p\n",addr,coin);
        return;
    }
    printf("DEDICATED RECV %s\n",addr->ipaddr);
    bufsize = IGUANA_MAXPACKETSIZE;
    buf = mycalloc('r',1,bufsize);
    while ( addr->usock >= 0 && addr->dead == 0 && coin->peers.shuttingdown == 0 )
        _iguana_processmsg(coin,addr,buf,bufsize);
    myfree(buf,bufsize);
}
    if ( packet->getdatablock > 0 && (packet->getdatablock < coin->blocks.parsedblocks || coin->R.recvblocks[packet->getdatablock] != 0) )
    {
        printf("discard sendQ for getdatablock.%d parsed.%d\n",packet->getdatablock,coin->blocks.parsedblocks);
        myfree(packet,sizeof(*packet) + packet->datalen);
        return(1);
        
        void iguana_issue(void *ptr)
        {
            uint32_t ipbits; char ipaddr[64]; struct iguana_peer *addr; struct iguana_info *coin=0; struct iguana_packet *packet = ptr;
            if ( (addr= packet->addr) == 0 || (coin= iguana_coin(addr->symbol)) == 0 || addr->dead != 0 )
            {
                printf("iguana_issue: addr %p coin.%p dead.%u\n",addr,coin,addr->dead);
                return;
            }
            ipbits = (uint32_t)calc_ipbits(addr->ipaddr);
            expand_ipbits(ipaddr,ipbits);
            if ( strcmp(ipaddr,addr->ipaddr) == 0 )
            {
                if ( packet->getdatablock == 0 )
                    iguana_send(coin,addr,packet->serialized,packet->datalen);
                else if ( packet->getdatablock > 0 && packet->getdatablock >= coin->blocks.parsedblocks )
                {
                    //printf("req block.%d to (%s) numthreads.%d\n",packet->getdatablock,packet->addr->ipaddr,iguana_numthreads(1 << IGUANA_SENDTHREAD));
                    iguana_send(coin,addr,packet->serialized,packet->datalen);
                    iguana_setwaitstart(coin,packet->getdatablock);
                }
            }
            else printf("iguana_issue: ipaddr mismatch.(%s) != (%s)\n",ipaddr,addr->ipaddr), getchar();
            //printf("finished sending %d to (%s) numthreads.%d\n",packet->datalen,packet->addr->ipaddr,iguana_numthreads(-1));
            addr->startsend = 0;
            myfree(packet,sizeof(*packet) + packet->datalen);
        }
        
        uint64_t iguana_validaterecv(struct iguana_info *coin,int32_t *nump,char *fname)
        {
            struct iguana_pending *ptr; struct iguana_block space; struct iguana_msgtx *tx;
            int32_t n = 0; struct iguana_mappedptr M; struct iguana_memspace RSPACE; uint64_t allocated = 0;
            memset(&M,0,sizeof(M));
            memset(&RSPACE,0,sizeof(RSPACE));
            if ( (ptr= iguana_mappedptr(0,&M,0,0,fname)) != 0 )
            {
                RSPACE.ptr = M.fileptr;
                RSPACE.used = 0;
                RSPACE.size = M.allocsize;
                printf("process.(%s) %ld\n",fname,(long)M.allocsize);
                n = 0;
                while ( ptr != 0 && ((long)ptr - (long)RSPACE.ptr)+ptr->next < (RSPACE.size - sizeof(*ptr)) )
                {
                    //printf("ptr diff.%d next.%d\n",(int32_t)((long)ptr - (long)RSPACE.ptr),ptr->next);
                    if ( (tx= iguana_validpending(coin,ptr,&space)) != 0 )
                    {
                        //printf("%d: ht.%-6d size.%d next.%d\n",n,ptr->block.height,ptr->allocsize,ptr->next);
                        iguana_freetx(tx,ptr->numtx);
                        allocated += ptr->allocsize;
                        n++;
                        coin->R.recvblocks[ptr->block.height] = ptr;
                    }
                    else
                    {
                        printf("n.%d ht.%d: tx doesnt validate\n",n,ptr->block.height);
                    }
                    if ( ptr->next != 0 )
                        ptr = (void *)((long)ptr + ptr->next);
                    else break;
                }
                if ( n == 0 )
                    iguana_closemap(&M);
            }
            *nump = n;
            return(allocated);
        }
        for (i=maxi=skipped=total=0; skipped<10; i++)
        {
            if ( coin->R.maprecvdata == 0 )
                break;
            sprintf(fname,"tmp/%s/recv.%d",coin->symbol,i), iguana_compatible_path(fname);
            if ( (allocated= iguana_validaterecv(coin,&n,fname)) != 0 )
                combined += allocated, total += n, skipped = 0, maxi = i;
                else if ( skipped++ > 10 )
                    break;
        }

        /*for (i=0; i<n; i++)
         {
         coin = coins[1 + i];
         sprintf(dirname,"DB/%s",coin->symbol);
         ensure_directory(dirname);
         sprintf(dirname,"tmp/%s",coin->symbol);
         ensure_directory(dirname);
         }*/
        //iguana_launch("peers",iguana_connections,coins,IGUANA_PERMTHREAD);
        //iguana_launch("requests",iguana_requests,coins,IGUANA_PERMTHREAD);
        
        //portable_mutex_t hdrsmutex; struct iguana_hdrs *hdrs; uint32_t savedhdrs,lasthdrtime,numhdrs;
       struct iguana_hdrs
        {
            bits256 hash2;
            struct iguana_block *blocks,*conflictblocks;
            int32_t n,conflictblocksn,height,conflicts,duplicates;
        };
        
        
        bits256 iguana_unspentmap(struct iguana_info *coin,uint32_t *spendindp,uint32_t *txidindp,char *txidstr,uint32_t unspentind)
        {
            struct iguana_unspent U;
            memset(&U,0,sizeof(U));
            if ( iguana_rwunspentind(coin,0,&U,unspentind) == 0 )
            {
                *txidindp = U.txidind;
                *spendindp = U.spendind;
                if ( txidstr != 0 )
                    return(iguana_txidstr(coin,0,0,txidstr,U.txidind));
            }
            else printf("error getting unspents[%u] when %d\n",unspentind,coin->latest.numunspents), getchar();
            return(bits256_zero);
        }
        
        int32_t iguana_inittxid(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,int32_t itemind,int32_t itemsize,int32_t numitems)
        {
            char txidstr[513]; bits256 checktxid; uint32_t txidind,spendind; struct iguana_txid *tx = value;
            if ( key != 0 && value != 0 && itemind > 0 )
            {
                //printf("inittxid.(%s) itemind.%d (%d %d)\n",bits256_str(tx->txid),itemind,tx->firstvout,tx->firstvin);
                checktxid = iguana_unspentmap(coin,&spendind,&txidind,txidstr,tx->firstvout);
                if ( memcmp(checktxid.bytes,key,sizeof(checktxid)) != 0 || txidind != itemind )
                {
                    printf("checktxid.%s miscompares to %s, txidind.%d vs itemind.%d\n",txidstr,bits256_str(tx->txid),txidind,itemind);
                    getchar();
                    return(-1);
                }
                if ( spendind >= coin->latest.numspends )
                {
                    //struct iguana_unspent U;
                    //iguana_rwunspentind(coin,0,&U,tx->firstvout);
                    //U.spendind = 0;
                    //iguana_rwunspentind(coin,1,&U,tx->firstvout);
                    printf("spendind.%d vs %d overflow in txid.%s txidind.%d U%d autocleared\n",spendind,coin->latest.numspends,txidstr,tx->firstvout,tx->firstvout);
                }
                //printf("txidind.%d: 1st.(%d %d)\n",txidind,tx->firstvout,tx->firstvin);
            }
            return(0);
        }
        
        /*if ( flag != 0 && height > 0 )
         {
         if ( coin->latest.numtxids != lastblock.L.firsttxidind + lastblock.txn_count && iguana_kvtruncate(coin,coin->txids,lastblock.L.firsttxidind + lastblock.txn_count) < 0 )
         err |= 1;
         if ( coin->latest.numunspents != lastblock.L.firstvout + lastblock.numvouts && iguana_kvtruncate(coin,coin->unspents,lastblock.L.firstvout + lastblock.numvouts) < 0 )
         err |= 2;
         if ( coin->latest.numspends != lastblock.L.firstvin + lastblock.numvins && iguana_kvtruncate(coin,coin->spends,lastblock.L.firstvin + lastblock.numvins) < 0 )
         err |= 4;
         if ( coin->latest.numpkhashes != lastblock.L.numpkinds && iguana_kvtruncate(coin,coin->pkhashes,lastblock.L.numpkinds) < 0 )
         err |= 8;
         }
         else
         {
         printf("reset counters flag.%d height.%d\n",flag,height); //getchar();
         }
         if ( err != 0 )
         return(-err);*/
        checktxid = iguana_txidstr(coin,0,0,txidstr,txidind);
        if ( memcmp(checktxid.bytes,txid.bytes,sizeof(txid)) != 0 )
        {
            int32_t i;
            printf("error kvwrite/read of txid.%s vs %s txidind.%d\n",bits256_str(txid),bits256_str2(checktxid),txidind);
            for (i=-10; i<10; i++)
            {
                iguana_rwtxidind(coin,0,&tx,txidind+i);
                printf("txidind.%d %s\n",txidind+i,bits256_str(tx.txid));
            }
            getchar();
            return(0);
        }
        checkind = iguana_txidind(coin,&checkfirstvout,&checkfirstvin,txid);
        if ( checkind != txidind || checkfirstvout != firstvout || checkfirstvin != firstvin )
        {
            printf("error kvwrite/read of txidind.%d:%d %s firstvout.%d vs %d firstvin.%d vs %d\n",txidind,checkind,bits256_str(txid),firstvout,checkfirstvout,checkfirstvin,firstvin);
            getchar();
            return(0);
        }
        
        int32_t iguana_recvinit(struct iguana_info *coin,int32_t initialheight)
        {
            //int32_t maxi,total; uint64_t allocated,combined = 0;
            //portable_mutex_init(&coin->R.RSPACE.mutex);
            //memset(&coin->R.RSPACE,0,sizeof(coin->R.RSPACE));
            //coin->R.RSPACE.size = 1024*1024*128;
            //coin->R.RSPACE.counter = total != 0 ? maxi+1 : 0;
            return(0);
        }
        
        int32_t iguana_initpkhash(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,int32_t itemind,int32_t itemsize,int32_t numitems)
        {
            int64_t balance; uint64_t credits,debits; int32_t numutxo; uint32_t unspents[64]; struct iguana_pkhash *P = value;
            if ( key != 0 && value != 0 && itemind > 0 )
            {
                if ( (balance= iguana_balance(coin,&credits,&debits,&numutxo,unspents,sizeof(unspents)/sizeof(*unspents),P,itemind)) < 0 )
                {
                    printf("iguana_balance error pkind.%d %.8f vs %.8f\n",itemind,dstr(balance),dstr(P->balance));
                    getchar();
                    return(-1);
                }
                coin->latest.credits += credits;
                coin->latest.debits += debits;
            }
            return(0);
        }
        /*
         
         int64_t iguana_balance(struct iguana_info *coin,uint64_t *creditsp,uint64_t *debitsp,int32_t *nump,uint32_t *unspents,long max,struct iguana_pkhash *P,uint32_t pkind)
         {
         uint32_t unspentind,spendind,lastunspentind,lastspendind,flag,n = 0; int64_t credits,debits,net = 0;
         struct iguana_unspent U; struct iguana_spend S;
         *creditsp = *debitsp = net = credits = debits = lastunspentind = lastspendind = flag = 0;
         unspentind = P->firstunspentind;
         while ( unspentind > 0 )
         {
         lastunspentind = unspentind;
         if ( iguana_rwunspentind(coin,0,&U,unspentind) == 0 )
         {
         credits += U.value;
         if ( U.spendind == 0 )
         {
         net += U.value;
         if ( n < max && unspents != 0 )
         unspents[n] = unspentind;
         }
         n++;
         if ( unspentind != P->lastunspentind && U.nextunspentind > 0 && U.nextunspentind > unspentind && U.nextunspentind < coin->latest.numunspents )
         unspentind = U.nextunspentind;
         else
         {
         if ( U.nextunspentind == 0 ) // cleared during unspents init
         {
         P->lastunspentind = unspentind = lastunspentind;
         flag++;
         }
         break;
         }
         } else return(-1);
         }
         if ( unspentind == P->lastunspentind )
         {
         if ( (spendind= P->firstspendind) >= coin->latest.numspends )
         {
         P->firstspendind = P->lastspendind = spendind = 0;
         flag++;
         }
         while ( spendind > 0 )
         {
         lastspendind = spendind;
         if ( iguana_rwspendind(coin,0,&S,spendind) == 0 )
         {
         if ( S.unspentind > 0 && S.unspentind < coin->latest.numunspents && iguana_rwunspentind(coin,0,&U,S.unspentind) == 0 )
         {
         debits += U.value;
         if ( spendind != P->lastspendind && S.nextspendind > 0 && S.nextspendind > spendind && S.nextspendind < coin->latest.numspends )
         spendind = S.nextspendind;
         } else S.nextspendind = 0;
         if ( S.nextspendind == 0 ) // cleared during spends init
         {
         P->lastspendind = spendind = lastspendind;
         flag++;
         break;
         }
         } else return(-1);
         }
         if ( flag != 0 )
         {
         if ( iguana_rwpkind(coin,1,P,pkind) < 0 )
         printf("error ");
         printf("pkind.%d autofix\n",pkind);
         P->balance = (credits - debits);
         }
         if ( net != (credits - debits) )
         printf("iguana_balance: total mismatch %.8f != %.8f (%.8f - %.8f)\n",dstr(net),dstr(credits)-dstr(debits),dstr(credits),dstr(debits));
         *nump = n;
         *creditsp = credits;
         *debitsp = debits;
         return(net);
         } else printf("iguana_balance error: unspentind.%u != last.%u\n",unspentind,P->lastunspentind);
         *nump = 0;
         return(-1);
         }*/
        
        int32_t iguana_processhdrs(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n)
        {
            bits256 hash2; int32_t i,flag=0,startheight = -1,height = -1; struct iguana_block space,*block;
            if ( startheight >= 0 )
            {
                printf("%s received headers %d [%d] %s\n",addr->ipaddr,startheight,n,bits256_str(blocks[0].hash2));
                if ( startheight+n < coin->blocks.hwmheight )
                    return(-1);
                for (i=0; i<n; i++)
                {
                    if ( (height= startheight+i) < coin->blocks.hwmheight )
                        continue;
                    if ( (block= iguana_findblock(coin,&space,blocks[i].hash2)) == 0 || height > coin->blocks.hwmheight )
                    {
                        if ( (height= iguana_addblock(coin,blocks[i].hash2,&blocks[i])) > 0 )
                        {
                            iguana_gotdata(coin,0,blocks[i].height,blocks[i].hash2);
                            flag++;
                        }
                    } else printf("height.%d:%d %s block.%p flag.%d\n",height,blocks[i].height,bits256_str(blocks[i].hash2),block,flag);
                }
                if ( flag != 0 )
                {
                    //iguana_queuehdrs(coin,blocks[n-1].height,blocks[n-1].hash2,1);
                    //iguana_lookahead(coin,&hash2,coin->blocks.hwmheight + 1);
                }
            }
            iguana_lookahead(coin,&hash2,coin->blocks.hwmheight + 1);
            return(flag);
        }
        
        /*int32_t iguana_updatewaiting(struct iguana_info *coin,int32_t starti,int32_t max)
         {
         int32_t i,height,gap,n = 0; uint32_t now;
         now = (uint32_t)time(NULL);
         height = starti;
         for (i=0; i<max; i++,height++)
         {
         gap = (height - coin->blocks.parsedblocks);
         if ( gap >= 0 )
         gap = sqrt(gap);
         if ( gap < 1 )
         gap = 1;
         if ( height < coin->R.numwaitingbits && coin->R.recvblocks[height] == 0 && now > (coin->R.waitstart[height] + gap) )
         {
         //printf("restart height.%d width.%d widthready.%d %s\n",height,coin->width,coin->widthready,bits256_str(iguana_blockhash(coin,height)));
         iguana_waitclear(coin,height);
         iguana_waitstart(coin,height);
         } //else printf("%d %d %p %u\n",height,coin->R.numwaitingbits,coin->R.recvblocks[height],coin->R.waitstart[height]);
         }
         //printf("height.%d max.%d\n",starti,max);
         height = starti;
         for (i=0; i<max; i++,height++)
         if ( coin->R.recvblocks[height] != 0 )
         n++;
         return(n);
         }*/
        
        /*void iguana_queuehdrs(struct iguana_info *coin,int32_t height,bits256 hash2,int32_t forceflag)
         {
         char hashstr[65];
         if ( memcmp(bits256_zero.bytes,hash2.bytes,sizeof(hash2)) == 0 )
         {
         printf("trying to queue null hash\n");
         getchar();
         }
         if ( height < 0 )
         forceflag = 1;
         if ( (forceflag != 0 && height > coin->blocks.hwmheight-coin->chain->bundlesize) || (height/coin->chain->bundlesize) > (coin->R.topheight/coin->chain->bundlesize) )
         {
         printf("queue hdrs height.%d %s\n",height,bits256_str(hash2));
         coin->R.pendingtopheight = coin->R.topheight;
         coin->R.pendingtopstart = (uint32_t)time(NULL);
         init_hexbytes_noT(hashstr,hash2.bytes,sizeof(hash2));
         queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
         }
         }*/
        /*if ( block->height >= coin->blocks.parsedblocks )
         {
         memset(&space,0,sizeof(space));
         if ( iguana_kvread(coin,coin->blocks.db,0,&space,(uint32_t *)&block->height) != 0 )
         iguana_mergeblock(&space,block);
         else printf("iguana_gotblock: cant read block.%d\n",block->height);
         iguana_recvblock(coin,addr,&space,txarray,numtx,data,datalen);
         iguana_kvwrite(coin,coin->blocks.db,0,&space,(uint32_t *)&space.height);
         } // else printf("orphan %d block.%s from gotblockM\n",block->height,bits256_str(block->hash2));
         iguana_waitclear(coin,block->height);*/
        //portable_mutex_unlock(&coin->blocks.mutex);

        /*if ( 1 && coin->R.pendingtopheight == 0 )
         {
         for (checkpointi=coin->blocks.hwmheight/coin->chain->bundlesize; checkpointi<coin->R.numcheckpoints; checkpointi++)
         if ( memcmp(bits256_zero.bytes,coin->R.checkpoints[checkpointi].prevhash2.bytes,sizeof(coin->R.checkpoints[checkpointi])) != 0 )
         iguana_queuehdrs(coin,coin->R.checkpoints[checkpointi].height,coin->R.checkpoints[checkpointi].prevhash2,1);
         coin->R.pendingtopheight = 1;
         printf("issued initial gethdrs from %d\n",(coin->blocks.hwmheight/coin->chain->bundlesize)*coin->chain->bundlesize); //getchar();
         }
         if ( coin->R.topheight < 0 )
         coin->R.topheight = 0;
         if ( coin->blocks.hwmheight < 0 )
         coin->blocks.hwmheight = 0;
         if ( coin->R.topheight < coin->blocks.hwmheight )
         coin->R.topheight = coin->blocks.hwmheight;
         if ( coin->R.topheight == 0 || coin->R.topheight >= coin->R.pendingtopheight+coin->chain->bundlesize  || time(NULL) > (coin->R.lasthdrtime + 60) )
         {
         memset(hash2.bytes,0,sizeof(hash2));
         if ( coin->R.pendingtopheight != coin->R.topheight )
         {
         height = (coin->R.topheight/coin->chain->bundlesize) * coin->chain->bundlesize;
         hash2 = coin->R.checkpoints[height / coin->chain->bundlesize].prevhash2;
         printf("request new header %d vs %d %u %s\n",height,coin->R.topheight,coin->R.pendingtopstart,bits256_str(hash2));
         if ( memcmp(bits256_zero.bytes,hash2.bytes,sizeof(hash2)) == 0 )
         hash2 = iguana_blockhash(coin,height);
         }
         if ( memcmp(bits256_zero.bytes,hash2.bytes,sizeof(hash2)) == 0 )
         {
         iguana_lookahead(coin,&hash2,1);
         if ( coin->blocks.hwmheight < coin->blocks.parsedblocks )
         coin->blocks.parsedblocks = coin->blocks.hwmheight;
         height = coin->blocks.parsedblocks;
         hash2 = iguana_blockhash(coin,height);
         if ( iguana_choosepeer(coin) != 0 )
         printf("hwmchain request new header %d vs %d %u\n",coin->R.pendingtopheight,coin->R.topheight,coin->R.pendingtopstart);
         }
         coin->R.lasthdrtime = (uint32_t)time(NULL);
         if ( memcmp(bits256_zero.bytes,hash2.bytes,sizeof(hash2)) != 0 )
         {
         iguana_queuehdrs(coin,height,hash2,1);
         return(1);
         }
         }
         if ( coin->newhdrs != 0 )
         {
         coin->newhdrs = 0;
         height = coin->blocks.hwmheight;
         iguana_lookahead(coin,&hash2,height + 1);
         if ( coin->blocks.hwmheight > height )
         return(1);
         }*/
        /*for (iter=0; iter<2; iter++)
         {
         while ( (req= queue_dequeue(&addr->pendblocksQ[iter ^ 1],0)) != 0 )
         {
         if ( memcmp(&req->hash2,hash2.bytes,sizeof(hash2)) == 0 )
         {
         if ( (*heightp= req->height) >= 0 && req->checkpointi >= 0 )
         {
         printf("FOUND.(%s) height.%d\n",bits256_str(req->hash2),req->height);
         if ( deleteflag == 0 )
         queue_enqueue("pendblocksQ",&addr->pendblocksQ[iter ^ 1],&req->DL,0);
         return(&coin->R.checkpoints[req->checkpointi]);
         } else printf("height.%d checkpointi.%d\n",req->height,req->checkpointi);
         }
         printf("requeue.%p\n",req);
         queue_enqueue("pendblocksQ",&addr->pendblocksQ[iter ^ 1],&req->DL,0);
         }
         }
         return(0);*/
        
        void iguana_queuebundle(struct iguana_info *coin,struct iguana_bundle *bundle)
        {
            int32_t i;
            printf("queue bundle.%p %s height.%d num.%d waitingbits.%d\n",bundle,bits256_str(bundle->prevhash2),bundle->height,bundle->num,coin->R.numwaitingbits);
            for (i=0; i<bundle->num; i++)
            {
                //printf("bundle[i.%d] %d %s\n",i,bundle->height + 1 + i,bits256_str(bundle->blocks[i].hash2));
                if ( iguana_recvblock(coin,bundle->height + 1 + i) == 0 )
                {
                    coin->R.blockhashes[bundle->height + 1 + i] = bundle->blocks[i].hash2;
                    //iguana_queueblock(coin,bundle->height + 1 + i,bundle->blocks[i].hash2,0);
                }
            }
        }
        
        struct iguana_bundle *iguana_bundleheight(struct iguana_info *coin,int32_t *heightp,bits256 hash2,bits256 prev_block,int32_t deleteflag)
        {
            //int32_t i,j,miscompare = 0; struct iguana_bundle *bundle;
            *heightp = -1;
            /*   for (i=0; i<coin->R.numbundles; i++)
             {
             if ( i*coin->chain->bundlesize > coin->longestchain )
             {
             // printf("i.%d %d < longestchain.%d\n",i,i*coin->chain->bundlesize,coin->longestchain);
             break;
             }
             bundle = &coin->R.bundles[i];
             if ( bundle->height >= 0 && bundle->blocks != 0 )
             {
             if ( bundle->recvstart == 0 )
             continue;
             // printf("bundlei.%d recvstart.%u finish.%u\n",i,bundle->recvstart,bundle->recvfinish);
             if ( memcmp(bundle->prevhash2.bytes,prev_block.bytes,sizeof(prev_block)) == 0 )
             {
             *heightp = bundle->height + 1;
             return(bundle);
             }
             for (j=0; j<bundle->num; j++)
             {
             if ( memcmp(bundle->blocks[j].hash2.bytes,hash2.bytes,sizeof(hash2)) == 0 )
             {
             *heightp = bundle->height + 1 + j;
             //printf("height.%d j.%d (%s) vs (%s) bundle.%d\n",*heightp,j,bits256_str(bundle->blocks[j].hash2),bits256_str2(hash2),bundle->height);
             return(bundle);
             } else miscompare++;//, printf("%x ",(uint32_t)bundle->blocks[j].hash2.uints[7]);
             }
             } //else printf("skip bundle.%d %p\n",bundle->height,bundle->blocks);
             }
             printf("cant find.(%s) miscompares.%d %x\n",bits256_str(hash2),miscompare,(uint32_t)hash2.uints[7]);*/
            return(0);
        }
        /*
         static bits256 lasthash2;
         struct iguana_blockreq *req; int32_t height;
         addr->lastrequest = bits256_zero;
         addr->recvhdrs++;
         if ( addr->pendhdrs > 0 )
         addr->pendhdrs--;
         coin->R.lasthdrtime = (uint32_t)time(NULL);
         if ( memcmp(lasthash2.bytes,blockhashes[0].bytes,sizeof(lasthash2)) != 0 )
         {
         if ( n <= 2 )
         {
         printf("gotblockhashes[%d] %s pend.%d\n",n,bits256_str(blockhashes[0]),addr->pendhdrs);
         lasthash2 = blockhashes[0];
         }
         }
         if ( n > 2 )
         {
         if ( n > coin->chain->bundlesize )
         printf("warning: %s gotheaders.%d is too many vs. %d\n",coin->symbol,n,coin->chain->bundlesize);
         req = mycalloc('r',1,sizeof(*req));
         req->hash2 = blockhashes[0];
         req->blockhashes = blockhashes;
         req->n = n;
         iguana_bundleheight(coin,&height,blockhashes[0],bits256_zero,0);
         if ( req->height >= 0 )
         {
         req->bundlei = (req->height / coin->chain->bundlesize);
         //printf("blocksQ.%s height.%d\n",bits256_str(blockhashes[0]),height);
         //queue_enqueue("blocksQ",&coin->blocksQ,&req->DL,0);
         }
         else
         {
         req->bundlei = -1;
         //printf("priorityQ.%s height.%d\n",bits256_str(blockhashes[0]),height);
         //queue_enqueue("priorityQ",&coin->priorityQ,&req->DL,0);
         }
         printf("blocksQ.%s height.%d req->height.%d\n",bits256_str(blockhashes[0]),height,req->height);
         queue_enqueue("blocksQ",&coin->blocksQ,&req->DL,0);
         } else myfree(blockhashes,n * sizeof(*blockhashes));
         }
         
         
         int32_t h,i,height; uint32_t now; bits256 prevhash2; //char hashstr[65];
         struct iguana_blockreq *req; struct iguana_bundle *bundle;
         
         iguana_gotdata(coin,addr,block->height,block->hash2);
         now = (uint32_t)time(NULL);
         bundle = iguana_bundleheight(coin,&height,block->hash2,block->prev_block,1);
         //printf("%s got block.%d height.%d\n",addr!=0?addr->ipaddr:"local",block->height,height);
         if ( (req= queue_dequeue(&addr->pendingQ,0)) != 0 ) // should only have depth 1!
         {
         if ( memcmp(req->hash2.bytes,block->hash2.bytes,sizeof(req->hash2)) == 0 )
         {
         if ( req->blockhashes != 0 )
         {
         iguana_gotdata(coin,addr,block->height,block->hash2);
         iguana_bundleinit(coin,block->height-1,block->prev_block);
         if ( (bundle= iguana_bundle(coin,block->prev_block)) != 0 )
         {
         portable_mutex_lock(&bundle->mutex);
         if ( bundle->blocks == 0 )
         {
         bundle->blockhashes = req->blockhashes;
         bundle->num = req->n;
         bundle->bundlei = (block->height / coin->chain->bundlesize);
         bundle->firsthash2 = block->hash2;
         bundle->lasthash2 = req->blockhashes[req->n-1];
         bundle->height = block->height - 1;
         bundle->blocks = mycalloc('B',req->n,sizeof(*bundle->blocks));
         bundle->blocks[0] = *block;
         prevhash2 = block->prev_block;
         for (i=0; i<req->n; i++)
         {
         height = (bundle->height + 1 + i);
         bundle->blocks[i].prev_block = prevhash2;
         bundle->blocks[i].hash2 = req->blockhashes[i];
         prevhash2 = req->blockhashes[i];
         if ( (height % coin->chain->bundlesize) == 0 )
         iguana_bundleinit(coin,height,req->blockhashes[i]);
         }
         printf("initialized bundlei.%d %d\n",bundle->bundlei,bundle->height);
         }
         portable_mutex_unlock(&bundle->mutex);
         } else printf("couldnt find matching bundle for %s\n",bits256_str(block->prev_block));
         myfree(req->blockhashes,req->n * sizeof(*req->blockhashes));
         myfree(req,sizeof(*req));
         } else printf("unexpected missing blockhashes.%p\n",req->blockhashes);
         } else printf("unexpected hash2 mismatch with height.%d\n",block->height);
         }
         else
         {
         if ( bundle == 0 )
         {
         printf("cant find bundle.(%s)\n",bits256_str(block->hash2));
         return;
         }
         if ( height > bundle->height && height <= bundle->height+bundle->num )
         {
         h = height - bundle->height - 1;
         portable_mutex_lock(&bundle->mutex);
         if ( bundle->numvalid < bundle->num && bundle->txdata[h] == 0 )
         {
         bundle->blocks[h] = *block;
         if ( iguana_recvblockptr(coin,height) == &bundle->txdata[h] && bundle->txdata[h] == 0 )
         {
         bundle->txdata[h] = txarray, bundle->numtxs[h] = numtx;
         coin->blocks.numblocks++;
         //if ( (rand() % 100) == 0 )
         printf("GOT.%d | received.%d total.%d | %.2f minutes\n",height,coin->blocks.recvblocks,coin->blocks.numblocks,(double)(now - coin->starttime)/60.);
         txarray = 0;
         if ( ++bundle->numvalid == bundle->num )
         {
         bundle->recvfinish = now;
         bundle->lastduration = (bundle->recvfinish - bundle->recvstart);
         dxblend(&coin->R.avetime,bundle->lastduration,.9);
         if ( bundle->lastduration < coin->R.avetime )
         coin->R.faster++;
         else coin->R.slower++;
         if ( coin->R.faster > 3*coin->R.slower || coin->R.slower > 3*coin->R.faster )
         {
         dir = (coin->R.maxrecvbundles - coin->R.prevmaxrecvbundles);
         if ( coin->R.slower >= coin->R.faster )
         dir = -dir;
         if ( dir > 0 )
         dir = 1;
         else if ( coin->R.maxrecvbundles > 2 )
         dir = -1;
         else dir = 0;
         printf("(%d vs %f) faster.%d slower.%d -> dir.%d apply -> %d\n",bundle->lastduration,coin->R.avetime,coin->R.faster,coin->R.slower,dir,coin->R.maxrecvbundles + dir);
         coin->R.prevmaxrecvbundles = coin->R.maxrecvbundles;
         coin->R.maxrecvbundles += dir;
         coin->R.slower = coin->R.faster = 0;
         }
         coin->R.finishedbundles++;
         printf("submit emit.%d height.%d\n",bundle->bundlei,bundle->height);
         queue_enqueue("emitQ",&coin->emitQ,&bundle->DL,0);
         }
         else
         {
         if ( coin->R.waitstart[height] > 0 )
         {
         if ( bundle->firstblocktime == 0 )
         bundle->firstblocktime = now;
         bundle->durationsum += (now - coin->R.waitstart[height] + 1);
         bundle->aveduration = (bundle->durationsum / bundle->numvalid);
         }
         }
         } else printf("recvblockptr error? height.%d %p %p h.%d\n",height,iguana_recvblockptr(coin,height),&bundle->txdata[h],h);
         } else if ( (rand() % 1000) == 0 )
         printf("interloper! already have txs[%d] for bundlei.%d\n",h,bundle!=0?bundle->height:-1);
         portable_mutex_unlock(&bundle->mutex);
         } else printf("height.%d outside range of bundlei.%d %d\n",height,bundle!=0?bundle->height:-1,bundle!=0?bundle->height:-1);
         }
         //iguana_waitclear(coin,block->height);
         if ( 1 && (rand() % 1000) == 0 )
         printf("%-15s pend.(%d %d) got block.%-6d recvblocks %-8.0f recvtotal %-10.0f\n",addr->ipaddr,addr->pendhdrs,addr->pendblocks,block->height,addr->recvblocks,addr->recvtotal);
         }
         if ( txarray != 0 )
         iguana_freetx(txarray,numtx);
         myfree(block,sizeof(*block));
         }*/
        
        
        /*
         if ( (bp= iguana_bundleinit(coin,-1,blocks[0].prev_block)) != 0 )
         {
         if ( n > coin->chain->bundlesize )
         printf("warning: %s gotheaders.%d is too many vs. %d\n",coin->symbol,n,coin->chain->bundlesize);
         portable_mutex_lock(&bundle->mutex);
         if ( bundle->blocks == 0 )
         {
         bundle->num = n;
         bundle->blocks = blocks;
         bundle->firsthash2 = blocks[0].hash2;
         bundle->lasthash2 = blocks[n-1].hash2;
         for (i=0; i<n; i++)
         {
         blocks[i].height = (bundle->height + i + 1);
         iguana_gotdata(coin,addr,blocks[i].height,blocks[i].hash2);
         if ( (blocks[i].height % coin->chain->bundlesize) == 0 )
         iguana_bundleinit(coin,blocks[i].height,blocks[i].hash2);
         }
         printf("%s set bundle.%d %s\n",addr->ipaddr,bundle->height,bits256_str(blocks[0].prev_block));
         }
         portable_mutex_unlock(&bundle->mutex);
         } else printf("ERROR iguana_gotheaders got bundle.(%s) n.%d that cant be found?\n",bits256_str(blocks[0].prev_block),n);
         }*/
        
        int32_t iguana_updatehdrs(struct iguana_info *coin)
        {
            int32_t flag = 0;
            int32_t i,j,m,height,run,flag = 0; uint32_t now; struct iguana_bundle *bundle;
            if ( iguana_needhdrs(coin) == 0 )
                return(flag);
            now = (uint32_t)time(NULL);
            run = -1;
            for (i=0; i<coin->R.numbundles; i++)
            {
                if ( i*coin->chain->bundlesize > coin->longestchain )
                    break;
                bundle = &coin->R.bundles[i];
                if ( bundle->blocks != 0 )
                {
                    if ( bundle->recvstart == 0 )
                    {
                        if ( (coin->R.startedbundles - coin->R.finishedbundles) < coin->R.maxrecvbundles )
                        {
                            iguana_queuebundle(coin,bundle);
                            bundle->recvstart = now;
                            coin->R.startedbundles++;
                            printf("startbundle.%d (%d - %d)\n",bundle->height,coin->R.startedbundles,coin->R.finishedbundles);
                            flag++;
                        }
                    }
                    else if ( bundle->recvfinish == 0 )
                    {
                        for (j=m=0; j<bundle->num; j++)
                        {
                            height = bundle->height+j+1;
                            if ( iguana_recvblock(coin,height) != 0 )
                                m++;
                            else if ( coin->R.waitstart[height] > 0 )
                            {
                                duration = (now - coin->R.waitstart[height]);
                                if ( duration > 60 || (duration > 10 && bundle->numvalid > 13 && duration > 3.*bundle->aveduration) )
                                {
                                    if ( now > bundle->lastdisp+15 )
                                        printf("height.%d in bundle.%d duration.%d vs ave %.3f\n",height,bundle->height,duration,bundle->aveduration);
                                    iguana_waitclear(coin,height);
                                    iguana_waitstart(coin,height,bundle->blocks[j].hash2,1);
                                }
                            }
                            else if ( bundle->firstblocktime > 0 && (now - bundle->firstblocktime) > 60 )
                            {
                                if ( now > bundle->lastdisp+15 )
                                    printf("height.%d in bundle.%d ave %.3f\n",height,bundle->height,bundle->aveduration);
                                iguana_waitclear(coin,height);
                                iguana_waitstart(coin,height,bundle->blocks[j].hash2,1);
                                bundle->firstblocktime = now;
                            }
                        }
                        if ( 0 && now > bundle->lastdisp+15 )
                        {
                            printf("bundle.%d (%d %d) elapsed.%d (%d - %d) %d | %.2f minutes\n",bundle->bundlei,bundle->height,m,(int32_t)(now - bundle->recvstart),coin->R.startedbundles,coin->R.finishedbundles,coin->R.maxrecvbundles,(double)(now - coin->starttime)/60.);
                            bundle->lastdisp = now;
                        }
                    }
                    else if ( run == i-1 )
                        run++;
                }
            }
            //iguana_lookahead(coin,&hash2,0);
            return(flag);
        }*/
        
        /*struct iguana_block *iguana_block(struct iguana_info *coin,struct iguana_block *space,int32_t height)
         {
         if ( height <= coin->blocks.hwmheight )
         {
         if ( iguana_kvread(coin,coin->blocks.db,0,space,(uint32_t *)&height) != 0 )
         {
         if ( bits256_nonz(space->hash2) != 0 )
         return(space);
         if ( height < coin->blocks.hwmheight )
         {
         printf("height.%d null blockhash? prev.%s\n",height,bits256_str(space->prev_block));
         getchar();
         }
         return(0);
         } else printf("error doing RWmmap\n");
         }
         //printf("iguana_block hwmheight.%d vs height.%d\n",coin->blocks.hwmheight,height);
         return(0);
         }
         
         struct iguana_block *iguana_findblock(struct iguana_info *coin,struct iguana_block *space,bits256 hash2)
         {
         struct iguana_block *block = 0; uint32_t itemind;
         if ( bits256_nonz(hash2) != 0 )
         {
         block = iguana_kvread(coin,coin->blocks.db,hash2.bytes,space,&itemind);
         //printf("iguana_findblock block.%p itemind.%d\n",block,itemind);
         if ( block == 0 || itemind != block->height )
         {
         if ( block != 0 && block->height != itemind )
         {
         printf("iguana_findblock (%s) error itemind.%d vs %d block.%p\n",bits256_str(hash2),itemind,block!=0?block->height:-1,block);
         getchar();
         }
         return(0);
         }
         }
         return(block);
         }*/
        struct iguana_bundle *iguana_bundlefindprev(struct iguana_info *coin,int32_t *heightp,bits256 prevhash2)
        {
            struct iguana_block *block;
            *heightp = -1;
            if ( (block= iguana_blockfind(coin,prevhash2)) != 0 )
            {
                *heightp = block->hh.itemind;
                if ( block->bundle == 0 )
                {
                    if ( *heightp == 0 )
                        block->bundle = coin->B[0];
                    else block->bundle = coin->B[(block->hh.itemind - 1) / coin->chain->bundlesize];
                }
                return(block->bundle);
            }
            else return(0);
        }
        
        /*int32_t iguana_bundleset(struct iguana_info *coin,int32_t origheight,bits256 hash2)
         {
         int32_t bundlei,blocki,height = origheight; struct iguana_bundle *bp = 0;
         //printf("bundleset.(%d %s)\n",height,bits256_str(hash2));
         if ( (height % coin->chain->bundlesize) == 0 && height > 0 )
         {
         iguana_blockhashset(coin,origheight,hash2,0);
         return(0);
         }
         if ( (bundlei= iguana_bundlei(coin,&blocki,height)) >= 0 && bundlei >= 0 && (bp= coin->B[bundlei]) != 0 )
         {
         if ( height > bp->height && height < bp->height+bp->num )
         {
         if ( iguana_blockhashset(coin,origheight,hash2,bp) != 0 )
         {
         return(0);
         }
         printf("iguana_bundleset error setting bundle height.%d %s\n",height,bits256_str(hash2));
         } else printf("iguana_bundleset illegal height.%d for bundle.%d\n",height,bp->height);
         } else printf("iguana_bundleset illegal height.%d bundlei.%d blocki.%d bp.%p\n",height,bundlei,blocki,bp);
         return(-1);
         }*/
        
        /*int32_t iguana_bundlei(struct iguana_info *coin,int32_t *blockip,int32_t height)
         {
         int32_t bundlei;
         *blockip = -1;
         if ( height <= 0 || height > coin->R.numwaitingbits )
         return(-1);
         height--;
         *blockip = (height % coin->chain->bundlesize);
         if ( (bundlei= (height / coin->chain->bundlesize)) < IGUANA_MAXBUNDLES )
         return(bundlei);
         else return(-1);
         }
         
         void **iguana_recvblockptr(struct iguana_info *coin,int32_t *blockip,int32_t height)
         {
         int32_t bundlei; struct iguana_bundle *bp;
         if ( (bundlei= iguana_bundlei(coin,blockip,height)) >= 0 )
         {
         if ( (bp= coin->B[bundlei]) != 0 )
         return(&bp->txdata[*blockip]);
         }
         return(0);
         }*/
        
        /*struct iguana_bundle *iguana_bundleinit(struct iguana_info *coin,int32_t height,bits256 hash2)
         {
         int32_t bundlei,blocki; struct iguana_bundle *bp = 0;
         if ( height < 0 || (height % coin->chain->bundlesize) != 0 )
         {
         printf("bundleinit error: height.%d %s\n",height,bits256_str(hash2));
         return(bp);
         }
         portable_mutex_lock(&coin->bundles_mutex);
         if ( (bundlei= iguana_bundlei(coin,&blocki,height+1)) >= 0 )
         {
         if ( (bp= coin->B[bundlei]) != 0 )
         {
         if ( memcmp(hash2.bytes,bp->prevhash2.bytes,sizeof(hash2)) != 0 )
         {
         if ( bits256_nonz(hash2) > 0 )
         {
         if ( bits256_nonz(bp->prevhash2) > 0 )
         {
         printf("bundleinit[%d]: %d hash conflict have %s, got %s\n",bp->bundlei,bp->height,bits256_str(bp->prevhash2),bits256_str2(hash2));
         //getchar();
         portable_mutex_unlock(&coin->bundles_mutex);
         return(0);
         }
         bp->prevhash2 = hash2;
         iguana_blockhashset(coin,height,hash2,1);
         printf("bundleinit: set starting hash.(%s) for %d\n",bits256_str(hash2),bp->height);
         }
         }
         }
         else
         {
         bp = mycalloc('b',1,sizeof(*bp));
         coin->B[bundlei] = bp; // cant change values once set to nonzero
         bp->prevhash2 = hash2;
         bp->bundlei = bundlei;
         bp->hasheaders = coin->chain->hasheaders;
         bp->num = coin->chain->bundlesize;
         bp->height = (bundlei * coin->chain->bundlesize);
         bp->starttime = (uint32_t)time(NULL);
         if ( bits256_nonz(hash2) > 0 )
         {
         iguana_blockhashset(coin,height,hash2,1);
         printf("created bundle.%d: %s coin->B[%d] <- %p\n",height,bits256_str(hash2),bundlei,bp);
         }
         }
         }
         portable_mutex_unlock(&coin->bundles_mutex);
         return(bp);
         }*/
        int32_t iguana_waitstart(struct iguana_info *coin,int32_t height,bits256 hash2,int32_t priority)
        {
            if ( height < 0 || iguana_recvblock(coin,height) == 0 )
                return(iguana_queueblock(coin,height,hash2,priority));
            else if ( height < coin->maxblockbits )
                printf("iguana_waitstart ignore height.%d < %d, %p GETBIT.%d\n",height,coin->maxblockbits,iguana_recvblock(coin,height),GETBIT(coin->R.waitingbits,height));
            return(0);
        }
        
        int32_t iguana_waitclear(struct iguana_info *coin,int32_t height)
        {
            if ( height < coin->maxblockbits )
            {
                //printf("%d waitclear.%d parsed.%d\n",coin->R.numwaiting,height,coin->blocks.recvblocks);
                if ( coin->R.numwaiting > 0 )
                    coin->R.numwaiting--;
                coin->R.waitstart[height] = 0;
                CLEARBIT(coin->R.waitingbits,height);
                return(0);
            }
            return(-1);
        }
        
        int32_t iguana_updatewaiting(struct iguana_info *coin,int32_t starti,int32_t max)
        {
            int32_t i,height,gap,n = 0; uint32_t now;
            now = (uint32_t)time(NULL);
            height = starti;
            iguana_waitclear(coin,height);
            iguana_waitstart(coin,height,coin->R.blockhashes[height],1);
            for (i=0; i<max; i++,height++)
            {
                gap = (height - coin->blocks.recvblocks);
                if ( gap >= 0 )
                    gap = sqrt(gap);
                if ( gap < 13 )
                    gap = 13;
                if ( height < coin->maxblockbits && iguana_recvblock(coin,height) == 0 && now > (coin->R.waitstart[height] + gap) && memcmp(bits256_zero.bytes,coin->R.blockhashes[height].bytes,sizeof(bits256)) != 0 )
                {
                    //printf("restart height.%d width.%d widthready.%d %s\n",height,coin->width,coin->widthready,bits256_str(coin->R.blockhashes[height]));
                    iguana_waitclear(coin,height);
                    iguana_waitstart(coin,height,coin->R.blockhashes[height],0);
                } //else printf("%d %d %p %u\n",height,coin->maxblockbits,coin->R.recvblocks[height],coin->R.waitstart[height]);
            }
            //printf("height.%d max.%d\n",starti,max);
            height = starti;
            for (i=0; i<max; i++,height++)
                if ( iguana_recvblock(coin,height) != 0 )
                    n++;
            return(n);
        }
        uint32_t iguana_issuereqs(struct iguana_info *coin)
        {
            int32_t width,w;
            coin->width = width = 4*sqrt(coin->longestchain - coin->blocks.recvblocks);
            if ( coin->width < 0 )
                width = 500;
            coin->widthready = 0;
            coin->width = 5000;
            //printf("width.%d\n",width);
            while ( iguana_recvblock(coin,coin->blocks.recvblocks) != 0 )
            {
                coin->blocks.recvblocks++;
                //printf("RECV.%d\n",coin->blocks.recvblocks);
            }
            while ( width < (coin->longestchain - coin->blocks.recvblocks) )
            {
                w = iguana_updatewaiting(coin,coin->blocks.recvblocks,width);
                //printf("w%d ",w);
                if ( width == coin->width )
                    coin->widthready = w;
                //else
                break;
                width <<= 1;
                if ( width >= coin->longestchain-coin->blocks.recvblocks )
                    width = coin->longestchain-coin->blocks.recvblocks-1;
                if ( (rand() % 100) == 0 && width > (coin->width<<2) )
                    printf("coin->width.%d higher width.%d all there, w.%d\n",coin->width,width,w);
            }
            return((uint32_t)time(NULL));
        }
        int32_t iguana_connectsocket(int32_t blockflag,struct iguana_peer *A,struct sockaddr *addr,socklen_t addr_len)
        {
            int32_t opt,flags; struct timeval timeout; //,val = 65536*2
            if ( A->usock >= 0 )
            {
                printf("iguana_connectsocket: (%s) already has usock.%d\n",A->ipaddr,A->usock);
                return(-1);
            }
            if ( A->ipv6 != 0 )
                A->usock = socket(AF_INET6,SOCK_STREAM,IPPROTO_TCP);
            else A->usock = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
            if ( A->usock >= 0 )
            {
                //setsockopt(A->usock,SOL_SOCKET,SO_SNDBUF,&val,sizeof(val));
                //setsockopt(A->usock,SOL_SOCKET,SO_RCVBUF,&val,sizeof(val));
                timeout.tv_sec = 0;
                timeout.tv_usec = 1000;
                setsockopt(A->usock,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout));
                setsockopt(A->usock,SOL_SOCKET,SO_SNDTIMEO,(char *)&timeout,sizeof(timeout));
                opt = 1;
                setsockopt(A->usock,SOL_SOCKET,SO_REUSEADDR,(void*)&opt,sizeof(opt));
                //retval = setsockopt(A->usock,SOL_SOCKET,SO_NOSIGPIPE,&opt,sizeof(opt));
                //printf("nosigpipe retval.%d\n",retval);
                if ( blockflag != 0 || ((flags= fcntl(A->usock,F_GETFL,0)) >= 0 && fcntl(A->usock,F_SETFL,flags|O_NONBLOCK) >= 0) )
                {
                    if ( connect(A->usock,addr,addr_len) >= 0 || errno == EINPROGRESS )
                        return(A->usock);
                    else fprintf(stderr,"usock %s connect -> errno.%d\n",A->ipaddr,errno);
                }// else fprintf(stderr,"usock %s fcntl -> flags.%d errno.%d",ipaddr,flags,errno);
            } else fprintf(stderr,"usock %s -> errno.%d\n",A->ipaddr,errno);
            return(-errno);
        }
        
        int32_t iguana_connect(struct iguana_info *coin,struct iguana_peer *addrs,int32_t maxaddrs,char *ipaddr,uint16_t default_port,int32_t connectflag)
        {
            struct sockaddr *addr; struct sockaddr_in6 saddr6; struct sockaddr_in saddr4; uint32_t ipbits;
            struct addrinfo hints,*res; socklen_t addr_len; struct addrinfo *ai; int32_t retval = -1,status,n = 0;
            addrs[n].usock = -1;
            memset(&hints,0,sizeof(hints));
            memset(&saddr6,0,sizeof(saddr6));
            memset(&saddr4,0,sizeof(saddr4));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            //printf("getaddrinfo\n");
            if ( getaddrinfo(ipaddr,NULL,&hints,&res))
            {
                printf("cant get addrinfo for (%s)\n",ipaddr);
                return(-1);
            }
            for (ai=res; ai!=NULL&&n<maxaddrs; ai=ai->ai_next)
            {
                if ( ai->ai_family == AF_INET6 )
                {
                    struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)ai->ai_addr;
                    memcpy(&addrs[n].A.ip,&saddr->sin6_addr,16);
                    memset(&saddr6,0,sizeof(saddr6));
                    saddr6.sin6_family = AF_INET6;
                    memcpy(&saddr6.sin6_addr.s6_addr,&addrs[n].A.ip[0],16);
                    saddr6.sin6_port = htons(default_port);
                    addrs[n].ipv6 = 1;
                    addr = (struct sockaddr *)&saddr6;
                    addr_len = sizeof(saddr6);
                }
                else if ( ai->ai_family == AF_INET )
                {
                    struct sockaddr_in *saddr = (struct sockaddr_in *)ai->ai_addr;
                    memset(&addrs[n].A.ip[0],0,10);
                    memset(&addrs[n].A.ip[10],0xff,2);
                    memcpy(&addrs[n].A.ip[12],&saddr->sin_addr,4);
                    memset(&saddr4,0,sizeof(saddr4));
                    saddr4.sin_family = AF_INET;
                    memcpy(&saddr4.sin_addr.s_addr,&addrs[n].A.ip[12],4);
                    saddr4.sin_port = htons(default_port);
                    addrs[n].ipv6 = 0;
                    addr = (struct sockaddr *)&saddr4;
                    addr_len = sizeof(saddr4);
                } else return(-1);
                addrs[n].A.nTime = (uint32_t)(time(NULL) - (24 * 60 * 60));
                addrs[n].A.port = default_port;
                strcpy(addrs[n].ipaddr,ipaddr);
                addrs[n].A.nServices = 0;
                n++;
                if ( connectflag != 0 )
                {
                    ipbits = (uint32_t)calc_ipbits(ipaddr);
                    addrs[n].usock = -1;
                    addrs[n].ipbits = ipbits;
                    strcpy(addrs[n].ipaddr,ipaddr);
                    //printf("call connectsocket\n");
                    if ( (addrs[n].usock= iguana_connectsocket(connectflag > 1,&addrs[n],addr,addr_len)) < 0 )
                    {
                        status = IGUANA_PEER_KILLED;
                        printf("refused PEER STATUS.%d for %s usock.%d\n",status,ipaddr,retval);
                        iguana_iAkill(coin,&addrs[n],1);
                        if ( iguana_rwipbits_status(coin,1,ipbits,&status) == 0 )
                            printf("error updating status.%d for %s\n",status,ipaddr);
                    }
                    else
                    {
                        status = IGUANA_PEER_READY;
                        printf("CONNECTED! PEER STATUS.%d for %s usock.%d\n",status,ipaddr,addrs[n].usock);
                        iguana_iAconnected(coin,&addrs[n]);
                        if ( iguana_rwipbits_status(coin,1,ipbits,&status) == 0 )
                            printf("error updating status.%d for %s\n",status,ipaddr);
                        else retval = addrs[n].usock;
                    }
                    break;
                }
            }
            freeaddrinfo(res);
            return(retval);
        }
        
        /*if ( (fp= fopen(fname,"r")) != 0 )
         {
         if ( fgets(line,sizeof(line),fp) > 0 )
         {
         line[strlen(line)-1] = 0;
         if ( atoi(line) > coin->blocks.hashblocks )
         {
         //printf("skip save since %s has %d\n",fname,atoi(line));
         fclose(fp);
         return(0);
         }
         }
         fclose(fp);
         }*/
        
        /*struct iguana_bundle
         {
         struct queueitem DL; portable_mutex_t mutex;
         char fname[512]; struct iguana_mappedptr M;
         void *txdata[_IGUANA_HDRSCOUNT]; int32_t numtxs[_IGUANA_HDRSCOUNT];
         struct iguana_counts presnapshot,postsnapshot;
         int32_t bundlei,height,num,hasheaders,numvalid,havehashes;
         uint32_t starttime,emitstart,emitfinish,lastdisp;
         bits256 prevhash2,firsthash2,lasthash2;
         //double durationsum,aveduration;
         //struct iguana_block *blocks;
         };*/
        
        /*struct iguana_recv
         {
         //uint8_t compressed[IGUANA_MAXPACKETSIZE],decompressed[IGUANA_MAXPACKETSIZE],checkbuf[IGUANA_MAXPACKETSIZE];
         long srcdatalen,compressedtotal; //uint64_t histo[0x100];
         struct iguana_memspace RSPACE,*oldRSPACE; int32_t numold;
         int64_t packetsallocated,packetsfreed; int32_t numwaiting,maprecvdata;
         uint8_t *waitingbits; uint32_t numwaitingbits,*waitstart; //struct iguana_pending **recvblocks;
         int32_t topheight,pendingtopheight;
         uint32_t pendingtopstart,numbundles,lasthdrtime,startedbundles,finishedbundles;
         bits256 tophash2;
         //int32_t prevmaxrecvbundles,maxrecvbundles,faster,slower; double avetime;
         };
         
         struct iguana_pending
         {
         int32_t next,numtx,datalen,origdatalen; struct iguana_block block; uint32_t allocsize,ipbits; uint8_t data[];
         };*/
        //struct iguana_recv R;
        //struct iguana_bundle *B[IGUANA_MAXBUNDLES];
        //struct iguana_blockhashes pendings[1024];
        /*   int32_t height;
         height = iguana_blockheight(coin,blockhashes[0]);
         if ( n > 2 && iguana_needhdrs(coin) > 0 )
         {
         //printf("got blockhashes[%d] %s height.%d\n",n,bits256_str(blockhashes[0]),height);
         if ( height >= 0 )
         {
         for (j=0; j<n && j<coin->chain->bundlesize && height+j<coin->longestchain; j++)
         {
         iguana_bundleset(coin,height+j,blockhashes[j]);
         iguana_gotdata(coin,0,height+j,blockhashes[j],j,n);
         }
         }
         else
         {
         iguana_queueblock(coin,-1,blockhashes[0],1);
         for (i=0; i<coin->numpendings; i++)
         if ( memcmp(coin->pendings[i].blockhashes[0].bytes,blockhashes[0].bytes,sizeof(bits256)) == 0 )
         break;
         if ( i == coin->numpendings )
         {
         if ( coin->numpendings < sizeof(coin->pendings)/sizeof(*coin->pendings) )
         {
         coin->pendings[coin->numpendings].blockhashes = blockhashes;
         coin->pendings[coin->numpendings].n = n;
         coin->pendings[coin->numpendings].starttime = (uint32_t)time(NULL);
         coin->numpendings++;
         printf("ADD to numpendings.%d priority.(%s) n.%d\n",coin->numpendings,bits256_str(blockhashes[0]),n);
         blockhashes = 0;
         } else printf("updatebundles: overflowed pendings\n");
         }
         }
         }*/
        
        /*  if ( iguana_bundlefindprev(coin,&height,blocks[0].prev_block) != 0 && height >= 0 )
         {
         //printf(">>>>>> found %s height.%d n.%d\n",bits256_str(blocks[0].prev_block),height,n);
         height++;
         for (i=0; i<n && i<coin->chain->bundlesize && height<coin->longestchain; i++,height++)
         {
         //printf("i.%d height.%d\n",i,height);
         iguana_bundleset(coin,height,blocks[i].hash2);
         iguana_gotdata(coin,req->addr,height,blocks[i].hash2,i,n);
         if ( height >= coin->blocks.hwmheight )
         {
         if ( height == coin->blocks.hwmheight )
         (*newhwmp)++;
         if ( (block= iguana_block(coin,height)) != 0 )
         iguana_mergeblock(block,&blocks[i]);
         else printf("unexpected null block at height.%d\n",height), getchar();
         }
         else
         {
         // verify it doesnt trigger reorg (and is recent enough!)
         }
         }
         } else printf("unexpected bundlefind error %s height.%d\n",bits256_str(blocks[0].prev_block),height), getchar();
         */
        
        /* int32_t height;
         //printf("%s got block.(%s) height.%d\n",req->addr!=0?req->addr->ipaddr:"local",bits256_str(block->hash2),height);
         if ( (height= iguana_bundleheight(coin,block)) > 0 )
         {
         if ( (ptrp= iguana_blockptrptr(coin,&blocki,height)) != 0 )
         {
         if ( (*ptrp) == 0 )
         {
         //printf("height.%d tx.%p blocki.%d txarray.%p[%d] (%p[%d] %p[%d])\n",height,&txarray[0],blocki,txarray,numtx,txarray[0].vouts,txarray[0].tx_out,txarray[0].vins,txarray[0].tx_in);
         (*ptrp) = (void *)txarray;
         bp->numtxs[blocki] = numtx;
         if ( bp->emitstart == 0 && ++bp->numvalid >= bp->num )
         {
         bp->emitstart = (uint32_t)time(NULL);
         iguana_emittxdata(coin,bp);
         //printf("queue txarray.%p[%d]\n",txarray,numtx);
         //queue_enqueue("emitQ",&coin->emitQ,&bp->DL,0);
         }
         //txarray = 0;
         }
         }
         else printf("cant get ptrp.%d\n",height), getchar();
         iguana_gotdata(coin,req->addr,height,block->hash2,0,0);
         if ( bp != 0 && iguana_bundleready(coin,height-1) <= 0 )
         {
         printf("check for pendings.%d height.%d\n",coin->numpendings,height);
         if ( height == coin->blocks.hwmheight )
         (*newhwmp)++;
         for (i=0; i<coin->numpendings; i++)
         if ( memcmp(coin->pendings[i].blockhashes[0].bytes,block->hash2.bytes,sizeof(block->hash2)) == 0 )
         {
         blockhashes = coin->pendings[i].blockhashes;
         n = coin->pendings[i].n;
         printf("pending[%d].%d bundlesets[%d] %d %s\n",i,coin->numpendings,n,height,bits256_str(blockhashes[0]));
         for (j=0; j<n && j<coin->chain->bundlesize && height+j<coin->longestchain; j++)
         {
         iguana_bundleset(coin,height+j,blockhashes[j]);
         iguana_gotdata(coin,0,height+j,blockhashes[j],j,n);
         }
         myfree(blockhashes,n * sizeof(*blockhashes));
         coin->pendings[i] = coin->pendings[--coin->numpendings];
         break;
         }
         //  queue tx for processing
         }
         else
         {
         // probably new block
         //printf("couldnt find.(%s)\n",bits256_str(block->hash2));
         }
         }*/
        //if ( height >= 0 )
        //    coin->blocks.ptrs[height] = block;
        //printf("found.%s -> %s %d %p inputht.%d\n",bits256_str(hash2),bits256_str(block->hash2),block->hh.itemind,block,height);
        if ( height < 0 || block->hh.itemind == height )
        {
            if ( (int32_t)block->hh.itemind < 0 )
            {
                //printf("found.%s -> %d %p set height.%d matches.%d\n",bits256_str(hash2),block->hh.itemind,block,height,block->matches);
                if ( height >= 0 && block->matches == 0 )
                    block->hh.itemind = height, block->matches = 1;
                    else block = 0;
                        }
            if ( block != 0 )
            {
                if ( block->matches < 100 )
                    block->matches++;
                //_iguana_blocklink(coin,block);
            }
        }
        else if ( block->matches == 0 && block->hh.itemind == (uint32_t)-1 )
        {
            if ( height >= 0 )
            {
                if ( (rand() % 10000) == 0 )
                    printf("set %s.itemind <- %d\n",bits256_str(hash2),height);
                    block->hh.itemind = height;
                    block->matches = 1;
                    }
            else
            {
                printf("matches.%d itemind.%d when height.%d\n",block->matches,block->hh.itemind,height);
                block = 0;
            }
        }
        else
        {
            /*if ( block->matches < 100 )
             {
             block->matches >>= 1;
             if ( block->matches == 0 )
             {
             //printf("collision with (%s) itemind.%d vs %d | matches.%d\n",bits256_str(hash2),block->hh.itemind,height,block->matches);
             block->hh.itemind = -1;
             for (i=0; i<1; i++)
             iguana_queueblock(coin,-1,block->hash2,1);
             block = 0;
             //coin->blocks.recvblocks = 0;
             }
             } else block = 0;*/
        }
        
        /*int32_t iguana_blockheight(struct iguana_info *coin,struct iguana_block *block)
         {
         int32_t height;
         if ( (height= iguana_itemheight(coin,block->hash2)) < 0 )
         {
         if ( (height= iguana_itemheight(coin,block->prev_block)) < 0 )
         {
         iguana_blockhashset(coin,-1,block->hash2,1);
         iguana_blockhashset(coin,-1,block->prev_block,1);
         }
         else
         {
         height++;
         iguana_blockhashset(coin,height,block->hash2,1);
         }
         } else iguana_blockhashset(coin,height,block->hash2,1); // increments matches
         return(height);
         }*/
        if ( (height= iguana_itemheight(coin,blockhashes[0])) >= 0 )
        {
            if ( iguana_needhdrs(coin) > 0 && iguana_havetxdata(coin,h) == 0 )
                iguana_queueblock(coin,height,blockhashes[0],1);
                }
        else if ( iguana_needhdrs(coin) > 0 && iguana_havetxdata(coin,h) == 0 )
            iguana_queueblock(coin,-1,blockhashes[0],1);
            //printf("check.%s height.%d\n",bits256_str(blockhashes[0]),height);
            for (i=0; i<n; i++)
            {
                if ( height >= 0 )
                    h = height++;
                    permblock = iguana_blockhashset(coin,h,blockhashes[i],1);
                    if ( h >= 0 && permblock != 0 )
                    {
                        if ( iguana_blockptr(coin,h) == 0 )
                        {
                            coin->blocks.ptrs[h] = permblock;
                            {
                                int32_t j,m;
                                for (j=m=0; j<coin->longestchain; j++)
                                    if ( iguana_blockptr(coin,j) != 0 )
                                        m++;
                                printf("set (%s) <- %d %p m.%d\n",bits256_str(blockhashes[i]),h,permblock,m);
                            }
                        }
                        if ( permblock->hh.itemind != h )
                            permblock->hh.itemind = h;
                            }
                if ( i == coin->chain->bundlesize-1 )
                {
                    init_hexbytes_noT(hashstr,blockhashes[i].bytes,sizeof(blockhashes[i]));
                    queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
                }
                //else //if ( h >= 0 ) printf("unexpected missing permblock for h.%d\n",h);
                //    iguana_queueblock(coin,-1,blockhashes[i],0);
            }
        for (i=m=run=0; i<num&&i<_IGUANA_HDRSCOUNT; i++)
        {
            if ( (height= iguana_heightwt(coin,&wt,blockhashes[i])) >= 0 )
            {
                if ( run == i && (i == 0 || height == height0+i) )
                    run++;
                if ( (block= iguana_blockfind(coin,blockhashes[i])) != 0 && block == blocks[i] && block->mainchain == 0 )
                {
                    if ( block->hh.itemind != height && wt > block->matches )
                    {
                        printf("%p[%d] <- %d matches.%d wt.%d vs matches.%d\n",block,block->hh.itemind,height,block->matches,wt,block->matches);
                        if ( block->matches < 100 )
                        {
                            block->matches = 1;
                            block->hh.itemind = height;
                        }
                        else printf("height conflict for %s\n",bits256_str(blockhashes[i]));
                            }
                } else blocks[i] = 0;
                    if ( i == 0 )
                        height0 = height;
                        height -= i;
                        if ( m > 0 )
                        {
                            for (j=0; j<m; j++)
                            {
                                if ( heightwts[j][0] == height )
                                {
                                    heightwts[j][1] += wt;
                                    //printf("matches j.%d m.%d wt.%d -> %d\n",j,m,wt,heightwts[j][1]);
                                    break;
                                }
                            }
                        } else j = 0;
                            if ( j == m )
                            {
                                heightwts[m][0] = height;
                                heightwts[m][1] = wt;
                                m++;
                            }
            }
            printf("i.%d j.%d m.%d height.%d wt.%d %s\n",i,j,m,height,wt,bits256_str(blockhashes[0]));
        }
        nlinks = plinks = 0;
        if ( m > 0 )
        {
            if ( m == 1 && height0 >= 0 )
            {
                wt = (heightwts[0][1] / num) + 2;
                for (i=0; i<num; i++)
                    if ( blocks[i] == 0 )
                        break;
                if ( i == num )
                {
                    //printf("height0.%d\n",height0);
                    if ( (prev= iguana_blockptr(coin,height0 - 1)) != 0 )
                    {
                        if ( prev->hh.next == 0 || prev->matches < wt )
                            prev->hh.next = blocks[0];
                            }
                    for (i=plinks=nlinks=0; i<num; i++)
                    {
                        next = (i < num) ? blocks[i+1] : iguana_blockptr(coin,height0 + num);
                        if ( (block= blocks[i]) != 0 )
                        {
                            if ( (int32_t)block->hh.itemind < 0 || block->matches < wt )
                            {
                                block->hh.itemind = height0 + i;
                                block->matches = (wt < 100) ? wt : 100;
                                SETBIT(coin->havehash,height0 + i);
                                //iguana_blockhashset(coin,height0 + i,blockhashes[i],(wt < 100) ? wt : 100);
                            }
                            if ( (block->hh.prev == 0 || block->matches < wt) && block->hh.prev != prev )
                                block->hh.prev = prev, plinks++;
                                if ( (block->hh.next == 0 || block->matches < wt) && block->hh.next != next )
                                    block->hh.next = next, nlinks++;
                                    if ( block->matches < 100 )
                                        block->matches++;
                        } else printf("recvblockhashes: blocks[%d] null\n",i);
                            prev = block;
                            }
                    if ( next != 0 && (next->hh.prev == 0 || next->matches < wt) )
                        next->hh.prev = prev;
                        } else printf("recvblockhashes: i.%d != num.%d\n",i,num);
                            }
            if ( height0 >= 0 && 0 )
            {
                for (i=0; i<m; i++)
                    printf("(h%d %d) ",heightwts[i][0],heightwts[i][1]);
                    printf("%s m.%d run.%d wt.%d height0.%d plinks.%d nlinks.%d\n",bits256_str(blockhashes[0]),m,run,wt,height0,plinks,nlinks);
                    }
        } else printf("recvblockhashes: m.%d height0.%d %s[%d]\n",m,height0,bits256_str(blockhashes[0]),num);
            prev = 0;
            for (i=m=0; i<num; i++)
            {
                if ( (block= iguana_blockhashset(coin,-1,blockhashes[i],1)) != 0 )
                {
                    next = (i < num) ? iguana_blockhashset(coin,-1,blockhashes[i+1],1) : 0;
                    if ( (height= iguana_heightwt(coin,&wt,prev,block,next)) >= 0 )
                    {
                        if ( i == 0 )
                            height0 = height, block0 = block;
                            m++;
                        //printf("height %d, wt %d itemind.%d matches.%d\n",height,wt,block->hh.itemind,block->matches);
                        if ( (int32_t)block->hh.itemind < 0 || block->matches*3 < wt )
                        {
                            SETBIT(coin->havehash,height);
                            block->hh.itemind = height;
                            block->matches = (wt/3) + 1;
                        }
                        if ( prev != 0 && ((int32_t)prev->hh.itemind < 0 || prev->matches*3 < wt) )
                        {
                            SETBIT(coin->havehash,height - 1);
                            prev->hh.itemind = height - 1;
                            prev->matches = (wt/3) + 1;
                        }
                        if ( next != 0 && ((int32_t)next->hh.itemind < 0 || next->matches*3 < wt) )
                        {
                            SETBIT(coin->havehash,height + 1);
                            next->hh.itemind = height + 1;
                            next->matches = (wt/3) + 1;
                        }
                    }
                }
                prev = block;
            }
        if ( m >= coin->chain->bundlesize && height0 >= 0 && block != 0 )
        {
            printf("gothdr.%d oldgothdr.%d %p %d <- %p\n",height0,block->gothdrs,coin->blocks.ptrs[height0],coin->blocks.ptrs[height0]!=0?coin->blocks.ptrs[height0]->hh.itemind:0,block);
            coin->blocks.ptrs[height0] = block;
            block->gothdrs = 1;
        }
        int32_t i,m,height,wt,height0 = -1; struct iguana_block *block,*next,*prev,*block0 = 0;
        
        int32_t iguana_blockmetric(struct iguana_info *coin,int32_t *wtp,struct iguana_block *block)
        {
            int32_t height = -1; int64_t wt;
            if ( block->mainchain != 0 && block->height >= 0 )
            {
                height = block->height;
                wt = ((int64_t)coin->blocks.hwmheight - block->height) * 10000;
                if ( wt > (1 << 28)/_IGUANA_HDRSCOUNT )
                    wt = (1 << 28) / _IGUANA_HDRSCOUNT;
                (*wtp) += (int32_t)wt;
            }
            else if ( block->height >= 0 )
            {
                height = block->height;
                (*wtp) += 10;
            }
            else if ( (int32_t)block->hh.itemind >= 0 )
            {
                height = block->hh.itemind;
                (*wtp) += block->matches;
            }
            return(height);
        }
        
        int32_t iguana_heightwt(struct iguana_info *coin,int32_t *wtp,struct iguana_block *prev,struct iguana_block *block,struct iguana_block *next)
        {
            int32_t heightwts[3][2],height,i,n = 0;
            *wtp = 0;
            height = -1;
            memset(heightwts,0,sizeof(heightwts));
            if ( block != 0 )
            {
                if ( (heightwts[1][0]= iguana_blockmetric(coin,&heightwts[1][1],block)) >= 0 )
                    n++;
                //printf("%s itemind.%d matches.%d ht.%d metric.%d n.%d\n",bits256_str(hash2),block->hh.itemind,block->matches,heightwts[1][0],heightwts[1][1],n);
                if ( prev != 0 )//|| (prev= block->hh.prev) != 0 )
                {
                    if ( (heightwts[0][0]= iguana_blockmetric(coin,&heightwts[0][1],prev)) >= 0 )
                    {
                        //printf("heightwts(%d + 1) vs %d\n",heightwts[0][0],heightwts[1][0]);
                        if ( heightwts[0][0]+1 == heightwts[1][0] )
                            n++;
                        else n--, heightwts[0][0] = -1;
                    }
                    //printf("%s itemind.%d matches.%d ht.%d metric.%d n.%d\n",bits256_str(prev->hash2),prev->hh.itemind,prev->matches,heightwts[0][0],heightwts[0][1],n);
                }
                if ( next != 0 )//(next= block->hh.prev) != 0 && next != block )
                {
                    if ( (heightwts[2][0]= iguana_blockmetric(coin,&heightwts[2][1],next)) >= 0 )
                    {
                        if ( heightwts[2][0]-1 == heightwts[1][0] )
                            n++;
                        else n--, heightwts[2][0] = -1;
                    }
                    //printf("%s itemind.%d matches.%d ht.%d metric.%d n.%d\n",bits256_str(next->hash2),next->hh.itemind,next->matches,heightwts[2][0],heightwts[2][1],n);
                }
                if ( n > 0 )
                {
                    for (i=0; i<3; i++)
                        if ( heightwts[i][0] >= 0 )
                            (*wtp) += heightwts[i][1];
                    (*wtp) *= n;
                    height = heightwts[1][0];
                }
            } //else printf("cant find.(%s)\n",bits256_str(hash2));
            return(height);
        }
        /*n = 0;
         if ( 0 && n == 0 && time(NULL) > coin->hdrstime+30 )
         {
         height = (coin->blocks.hashblocks / coin->chain->bundlesize) * coin->chain->bundlesize;
         while ( height < (coin->longestchain - coin->chain->bundlesize - 1) )
         {
         if ( (hdrs= iguana_addhdr(coin,block->hash2,bits256_zero)) != 0 && hdrs->block.gothdrs == 0 )
         {
         flag++;
         //printf("REQ HDR.(%s) %d\n",bits256_str(block->hash2),height);
         printf("%d ",height);
         n++;
         init_hexbytes_noT(hashstr,hdrs->bundlehash2.bytes,sizeof(bits256));
         queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
         }
         height += coin->chain->bundlesize;
         }
         coin->hdrstime = (uint32_t)time(NULL);
         }
         if ( n > 0 )
         printf("REQ EXTRA HDRS\n");*/
        if ( offset == 0 )
            printf("unhandled case offset.0\n");
            else
            {
                struct iguana_block *block;
                if ( bits256_nonz(hdrs->bundlehash2) == 0 )
                {
                    if ( (block= iguana_blockfind(coin,blockhashes[0])) != 0 )
                        hdrs->bundlehash2 = block->prev_block;
                        }
            }
        
        struct iguana_block *iguana_updatehdrs(struct iguana_info *coin,int32_t *newhwmp,struct iguana_block *block,bits256 prevhash2,bits256 hash2)
        {
            struct iguana_bundlereq *hdrs; int32_t i,offset,height;
            if ( (hdrs= iguana_addhdr(coin,&offset,0,prevhash2,hash2)) != 0 && hdrs->bundleheight >= 0 )
            {
                iguana_blockset(coin,hdrs->bundleheight,hdrs->bundlehash2);
                height = (hdrs->bundleheight + offset);
                if ( block != 0 )
                {
                    block->hh.itemind = height;
                    hdrs->block = *block;
                    prevhash2 = block->prev_block, hash2 = block->hash2;
                    if ( height > 0 )
                        iguana_blockset(coin,height - 1,prevhash2);
                    if ( height <= coin->blocks.hwmheight )
                    {
                        if ( height < coin->blocks.hwmheight || coin->blocks.dirty == 0 )
                            coin->blocks.dirty = height;
                        (*newhwmp)++;
                    }
                }
                if ( hdrs->hashes != 0 )
                {
                    for (i=0; i<hdrs->n; i++)
                        if ( memcmp(block->hash2.bytes,hdrs->hashes[i].bytes,sizeof(bits256)) == 0 )
                            break;
                    printf("got block.(%s) height.%d i.%d\n",bits256_str(block->hash2),height,i);
                    for (; i<hdrs->n; i++,height++)
                        iguana_blockset(coin,height,hdrs->hashes[i]);
                } else printf("no blockhashes.%d\n",hdrs->bundleheight);
            } else printf("cant find hdrs.%s %s %d\n",bits256_str(prevhash2),bits256_str2(hash2),hdrs==0?-1:hdrs->bundleheight), getchar();
            return(iguana_blockfind(coin,hash2));
        }
        
        struct iguana_block *iguana_blockset(struct iguana_info *coin,int32_t height,bits256 hash2)
        {
            struct iguana_block *block; int32_t offset,h,flag; struct iguana_bundlereq *hdrs;
            //printf("blockset.%d %s\n",height,bits256_str(hash2));
            if ( height < 0 )
                getchar();
            iguana_blockhashset(coin,height,hash2,100);
            if ( (block= iguana_blockfind(coin,hash2)) != 0 )
            {
                SETBIT(coin->havehash,height);
                block->hh.itemind = height;
                coin->blocks.ptrs[height] = block;
                //printf("SETBIT.%d %s %p\n",hdrs->bundleheight,bits256_str(hdrs->bundlehash2),permblock);
            }
            if ( (height % coin->chain->bundlesize) == 0 )
            {
                if ( 0 && (hdrs= iguana_addhdr(coin,&offset,1,hash2,bits256_zero)) != 0 )
                {
                    if ( hdrs->bundleheight != height && hdrs->bundleheight >= 0 )
                    {
                        printf("bundleheight.%d -> EXTENDED HDRS.%d %s\n",hdrs->bundleheight,height,bits256_str(hash2));
                        hdrs->bundleheight = height;
                    }
                }
            }
            if ( height >= 0 && bits256_nonz(hash2) > 0 )
            {
                if ( coin->chain->hasheaders == 0 && (height % coin->chain->bundlesize) == 1 && iguana_havetxdata(coin,height) == 0 )
                    iguana_queueblock(coin,height,hash2,1);
            }
            return(block);
        }
        //tmp = iguana_updatehdrs(coin,newhwmp,block,block->prev_block,block->hash2);
        if ( (prev= iguana_blockfind(coin,block->prev_block)) != 0 && (int32_t)prev->hh.itemind >= 0 )
        {
            //printf("recv blockset.%s %d\n",bits256_str(block->hash2),prev->hh.itemind+1);
            permblock = iguana_blockset(coin,prev->hh.itemind+1,block->hash2);
            //permblock = iguana_blockhashset(coin,prev->hh.itemind+1,block->hash2,1);
        }
        else if ( (permblock= iguana_blockfind(coin,block->hash2)) == 0 )
            printf("cant find block prev.%s\n",bits256_str(block->prev_block));
            if ( tmp != 0 && permblock == 0 )
                permblock = tmp;
            /*struct iguana_block *block; int32_t flag = 0;
             while ( coin->blocks.issuedblocks < coin->blocks.hashblocks && coin->blocks.issuedblocks < coin->blocks.recvblocks+coin->chain->bundlesize*IGUANA_INITIALBUNDLES  )
             {
             if ( (block= iguana_blockptr(coin,coin->blocks.issuedblocks)) != 0 && bits256_nonz(block->hash2) != 0 )
             iguana_queueblock(coin,coin->blocks.issuedblocks,block->hash2,0);
             coin->blocks.issuedblocks++;
             flag++;
             }
             return(flag);*/
                
            /*int32_t iguana_reqblocks(struct iguana_info *coin)
             {
             int32_t n,height,flag = 0; struct iguana_block *block;
             if ( queue_size(&coin->priorityQ) == 0 )
             {
             coin->pcount++;
             if ( coin->pcount > 1 && (block= iguana_blockptr(coin,coin->blocks.recvblocks)) != 0 && coin->blocks.recvblocks < coin->blocks.issuedblocks && bits256_nonz(block->hash2) > 0 )
             flag += (iguana_queueblock(coin,coin->blocks.recvblocks,block->hash2,1) > 0);
             } else coin->pcount = 0;
             if ( queue_size(&coin->blocksQ) == 0 )
             {
             coin->bcount++;
             n = 0;
             if ( coin->bcount > 100 && time(NULL) > coin->recvtime+3 )
             {
             for (height=coin->blocks.recvblocks+1; height<coin->blocks.issuedblocks&&n<coin->chain->bundlesize; height++)
             {
             if ( (block= iguana_blockptr(coin,coin->blocks.recvblocks)) != 0 && bits256_nonz(block->hash2) > 0 )
             {
             //if ( (height % 100) == 0 )
             printf("RETRY BLOCK.%d\n",height);
             flag += (iguana_queueblock(coin,height,block->hash2,0) > 0);
             n++;
             }
             }
             //coin->recvtime = (uint32_t)time(NULL);
             }
             } else coin->bcount = 0;
             return(flag);
             }
             
             {
             bundlei = (height / coin->chain->bundlesize);
             if ( GETBIT(coin->emitbits,bundlei) == 0 && iguana_bundleready(coin,height) > 0 )
             {
             req->bundleheight = bundlei * coin->chain->bundlesize;
             SETBIT(coin->emitbits,bundlei);
             req->type = 'E';
             printf("Q emit.%d\n",req->bundleheight);
             queue_enqueue("emitQ",&coin->emitQ,&req->DL,0);
             }
             }*/
                hash2 = iguana_bundleihash2(coin,bp,bundlei);
                if ( memcmp(hash2.bytes,block->hash2.bytes,sizeof(hash2)) == 0 )
                {
                    *hdrsp = bp;
                    *bundleip = bundlei;
                    if ( bundlei == 0 )
                    {
                        if ( (prevbp= iguana_bundlesearch(coin,&prevbundlei,block->bundlehash2,block->prev_block,IGUANA_SEARCHNEXT)) != 0 )
                        {
                            if ( prevbundlei == prevbp->n+1 )
                            {
                                bp->prevbundlehash2 = prevbp->bundlehash2;
                                prevbp->nextbundlehash2 = block->hash2;
                                //printf("prev BUNDLES LINKED! (%d <-> %d) (%s <-> %s)\n",prevbp->bundleheight,bp->bundleheight,bits256_str(prevbp->bundlehash2),bits256_str2(bp->bundlehash2));
                                if ( prevbp->bundleheight != bp->bundleheight-coin->chain->bundlesize )
                                    printf("WARNING gap in bundleheight %d != %d bundlesize\n",prevbp->bundleheight,bp->bundleheight-coin->chain->bundlesize);
                                    } else printf("prevbundlei.%d != prevhdrs->n %d\n",prevbundlei,prevbp->n+1);
                                        }
                    }
                    else if ( bundlei == bp->n )
                    {
                        if ( (nextbp= iguana_bundlesearch(coin,&nextbundlei,block->bundlehash2,block->hash2,IGUANA_SEARCHPREV)) != 0 )
                        {
                            if ( nextbundlei == 0 )
                            {
                                bp->nextbundlehash2 = nextbp->bundlehash2;
                                nextbp->prevbundlehash2 = block->hash2;
                                //printf("next BUNDLES LINKED! (%d <-> %d) (%s <-> %s)\n",nextbp->bundleheight,bp->bundleheight,bits256_str(nextbp->bundlehash2),bits256_str2(bp->bundlehash2));
                                if ( nextbp->bundleheight != bp->bundleheight+coin->chain->bundlesize )
                                    printf("WARNING gap in bundleheight != bundlesize\n");
                                    } else printf("nextbundlei.%d != nextbp->n %d\n",nextbundlei,nextbp->n);
                                        }
                    }
                } else printf("hdrs.%d [%d] unexpected hash2 mismatch for %s != %s\n",bp->bundleheight,bundlei,bits256_str(block->hash2),bits256_str2(hash2));

                                
            /*int32_t iguana_havehash(struct iguana_info *coin,int32_t height)
             {
             return(GETBIT(coin->havehash,height) != 0);
             }*/
                    
                    if ( (bp= iguana_bundlefind(coin,bundleip,block->hash2)) == 0 )
                    {
                        if ( (prevbp= iguana_bundlefind(coin,&prevbundlei,block->prev_block)) == 0 )
                        {
                            for (j=0; j<coin->bundlescount; j++)
                            {
                                if ( (bp= coin->bundles[j]) != 0 )
                                {
                                    if ( bp->blockhashes != 0 && bp->n > 0 && (bp= iguana_bundlescan(coin,bundleip,bp,block->hash2,IGUANA_SEARCHBUNDLE)) != 0 )
                                    {
                                        return(bp);
                                    }
                                }
                            }
                            return(0);
                        }
                        else if ( prevbundlei == prevbp->n )
                        {
                            printf("prev AUTOCREATE.%s\n",bits256_str(block->hash2));
                            iguana_bundlecreate(coin,block->hash2,bits256_zero);
                        }
                    }
        || (bp= iguana_bundlefind(coin,bundleip,hash2)) != 0 )
        {
            if ( (bp= iguana_bundlescan(coin,bundleip,bp,hash2,searchmask)) != 0 )
                return(bp);
        }
        if ( (bp= iguana_bundlefind(coin,bundleip,hash2)) != 0 )
        return(bp);
        if ( (block= iguana_blockfind(coin,hash2)) == 0 )
            iguana_blockhashset(coin,-1,hash2,1);
            if ( (block= iguana_blockfind(coin,hash2)) != 0 )
            {
                if ( bits256_nonz(block->bundlehash2) > 0 )
                {
                    if ( (bp= iguana_bundlefind(coin,&tmp,block->bundlehash2)) != 0 )
                        return(iguana_bundlescan(coin,bundleip,bp,hash2,searchmask));
                }
            }
        
        for (i=0; i<n; i++)
        {
            if ( (block= iguana_recvblockhdr(coin,&bp,&bundlei,&blocks[i],newhwmp)) != 0 && bp != 0 )
            {
                iguana_bundleblockadd(coin,bp,bundlei,blocks[i].hash2);
            } else printf("got hdrs[%d] no block.%p\n",i,block);
                }
        printf("recv'd %d hdrs\n",n);
        if ( n == coin->chain->bundlesize+1 && iguana_bundlefind(coin,&bundlei,blocks[n - 1].hash2,0) == 0 )
        {
            printf("AUTO EXTEND3.%s[%d]\n",bits256_str(blocks[n - 1].hash2),n);
            iguana_bundlecreate(coin,blocks[n - 1].hash2,bits256_zero);
        }
        
        //struct iguana_blockhashes { bits256 *blockhashes; int32_t n; uint32_t starttime; };
        
        void iguana_freetx(struct iguana_msgtx *tx,int32_t n)
        {
            int32_t i,j; struct iguana_msgtx *origtx = tx;
            return;
            for (j=0; j<n; j++,tx++)
            {
                //Tx_freed++, Tx_freesize += tx->allocsize;
                if ( tx->vins != 0 )
                {
                    for (i=0; i<tx->tx_in; i++)
                        if ( tx->vins[i].script != 0 )
                            myfree(tx->vins[i].script,tx->vins[i].scriptlen);
                    myfree(tx->vins,tx->tx_in * sizeof(*tx->vins));
                }
                if ( tx->vouts != 0 )
                {
                    for (i=0; i<tx->tx_out; i++)
                        if ( tx->vouts[i].pk_script != 0 )
                            myfree(tx->vouts[i].pk_script,tx->vouts[i].pk_scriptlen);
                    myfree(tx->vouts,tx->tx_out * sizeof(*tx->vouts));
                }
            }
            myfree(origtx,sizeof(*origtx) * n);
        }
        
        /*
         struct iguana_rawtx { bits256 txid; uint16_t numvouts,numvins; uint8_t rmd160[20]; };
         
         int32_t iguana_emittx(struct iguana_info *coin,FILE *fp,struct iguana_block *block,struct iguana_msgtx *tx,int32_t txi,uint32_t *numvoutsp,uint32_t *numvinsp,int64_t *outputp)
         {
         int32_t blocknum,i; int64_t reward; uint16_t s; struct iguana_rawtx rawtx; uint8_t rmd160[20],buf[64];
         struct iguana_msgvin *vin;
         blocknum = block->hh.itemind;
         memset(&rawtx,0,sizeof(rawtx));
         rawtx.txid = tx->txid;
         rawtx.numvouts = tx->tx_out, rawtx.numvins = tx->tx_in;
         if ( (blocknum == 91842 || blocknum == 91880) && txi == 0 && strcmp(coin->name,"bitcoin") == 0 )
         rawtx.txid.ulongs[0] ^= blocknum;
         //printf("%d: tx.%p %p[numvouts.%d] %p[numvins.%d]\n",block->hh.itemind,tx,tx->vouts,tx->tx_out,tx->vins,tx->tx_in);
         if ( fwrite(&rawtx,1,sizeof(rawtx),fp) == sizeof(rawtx) )
         {
         for (i=0; i<rawtx.numvouts; i++)
         {
         iguana_calcrmd160(coin,rmd160,tx->vouts[i].pk_script,tx->vouts[i].pk_scriptlen,rawtx.txid);
         memcpy(buf,&tx->vouts[i].value,sizeof(tx->vouts[i].value));
         memcpy(&buf[sizeof(tx->vouts[i].value)],rmd160,sizeof(rmd160));
         if ( fwrite(buf,1,sizeof(rmd160)+sizeof(tx->vouts[i].value),fp) == sizeof(rmd160)+sizeof(tx->vouts[i].value) )
         {
         (*numvoutsp)++;
         (*outputp) += tx->vouts[i].value;
         } else printf("error writing txi.%d vout.%d\n",txi,i);
         }
         for (i=0; i<rawtx.numvins; i++)
         {
         vin = &tx->vins[i];
         if ( bits256_nonz(vin->prev_hash) == 0 )
         {
         if ( i == 0 && (int32_t)vin->prev_vout < 0 )
         {
         reward = iguana_miningreward(coin,blocknum);
         //printf("reward %.8f\n",dstr(reward));
         (*outputp) += reward;
         } else printf("unexpected prevout.%d\n",vin->prev_vout), getchar();
         continue;
         }
         memcpy(buf,vin->prev_hash.bytes,sizeof(vin->prev_hash));
         s = vin->prev_vout;
         memcpy(&buf[sizeof(vin->prev_hash)],&s,sizeof(s));
         //printf("do spend.%s\n",bits256_str(vin->prev_hash));
         if ( fwrite(buf,1,sizeof(bits256)+sizeof(s),fp) == sizeof(bits256)+sizeof(s) )
         (*numvinsp)++;
         else printf("error writing txi.%d vin.%d\n",txi,i);
         }
         return(0);
         }
         else printf("error writing txi.%d blocknum.%d\n",txi,blocknum);
         return(-1);
         }
         
         void iguana_emittxarray(struct iguana_info *coin,FILE *fp,struct iguana_block *block,struct iguana_msgtx *txarray,int32_t numtx)
         {
         uint32_t i,numvouts,numvins; int64_t credits; long fpos,endpos;
         if ( fp != 0 && block != 0 )
         {
         //printf("%d/%d: txarray.%p, numtx.%d bp.%p\n",block->hh.itemind,block->hh.itemind,txarray,numtx,bp);
         fpos = ftell(fp);
         credits = numvouts = numvins = 0;
         for (i=0; i<numtx; i++)
         iguana_emittx(coin,fp,block,&txarray[i],i,&numvouts,&numvins,&credits);
         endpos = ftell(fp);
         fseek(fp,fpos,SEEK_SET);
         block->L.supply = credits;
         block->txn_count = numtx;
         block->numvouts = numvouts, block->numvins = numvins;
         block->L.numtxids = numtx, block->L.numunspents = numvouts, block->L.numspends = numvins;
         if ( fwrite(block,1,sizeof(*block),fp) != sizeof(*block) )
         printf("iguana_emittxarray: error writing block.%d\n",block->height);
         fseek(fp,endpos,SEEK_SET);
         }
         }
         
         int32_t iguana_maptxdata(struct iguana_info *coin,struct iguana_mappedptr *M,struct iguana_bundle *bp,char *fname)
         {
         void *fileptr = 0; int32_t i; uint32_t *offsets; struct iguana_block *block;
         if ( (fileptr= iguana_mappedptr(0,M,0,0,fname)) != 0 )
         {
         offsets = fileptr;
         for (i=0; i<bp->n; i++)
         {
         if ( (block= bp->blocks[i]) != 0 )
         {
         if ( block->txdata != 0 )
         {
         if ( block->mapped == 0 )
         {
         printf("[%d].%d free txdata.%d %p\n",bp->hdrsi,i,((struct iguana_bundlereq *)block->txdata)->allocsize,block->txdata);
         myfree(block->txdata,((struct iguana_bundlereq *)block->txdata)->allocsize);
         block->txdata = 0;
         block->mapped = 0;
         }
         }
         if ( i < coin->chain->bundlesize )
         {
         block->txdata = (void *)((long)fileptr + offsets[i]);
         block->mapped = 1;
         }
         }
         else if ( i < coin->chain->bundlesize )
         printf("iguana_maptxdata cant find block[%d]\n",i);
         }
         return(i < coin->chain->bundlesize ? i : coin->chain->bundlesize);
         }
         printf("error mapping (%s)\n",fname);
         return(-1);
         }
         
         void iguana_emittxdata(struct iguana_info *coin,struct iguana_bundle *emitbp)
         {
         FILE *fp; char fname[512];uint32_t offsets[_IGUANA_HDRSCOUNT+1];
         //uint8_t extra[256];  struct iguana_msgtx *txarray,*tx;
         struct iguana_bundlereq *req; struct iguana_mappedptr M;
         int32_t i,bundleheight,height,numtx,n; long len; struct iguana_block *block;
         return;
         if ( emitbp == 0 )
         return;
         sprintf(fname,"tmp/%s/txdata.%d",coin->symbol,emitbp->bundleheight);
         if ( (fp= fopen(fname,"wb")) != 0 )
         {
         bundleheight = emitbp->bundleheight;
         for (i=n=0; i<emitbp->n&&i<coin->chain->bundlesize; i++)
         if ( (block= emitbp->blocks[i]) != 0 && block->txdata != 0 && block->mapped == 0 )
         n++;
         if ( n != emitbp->n && n != coin->chain->bundlesize )
         printf("iguana_emittxdata: WARNING n.%d != bundlesize.%d bundlesize.%d\n",n,emitbp->n,coin->chain->bundlesize);
         memset(offsets,0,sizeof(offsets));
         if ( (len= fwrite(offsets,sizeof(*offsets),n+1,fp)) != n+1 )
         printf("%s: error writing blank offsets len.%ld != %d\n",fname,len,n+1);
         for (i=0; i<n; i++)
         {
         offsets[i] = (uint32_t)ftell(fp);
         height = (bundleheight + i);
         if ( (block= emitbp->blocks[i]) != 0 )
         {
         if ( (req= block->txdata) != 0 && (numtx= block->txn_count) > 0 )
         {
         if ( 0 && fwrite(req->serialized,1,req->n,fp) != req->n )
         printf("error writing serialized data.%d\n",req->n);
         if ( 0 && (txarray= iguana_gentxarray(coin,&len2,block,req->serialized,req->n,extra)) != 0 )
         {
         tx = txarray;
         for (j=0; j<numtx; j++,tx++)
         printf("(%p[%d] %p[%d]) ",tx->vouts,tx->tx_out,tx->vins,tx->tx_in);
         printf("emit.%d txarray.%p[%d]\n",i,txarray,numtx);
         iguana_emittxarray(coin,fp,block,txarray,numtx);
         iguana_freetx(txarray,numtx);
         }
         } else printf("emittxdata: unexpected missing txarray[%d]\n",i);
         } else printf("emittxdata: error with recvblockptr[%d]\n",emitbp->bundleheight + i);
         }
         offsets[i] = (uint32_t)ftell(fp);
         rewind(fp);
         if ( (len= fwrite(offsets,sizeof(*offsets),n+1,fp)) != n+1 )
         printf("%s: error writing offsets len.%ld != %d\n",fname,len,n+1);
         fclose(fp), fp = 0;
         memset(&M,0,sizeof(M));
         //if ( iguana_maptxdata(coin,&M,emitbp,fname) != n )
         //    printf("emit error mapping n.%d height.%d\n",n,bundleheight);
         //else
         {
         //if ( emitbp->blockhashes != 0 )
         //    myfree(emitbp->blockhashes,sizeof(*emitbp->blockhashes) * emitbp->n);
         //emitbp->blockhashes = 0;
         }
         }
         }*/
        //static uint64_t Tx_allocated,Tx_allocsize,Tx_freed,Tx_freesize;
        
        /*int64_t iguana_MEMallocated(struct iguana_info *coin)
         {
         int64_t total = coin->TMPallocated;
         if ( Tx_allocsize > Tx_freesize )
         total += (Tx_allocsize - Tx_freesize);
         //total += coin->R.RSPACE.openfiles * coin->R.RSPACE.size;
         //total += iguana_packetsallocated(coin);
         return(total);
         }*/
        
        static int32_t _sort_by_bits256(struct iguana_kvitem *a,struct iguana_kvitem *b)
        {
            return(bits256_cmp(*(bits256 *)a->keyvalue,*(bits256 *)b->keyvalue));
        }
        
        static int32_t _sort_by_revbits256(struct iguana_kvitem *a,struct iguana_kvitem *b)
        {
            return(bits256_revcmp(*(bits256 *)a->keyvalue,*(bits256 *)b->keyvalue));
        }
        
        static int32_t _sort_by_rmd160(struct iguana_kvitem *a,struct iguana_kvitem *b)
        {
            return(rmd160_cmp(a->keyvalue,b->keyvalue));
        }
        
        static int32_t _sort_by_revrmd160(struct iguana_kvitem *a,struct iguana_kvitem *b)
        {
            return(rmd160_revcmp(a->keyvalue,b->keyvalue));
        }
        
        //    HASH_SORT(coin->blocks.hash,_sort_by_txid);
        /* if ( bp->type == 'Q' )
         {
         req = (struct iguana_bundlereq *)ptr;
         //printf("START.%p save tmp txdata %p [%d].%d datalen.%d %p\n",req,req->argbp,req->argbp!=0?req->argbp->hdrsi:-1,req->argbundlei,req->datalen,req->data);
         if ( fp != 0 )
         {
         if ( fwrite(req->data,1,req->datalen,fp) != req->datalen )
         printf("error writing [%d].%d datalen.%d\n",req->argbp!=0?req->argbp->hdrsi:-1,req->argbundlei,req->datalen);
         }
         //Tx_freed++;
         //Tx_freesize += req->allocsize;
         if ( req->data != 0 )
         myfree(req->data,req->datalen);
         if ( req->blocks != 0 )
         myfree(req->blocks,sizeof(*req->blocks));
         myfree(req,req->allocsize);
         }
         else if ( bp->type == 'E' )
         {
         fflush(fp);
         //myallocated(0,0);
         //iguana_emittxdata(bp->coin,bp);
         //myallocated(0,0);
         }
         else
         {
         printf("iguana_helper: unsupported type.%c %d %p\n",bp->type,bp->type,bp);
         }*/
        for (j=0; j<numdirs; j++)
        {
            finished = 0;
            if ( (dir= iguana_peerdirptrHT(coin,&num,inds[j][0],inds[j][1],1)) != 0 )
            {
                for (i=0; i<num; i++)
                {
                    if ( (itembp= iguana_bundlesearch(coin,&bundlei,dir[i].hash2)) != 0 )
                    {
                        //printf("dir[i.%d] j.%d %s %d[%d] %u\n",i,j,bits256_str(str,dir[i].hash2),itembp->hdrsi,bundlei,itembp->emitfinish);
                        if ( itembp->emitfinish != 0 )
                            finished++;
                    }
                }
                if ( finished == num )
                    iguana_peerfilecloseHT(coin,inds[j][0],inds[j][1]);
                    else printf("peerdir.(%d %d) finished.%d of %d\n",inds[j][0],inds[j][1],finished,num);
                        } else printf("cant get peerdirptr.(%d %d)\n",inds[j][0],inds[j][1]);
                            }
        
        int32_t iguana_bundlesaveHT(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_memspace *memB,struct iguana_bundle *bp) // helper thread
        {
            void *ptrs[IGUANA_MAXBUNDLESIZE]; uint32_t inds[IGUANA_MAXBUNDLESIZE][2]; struct iguana_fileitem *dir;
            struct iguana_bundle *itembp; int32_t addrind,bundlei,finished,fileind,i,j,maxrecv,num,flag,numdirs=0;
            struct iguana_txdatabits txdatabits; struct iguana_ramchain *ramchain; uint64_t estimatedsize = 0;
            struct iguana_block *block;
            memset(ptrs,0,sizeof(ptrs)), memset(inds,0,sizeof(inds));
            flag = maxrecv = 0;
            for (i=0; i<bp->n && i<coin->chain->bundlesize; i++)
            {
                if ( (block= bp->blocks[i]) != 0 )
                {
                    txdatabits = block->txdatabits;
                    if ( memcmp(block->hash2.bytes,coin->chain->genesis_hashdata,sizeof(bits256)) == 0 )
                        ptrs[i] = coin->chain->genesis_hashdata, flag++;
                    else if ( (ptrs[i]= iguana_peerfileptrHT(coin,txdatabits,1)) != 0 )
                    {
                        if ( block->recvlen > maxrecv )
                            maxrecv = block->recvlen;
                        estimatedsize += block->recvlen;
                        flag++;
                    }
                    else
                    {
                        printf("peerfileptr[%d] (%d %d %d %d) null bp.%p %d\n",i,txdatabits.addrind,txdatabits.filecount,txdatabits.fpos,txdatabits.datalen,bp,bp->hdrsi);
                        if ( 1 )
                        {
                            CLEARBIT(bp->recv,i);
                            bp->issued[i] = 0;
                            memset(&block->txdatabits,0,sizeof(block->txdatabits));
                            block = 0;
                        }
                    }
                    addrind = txdatabits.addrind, fileind = txdatabits.filecount;
                    if ( numdirs > 0 )
                    {
                        for (j=0; j<numdirs; j++)
                        {
                            if ( inds[j][0] == addrind && inds[j][1] == fileind )
                                break;
                        }
                    } else j = 0;
                    if ( j == numdirs )
                    {
                        inds[j][0] = addrind;
                        inds[j][1] = fileind;
                        numdirs++;
                    }
                }
            }
            if ( flag == i )
            {
                iguana_meminit(mem,"bundleHT",0,estimatedsize + IGUANA_MAXPACKETSIZE,0);
                iguana_meminit(memB,"ramchainB",0,maxrecv + IGUANA_MAXPACKETSIZE,0);
                printf(">>>>>>>>> start MERGE.(%ld %ld) numdirs.%d i.%d flag.%d estimated.%ld maxrecv.%d\n",(long)mem->totalsize,(long)memB->totalsize,numdirs,i,flag,(long)estimatedsize,maxrecv);
                if ( (ramchain= iguana_bundlemergeHT(coin,mem,memB,ptrs,i,bp)) != 0 )
                {
                    iguana_ramchainsave(coin,mem,ramchain);
                    iguana_ramchainfree(coin,mem,ramchain);
                    bp->emitfinish = (uint32_t)time(NULL);
                } else bp->emitfinish = 0;
                iguana_mempurge(mem);
                iguana_mempurge(memB);
            }
            else
            {
                printf(">>>>> bundlesaveHT error: numdirs.%d i.%d flag.%d\n",numdirs,i,flag);
                bp->emitfinish = 0;
            }
            return(flag);
        }
        
        int32_t iguana_peerfilecloseHT(struct iguana_info *coin,uint32_t addrind,uint32_t filecount)
        {
            char fname[512]; int32_t i,n = 0; struct iguana_mappedptr *M;
            return(0);
            iguana_peerfilename(coin,fname,addrind,filecount);
            printf("PEERFILECLOSE.%s\n",fname);
            //portable_mutex_lock(&coin->peers.filesM_mutex);
            if ( coin->peers.filesM != 0 )
            {
                for (i=0; i<coin->peers.numfilesM; i++)
                {
                    M = &coin->peers.filesM[i];
                    if ( strcmp(fname,M->fname) == 0 && M->fileptr != 0 )
                    {
                        printf("[%d] closemap.(%s)\n",i,fname);
                        iguana_closemap(M);
                        M->closetime = (uint32_t)time(NULL);
                        n++;
                    }
                }
            }
            //portable_mutex_unlock(&coin->peers.filesM_mutex);
            return(n);
        }
        
        void *_iguana_txdataptrHT(struct iguana_info *coin,struct iguana_mappedptr *M,char *fname,struct iguana_txdatabits txdatabits)
        {
            int32_t len; uint8_t *rawptr; uint32_t starttime = (uint32_t)time(NULL);
            if ( M->fileptr != 0 )
            {
                while ( M->allocsize < (txdatabits.fpos + txdatabits.datalen + sizeof(uint32_t)) )
                {
                    iguana_closemap(M);
                    if ( iguana_mappedptr(0,M,0,0,fname) == 0 || M->allocsize < (txdatabits.fpos + txdatabits.datalen + sizeof(uint32_t)) )
                    {
                        if ( time(NULL) > starttime+3 )
                        {
                            printf("too small (%s) %llu vs %ld\n",fname,(long long)M->allocsize,(txdatabits.fpos + txdatabits.datalen + sizeof(uint32_t)));
                            return(0);
                        } else sleep(1);
                    }
                }
                rawptr = (void *)((long)M->fileptr + txdatabits.fpos);
                memcpy(&len,rawptr,sizeof(len));
                if ( len == IGUANA_MARKER )
                {
                    memcpy(&len,&rawptr[sizeof(len)],sizeof(len));
                    //printf("found marker %s[%u] numblocks.%d\n",fname,(int32_t)txdatabits.fpos,len);
                    if ( txdatabits.isdir != 0 )
                        return(&rawptr[sizeof(uint32_t)*2]);
                    else printf("isdir notset with IGUANA_MARKER.%x\n",IGUANA_MARKER);
                }
                else if ( len == txdatabits.datalen && len < IGUANA_MAXPACKETSIZE )
                {
                    if ( txdatabits.isdir == 0 )
                        return(&rawptr[sizeof(uint32_t)]);
                    else printf("isdir set without IGUANA_MARKER.%x\n",IGUANA_MARKER);
                } else printf("txdataptr.%s: len.%d error [%d %d %d %d] (%d %d)\n",fname,len,txdatabits.datalen,txdatabits.addrind,txdatabits.fpos,txdatabits.filecount,len == txdatabits.datalen,len < IGUANA_MAXPACKETSIZE);//, getchar();
            } //else printf("txdataptr.%s %p %ld vs %ld\n",M->fname,M->fileptr,M->allocsize,(txdatabits.fpos + txdatabits.datalen + sizeof(uint32_t)));
            return(0);
        }
#define IGUANA_MARKER 0x07770777
        
        void iguana_peerfilename(struct iguana_info *coin,char *fname,uint32_t addrind,uint32_t filecount)
        {
            sprintf(fname,"tmp/%s/peer%d.%d",coin->symbol,addrind,filecount);
        }
        
        struct iguana_txdatabits iguana_calctxidbits(uint32_t addrind,uint32_t filecount,uint32_t fpos,uint32_t datalen)
        {
            struct iguana_txdatabits bits;
            if ( (bits.addrind= addrind) != addrind )
                printf("iguana_calctxidbits: addrind overflow.%d\n",addrind), exit(-1);
                if ( (bits.filecount= filecount) != filecount )
                    printf("iguana_calctxidbits: filecount overflow.%d\n",filecount), exit(-1);
                    if ( (bits.fpos= fpos) != fpos )
                        printf("iguana_calctxidbits: fpos overflow.%d\n",fpos), exit(-1);
                        if ( (bits.datalen= datalen) != datalen )
                            printf("iguana_calctxidbits: datalen overflow.%d\n",datalen), exit(-1);
                            return(bits);
        }
        
        void *iguana_peerfileptrHT(struct iguana_info *coin,struct iguana_txdatabits txdatabits,int32_t createflag)
        {
            char fname[512]; int32_t i,oldesti,oldest,duration,datalen; uint64_t fpos; struct iguana_mappedptr *M = 0; void *ptr = 0;
            fpos = txdatabits.fpos, datalen = txdatabits.datalen;
            oldesti = -1;
            oldest = 0;
            iguana_peerfilename(coin,fname,txdatabits.addrind,txdatabits.filecount);
            //portable_mutex_lock(&coin->peers.filesM_mutex);
            if ( coin->peers.filesM != 0 )
            {
                for (i=0; i<coin->peers.numfilesM; i++)
                {
                    M = &coin->peers.filesM[i];
                    if ( strcmp(fname,M->fname) == 0 )
                    {
                        if ( M->fileptr != 0 && (ptr= _iguana_txdataptrHT(coin,M,fname,txdatabits)) != 0 )
                        {
                            //portable_mutex_unlock(&coin->peers.filesM_mutex);
                            //printf("peerfileptr.(%s) %d %d -> %p\n",fname,txdatabits.addrind,txdatabits.filecount,ptr);
                            return(ptr);
                        }
                        else if ( M->closetime != 0 )
                        {
                            duration = (uint32_t)(time(NULL) - M->closetime);
                            if ( duration > oldest )
                                oldest = duration, oldesti = i;
                        }
                    }
                }
                M = 0;
            }
            if ( createflag != 0 )
            {
                if ( oldesti >= 0 && oldest > 60 )
                {
                    M = &coin->peers.filesM[oldesti];
                    printf("oldesti.%d oldest.%d remove.(%s) recycle slot.%d\n",oldesti,oldest,M->fname,i);
                    iguana_removefile(M->fname,0);
                    memset(M,0,sizeof(*M));
                }
                if ( M == 0 )
                {
                    coin->peers.filesM = myrealloc('m',coin->peers.filesM,coin->peers.filesM==0?0:coin->peers.numfilesM * sizeof(*coin->peers.filesM),(coin->peers.numfilesM+1) * sizeof(*coin->peers.filesM));
                    M = &coin->peers.filesM[coin->peers.numfilesM];
                    coin->peers.numfilesM++;
                    //if ( (coin->peers.numfilesM % 10) == 0 )
                    printf("iguana_peerfileptr realloc filesM.%d\n",coin->peers.numfilesM);
                }
                if ( iguana_mappedptr(0,M,0,0,fname) != 0 )
                {
                    ptr = _iguana_txdataptrHT(coin,M,fname,txdatabits);
                    printf("mapped.(%s) size.%ld %p\n",fname,(long)M->allocsize,ptr);
                } else printf("iguana_peerfileptr error mapping.(%s)\n",fname);
            }
            //portable_mutex_unlock(&coin->peers.filesM_mutex);
            return(ptr);
        }
        
        struct iguana_fileitem *iguana_peerdirptrHT(struct iguana_info *coin,int32_t *nump,uint32_t addrind,uint32_t filecount,int32_t createflag)
        {
            char fname[512]; FILE *fp; uint32_t dirpos,marker; struct iguana_txdatabits txdatabits;
            *nump = 0;
            if ( filecount >= coin->peers.active[addrind].filecount )
                return(0);
            iguana_peerfilename(coin,fname,addrind,filecount);
            if ( (fp= fopen(fname,"rb")) != 0 )
            {
                fseek(fp,-sizeof(int32_t) * 3,SEEK_END);
                fread(nump,1,sizeof(*nump),fp);
                fread(&dirpos,1,sizeof(dirpos),fp);
                fread(&marker,1,sizeof(marker),fp);
                if ( marker == IGUANA_MARKER && (dirpos + sizeof(uint32_t) * 5 + *nump * sizeof(struct iguana_fileitem)) == ftell(fp) )
                {
                    txdatabits = iguana_calctxidbits(addrind,filecount,dirpos,(int32_t)(*nump * sizeof(struct iguana_fileitem)));
                    fclose(fp);
                    txdatabits.isdir = 1;
                    return(iguana_peerfileptrHT(coin,txdatabits,1));
                }
                else //if ( marker == IGUANA_MARKER )
                    printf("marker.%x vs %x: dirpos.%d num.%d -> %ld vs %ld\n",marker,IGUANA_MARKER,dirpos,*nump,dirpos + sizeof(uint32_t) * 4 + *nump * sizeof(struct iguana_fileitem),ftell(fp));
                fclose(fp);
            } else printf("cant open dir.(%s)\n",fname);
            return(0);
        }
        struct iguana_txdatabits iguana_peerfilePT(struct iguana_info *coin,struct iguana_peer *addr,bits256 hash2,struct iguana_txdatabits txdatabits,int32_t datalen)
        {
            char fname[512]; int32_t marker; uint32_t dirpos;
            if ( bits256_nonz(hash2) == 0 || addr->fp == 0 || ftell(addr->fp)+datalen >= IGUANA_PEERFILESIZE-IGUANA_MAXPACKETSIZE || addr->numfilehash2 >= addr->maxfilehash2 )
                //if ( addr->fp == 0 )
            {
                if ( addr->fp != 0 )
                {
                    dirpos = (uint32_t)ftell(addr->fp);
                    marker = IGUANA_MARKER;
                    fwrite(&marker,1,sizeof(marker),addr->fp);
                    fwrite(&addr->numfilehash2,1,sizeof(addr->numfilehash2),addr->fp);
                    fwrite(addr->filehash2,addr->numfilehash2,sizeof(*addr->filehash2),addr->fp);
                    fwrite(&addr->numfilehash2,1,sizeof(addr->numfilehash2),addr->fp);
                    fwrite(&dirpos,1,sizeof(dirpos),addr->fp);
                    fwrite(&marker,1,sizeof(marker),addr->fp);
                    fclose(addr->fp);
                    //iguana_flushQ(coin,addr);
                    //fflush(addr->fp);
                }
                iguana_peerfilename(coin,fname,addr->addrind,++addr->filecount);
                txdatabits.filecount = addr->filecount;
                addr->fp = fopen(fname,"wb");
                addr->numfilehash2 = 0;
            }
            if ( addr->fp == 0 )
            {
                printf("error creating fileind.%d %s\n",addr->filecount,addr->ipaddr);
                exit(1);
            }
            if ( addr->numfilehash2 < addr->maxfilehash2 )
            {
                if ( addr->filehash2 == 0 )
                    addr->filehash2 = mycalloc('f',addr->maxfilehash2,sizeof(*addr->filehash2));
                    addr->filehash2[addr->numfilehash2].hash2 = hash2;
                    addr->filehash2[addr->numfilehash2].txdatabits = txdatabits;
                    addr->numfilehash2++;
            }
            return(txdatabits);
        }

        
        int32_t iguana_ramchainspend(struct iguana_info *coin,struct iguana_ramchain *ramchain,uint32_t spendind,uint32_t spent_txidind,uint16_t spent_vout,int32_t updateflag)
        {
            struct iguana_pkhash *p; struct iguana_unspent *u; struct iguana_account *acct; int32_t unspentind,pkind;
            if ( spent_txidind < ramchain->numtxids )
            {
                unspentind = (spent_txidind + spent_vout);
                u = &ramchain->U[unspentind];
                if ( (pkind= u->pkind) < ramchain->numpkinds && pkind >= 0 )
                {
                    if ( updateflag != 0 )
                    {
                        p = &ramchain->P[pkind];
                        if ( ramchain->pkextras[pkind].firstspendind == 0 )
                            ramchain->pkextras[pkind].firstspendind = spendind;
                        acct = &ramchain->accounts[pkind];
                        ramchain->S[spendind].prevspendind = acct->lastspendind;
                        acct->lastspendind = spendind;
                        if ( ramchain->Uextras[unspentind].spendind != 0 )
                        {
                            printf("double spend u.%d has spendind.%d when s.%d refers to it\n",unspentind,ramchain->Uextras[unspentind].spendind,spendind);
                            return(-1);
                        }
                        ramchain->Uextras[unspentind].spendind = spendind;
                    }
                    return(1);
                }
            }
            return(0);
        }
        
        int32_t iguana_ramchainspends(struct iguana_info *coin,struct iguana_ramchain *ramchain,int32_t updateflag)
        {
            struct iguana_spend *s; int32_t j,spendind,retval,spent_txidind,spent_vout,needtxidinds = 0;
            spendind = 0;
            for (j=0; j<ramchain->numspends; j++,spendind++)
            {
                s = &ramchain->S[spendind];
                spent_txidind = (s->unspentind >> 16) & 0xffff;
                spent_vout = (s->unspentind & 0xffff);
                if ( (retval= iguana_ramchainspend(coin,ramchain,spendind,spent_txidind,spent_vout,updateflag)) < 0 )
                    return(-1);
                needtxidinds += retval;
            }
            return(needtxidinds);
        }
        
        int32_t iguana_ramchainload(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_ramchain *ramchain)
        {
            int32_t i,j; uint32_t unspentind,spendind,txidind,pkind,needtxidinds = 0;
            struct iguana_txid *tx; struct iguana_pkhash *p; struct iguana_unspent *u; struct iguana_account *acct;
            txidind = unspentind = spendind = pkind = 0;
            for (pkind=0; pkind<ramchain->numpkinds; pkind++)
            {
                p = &ramchain->P[pkind];
                iguana_hashsetHT(ramchain->pkhashes,0,p->rmd160,sizeof(p->rmd160),pkind);
            }
            for (i=0; i<ramchain->numtxids; i++,txidind++)
            {
                tx = &ramchain->T[txidind];
                iguana_hashsetHT(ramchain->txids,0,tx->txid.bytes,sizeof(bits256),txidind);
                for (j=0; j<tx->numvouts; j++,unspentind++)
                {
                    u = &ramchain->U[unspentind];
                    acct = &ramchain->accounts[u->pkind];
                    u->prevunspentind = acct->lastunspentind;
                    acct->lastunspentind = unspentind;
                    if ( u->txidind != txidind )
                    {
                        printf("txidind.%d u->txidind.%d mismatch\n",txidind,u->txidind);
                        return(-1);
                    }
                    acct->balance += u->value;
                }
            }
            if ( (needtxidinds= iguana_ramchainspends(coin,ramchain,0)) == 0 )
            {
                if ( (needtxidinds= iguana_ramchainspends(coin,ramchain,1)) != 0 )
                    printf("ramchainspends unexpected error\n");
            }
            return(needtxidinds);
        }
        
        int32_t iguana_ramchainload(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_ramchain *ramchain)
        {
            int32_t i,j; uint32_t unspentind,spendind,txidind,pkind,needtxidinds = 0;
            struct iguana_txid *tx; struct iguana_pkhash *p; struct iguana_unspent *u; struct iguana_account *acct;
            txidind = unspentind = spendind = 0;
            for (i=0; i<ramchain->numtxids; i++,txidind++)
            {
                tx = &ramchain->T[txidind];
                iguana_hashsetHT(ramchain->txids,0,tx->txid.bytes,sizeof(bits256),txidind);
                for (j=0; j<tx->numvouts; j++,unspentind++)
                {
                }
            }
            if ( (needtxidinds= iguana_ramchainspends(coin,ramchain,0)) == 0 )
            {
                if ( (needtxidinds= iguana_ramchainspends(coin,ramchain,1)) != 0 )
                    printf("ramchainspends unexpected error\n");
            }
            return(needtxidinds);
        }
        
        
        int32_t iguana_ramchainspend(struct iguana_info *coin,struct iguana_ramchain *ramchain,uint32_t spendind,uint32_t spent_txidind,uint16_t spent_vout,int32_t updateflag)
        {
            struct iguana_pkhash *p; struct iguana_unspent *u; struct iguana_account *acct; int32_t unspentind,pkind;
            if ( spent_txidind < ramchain->numtxids )
            {
                unspentind = (spent_txidind + spent_vout);
                u = &ramchain->U[unspentind];
                if ( (pkind= u->pkind) < ramchain->numpkinds && pkind >= 0 )
                {
                    if ( updateflag != 0 )
                    {
                        p = &ramchain->P[pkind];
                        if ( ramchain->pkextras[pkind].firstspendind == 0 )
                            ramchain->pkextras[pkind].firstspendind = spendind;
                        acct = &ramchain->accounts[pkind];
                        ramchain->S[spendind].prevspendind = acct->lastspendind;
                        acct->lastspendind = spendind;
                        if ( ramchain->Uextras[unspentind].spendind != 0 )
                        {
                            printf("double spend u.%d has spendind.%d when s.%d refers to it\n",unspentind,ramchain->Uextras[unspentind].spendind,spendind);
                            return(-1);
                        }
                        ramchain->Uextras[unspentind].spendind = spendind;
                    }
                    return(1);
                }
            }
            return(0);
        }
        uint32_t oldiguana_rwiAddrind(struct iguana_info *coin,int32_t rwflag,struct iguana_iAddr *iA,uint32_t ind)
        {
            uint32_t tmpind; char ipaddr[64]; struct iguana_iAddr checkiA;
            if ( rwflag == 0 )
            {
                memset(iA,0,sizeof(*iA));
                if ( iguana_kvread(coin,coin->iAddrs,0,iA,&ind) != 0 )
                {
                    //printf("read[%d] %x -> status.%d\n",ind,iA->ipbits,iA->status);
                    return(ind);
                } else printf("error getting pkhash[%u] when %d\n",ind,coin->numiAddrs);
            }
            else
            {
                expand_ipbits(ipaddr,iA->ipbits);
                tmpind = ind;
                if ( iguana_kvwrite(coin,coin->iAddrs,&iA->ipbits,iA,&tmpind) != 0 )
                {
                    if ( tmpind != ind )
                        printf("warning: tmpind.%d != ind.%d for %s\n",tmpind,ind,ipaddr);
                    //printf("iA[%d] wrote status.%d\n",ind,iA->status);
                    if ( iguana_kvread(coin,coin->iAddrs,0,&checkiA,&tmpind) != 0 )
                    {
                        if ( memcmp(&checkiA,iA,sizeof(checkiA)) != 0 )
                            printf("compare error tmpind.%d != ind.%d\n",tmpind,ind);
                    }
                    return(iA->ipbits);
                } else printf("error kvwrite (%s) ind.%d tmpind.%d\n",ipaddr,ind,tmpind);
            }
            printf("iA[%d] error rwflag.%d\n",ind,rwflag);
            return(0);
        }
        struct iguana_peer *iguana_choosepeer(struct iguana_info *coin)
        {
            int32_t i,j,r,iter; struct iguana_peer *addr;
            r = rand();
            portable_mutex_lock(&coin->peers_mutex);
            if ( coin->MAXPEERS == 0 )
                coin->MAXPEERS = IGUANA_MAXPEERS;
            if ( coin->peers.numranked > 0 )
            {
                for (j=0; j<coin->peers.numranked; j++)
                {
                    i = (j + r) % coin->MAXPEERS;
                    if ( (addr= coin->peers.ranked[i]) != 0 && addr->pendblocks < coin->MAXPENDING && addr->dead == 0 && addr->usock >= 0 )
                    {
                        portable_mutex_unlock(&coin->peers_mutex);
                        return(addr);
                    }
                }
            }
            portable_mutex_unlock(&coin->peers_mutex);
            for (iter=0; iter<2; iter++)
            {
                for (i=0; i<coin->MAXPEERS; i++)
                {
                    addr = &coin->peers.active[(i + r) % coin->MAXPEERS];
                    if ( addr->dead == 0 && addr->usock >= 0 && (iter == 1 || addr->pendblocks < coin->MAXPENDING) )
                        return(addr);
                }
            }
            return(0);
        }
        void iguana_shutdownpeers(struct iguana_info *coin,int32_t forceflag)
        {
#ifndef IGUANA_DEDICATED_THREADS
            int32_t i,skip,iter; struct iguana_peer *addr;
            if ( forceflag != 0 )
                coin->peers.shuttingdown = (uint32_t)time(NULL);
            for (iter=0; iter<60; iter++)
            {
                skip = 0;
                for (i=0; i<coin->MAXPEERS; i++)
                {
                    addr = &coin->peers.active[i];
                    if ( addr->ipbits == 0 || addr->usock < 0 || (forceflag == 0 && addr->dead == 0) )
                        continue;
                    if ( addr->startsend != 0 || addr->startrecv != 0 )
                    {
                        skip++;
                        continue;
                    }
                    iguana_iAkill(coin,addr,0);
                }
                if ( skip == 0 )
                    break;
                sleep(1);
                printf("iguana_shutdownpeers force.%d skipped.%d\n",forceflag,skip);
            }
            if ( forceflag != 0 )
                coin->peers.shuttingdown = 0;
#endif
        }
 
        uint32_t iguana_ipbits2ind(struct iguana_info *coin,struct iguana_iAddr *iA,uint32_t ipbits,int32_t createflag)
        {
            char ipaddr[64]; struct iguana_kvitem *item; struct iguana_iAddr *tmp;
            expand_ipbits(ipaddr,ipbits);
            //printf("ipbits.%x %s to ind\n",ipbits,ipaddr);
            memset(iA,0,sizeof(*iA));
            if ( (item= iguana_hashfind(coin->iAddrs,&ipbits,sizeof(ipbits))) == 0 )
                //if ( iguana_kvread(coin,coin->iAddrs,&ipbits,iA,&ind) == 0 )
            {
                if ( createflag == 0 )
                    return(0);
                tmp = mycalloc('i',1,sizeof(*iA));
                *tmp = *iA;
                iA->ind = coin->numiAddrs;
                iA->ipbits = ipbits;
                if ( (item= iguana_hashset(coin->iAddrs,0,&iA->ipbits,sizeof(iA->ipbits),iA->ind)) == 0 )
                {
                    printf("iguana_addr: cant save.(%s)\n",ipaddr);
                    return(0);
                }
                else
                {
                    coin->numiAddrs++;
                    if ( iguana_rwiAddrind(coin,1,iA,iA->ind) == 0 )
                        printf("error iAddr.%d: created %x %s\n",iA->ind,ipbits,ipaddr);
                }
            }
            else *iA = *(struct iguana_iAddr *)item->keyvalue;
            return(iA->ind);
        }
        
        int32_t iguana_set_iAddrheight(struct iguana_info *coin,uint32_t ipbits,int32_t height)
        {
            struct iguana_iAddr iA; uint32_t ind;
            if ( (ind= iguana_ipbits2ind(coin,&iA,ipbits,1)) > 0 )
            {
                iA.ipbits = ipbits;
                if ( (ind= iguana_rwiAddrind(coin,0,&iA,ind)) > 0 && height > iA.height )
                {
                    iA.height = height;
                    iA.ipbits = ipbits;
                    iguana_rwiAddrind(coin,1,&iA,ind);
                }
            }
            return(iA.height);
        }
        
        uint32_t iguana_rwipbits_status(struct iguana_info *coin,int32_t rwflag,uint32_t ipbits,int32_t *statusp)
        {
            struct iguana_iAddr iA; uint32_t ind;
            if ( (ind= iguana_ipbits2ind(coin,&iA,ipbits,1)) > 0 )
            {
                if ( (ind= iguana_rwiAddrind(coin,0,&iA,ind)) > 0 )
                {
                    if ( rwflag == 0 )
                        *statusp = iA.status;
                    else
                    {
                        iA.status = *statusp;
                        iA.ipbits = ipbits;
                        printf("%p status.%d ipbits.%x iA.%d saved iA->ind.%d\n",&iA,iA.status,iA.ipbits,ind,iA.ind);
                        //printf("set status.%d for ind.%d\n",iA.status,ind);
                        if ( iguana_rwiAddrind(coin,1,&iA,ind) == 0 )
                        {
                            printf("iguana_iAconnected (%x) save error\n",iA.ipbits);
                            return(0);
                        }
                    }
                    return(ind);
                } else printf("iguana_rwiAstatus error getting iA[%d]\n",ind);
            } else printf("error ipbits status\n");
            return(0);
        }

        int32_t iguana_ramchainspends(struct iguana_info *coin,struct iguana_ramchain *ramchain,int32_t updateflag)
        {
            struct iguana_spend *s; int32_t j,spendind,retval,needtxidinds = 0;
            spendind = 0;
            for (j=0; j<ramchain->numspends; j++,spendind++)
            {
                s = &ramchain->S[spendind];
                if ( (retval= iguana_ramchainspend(coin,ramchain,spendind,s->spendtxidind,s->vout,updateflag)) < 0 )
                    return(-1);
                needtxidinds += retval;
            }
            return(needtxidinds);
        }
        if ( bundlei >= coin->chain->bundlesize )
            return(block);
        if ( (block->bundlei= bundlei) == 0 )
        {
            iguana_hash2set(coin,"bundlehash2",&bp->blockhashes[0],block->hash2);
            //iguana_blockQ(coin,bp,0,bp->bundlehash2,1);
            if ( bits256_nonz(block->prev_block) > 0 )
            {
                //iguana_blockQ(coin,bp,-1,block->prev_block,1);
                for (i=0; i<coin->bundlescount; i++)
                {
                    if ( (prevbp= coin->bundles[i]) != 0 && prevbp->n >= coin->chain->bundlesize )
                    {
                        cmphash2 = iguana_bundleihash2(coin,prevbp,coin->chain->bundlesize-1);
                        if ( memcmp(cmphash2.bytes,block->prev_block.bytes,sizeof(bits256)) == 0 )
                        {
                            //printf("found prev_block\n");
                            iguana_hash2set(coin,"bp setprev",&bp->prevbundlehash2,prevbp->blockhashes[0]);
                            iguana_hash2set(coin,"prevbp setnext",&prevbp->nextbundlehash2,bp->blockhashes[0]);
                            //printf("prev BUNDLES LINKED! (%d <-> %d) (%s <-> %s)\n",prevbp->bundleheight,bp->bundleheight,bits256_str(prevbp->bundlehash2),bits256_str2(bp->bundlehash2));
                            if ( prevbp->bundleheight != bp->bundleheight-coin->chain->bundlesize )
                                printf("WARNING gap in bundleheight %d != %d bundlesize\n",prevbp->bundleheight,bp->bundleheight-coin->chain->bundlesize);
                                break;
                        }
                    }
                }
            }
        }
        else if ( bundlei == 1 )
        {
            if ( iguana_hash2set(coin,"firstblockhash2",&bp->blockhashes[1],block->hash2) < 0 )
                return(0);
            if ( bp->blockhashes != 0 )
            {
                if ( bits256_nonz(block->prev_block) > 0 )
                    iguana_hash2set(coin,"b blockhashes[0]",&bp->blockhashes[0],block->prev_block);
                    iguana_hash2set(coin,"b blockhashes[1]",&bp->blockhashes[1],block->hash2);
                    }
        }
        else if ( bundlei == bp->n-1 )
        {
            if ( (nextbp= iguana_bundlefind(coin,&nextbundlei,hash2,IGUANA_SEARCHBUNDLE)) != 0 )
            {
                if ( nextbundlei == 0 )
                {
                    iguana_hash2set(coin,"bp setnext",&bp->nextbundlehash2,nextbp->blockhashes[0]);
                    iguana_hash2set(coin,"next setprev",&nextbp->prevbundlehash2,bp->blockhashes[0]);
                    char str[65],str2[65];
                    bits256_str(str,bp->blockhashes[0]), bits256_str(str2,nextbp->blockhashes[0]);
                    printf("next BUNDLES LINKED! (%d <-> %d) (%s <-> %s)\n",bp->bundleheight,nextbp->bundleheight,str,str2);
                    if ( nextbp->bundleheight != bp->bundleheight+coin->chain->bundlesize )
                        printf("WARNING gap in bundleheight %d != %d bundlesize\n",nextbp->bundleheight,bp->bundleheight+coin->chain->bundlesize);
                        } else printf("nextbundlei.%d != 0 nextbp->n %d\n",nextbundlei,nextbp->n);
                            }
            //iguana_hash2set(coin,"lastblockhash2",&bp->lastblockhash2,block->hash2);
        }
    }
    
    
    struct iguana_bundle *iguana_bundlescan(struct iguana_info *coin,int32_t *bundleip,struct iguana_bundle *bp,bits256 hash2,int32_t searchmask)
    {
        int32_t i;
        *bundleip = -2;
        if ( (searchmask & IGUANA_SEARCHBUNDLE) != 0 )
        {
            // bloom filter here
            //printf("%s vs %s: %d\n",bits256_str(hash2),bits256_str2(bp->bundlehash2),memcmp(hash2.bytes,bp->bundlehash2.bytes,sizeof(hash2)));
            if ( memcmp(hash2.bytes,bp->blockhashes[0].bytes,sizeof(hash2)) == 0 )
            {
                *bundleip = 0;
                //printf("found blockhash[0]\n");
                return(bp);
            }
            if ( memcmp(hash2.bytes,bp->blockhashes[1].bytes,sizeof(hash2)) == 0 )
            {
                *bundleip = 1;
                //printf("found blockhash[1]\n");
                return(bp);
            }
            for (i=2; i<bp->n && i<coin->chain->bundlesize; i++)
            {
                if ( memcmp(hash2.bytes,bp->blockhashes[i].bytes,sizeof(hash2)) == 0 )
                {
                    *bundleip = i;
                    return(bp);
                }
            }
        }
        if ( (searchmask & IGUANA_SEARCHPREV) != 0 && memcmp(hash2.bytes,bp->prevbundlehash2.bytes,sizeof(hash2)) == 0 )
        {
            *bundleip = -1;
            return(bp);
        }
        if ( (searchmask & IGUANA_SEARCHNEXT) != 0 && memcmp(hash2.bytes,bp->nextbundlehash2.bytes,sizeof(hash2)) == 0 )
        {
            *bundleip = bp->n;
            return(bp);
        }
        return(0);
    }
    
    struct iguana_bundle *iguana_bundlefind(struct iguana_info *coin,int32_t *bundleip,bits256 hash2,int32_t adjust)
    {
        int32_t i,searchmask; struct iguana_bundle *bp = 0; // struct iguana_block *block;
        *bundleip = -2;
        if ( bits256_nonz(hash2) > 0 )
        {
            if ( adjust == 0 )
                searchmask = IGUANA_SEARCHBUNDLE;
            else searchmask = IGUANA_SEARCHNOLAST;
            //if ( (block= iguana_blockfind(coin,hash2)) != 0 && (bp= block->bp) != 0 && (bp= iguana_bundlescan(coin,bundleip,bp,hash2,searchmask)) != 0 )
            //    return(bp);
            for (i=0; i<coin->bundlescount; i++)
            {
                if ( (bp= coin->bundles[i]) != 0 )
                {
                    if ( (bp= iguana_bundlescan(coin,bundleip,bp,hash2,searchmask)) != 0 )
                        return(bp);
                }
            }
        }
        //printf("iguana_hdrsfind: cant find %s\n",bits256_str(hash2));
        return(0);
    }
    
    int32_t iguana_bundlecheck(struct iguana_info *coin,struct iguana_bundle *bp,int32_t priorityflag)
    {
        int32_t i,qsize,remains,incomplete,lasti,n = 0; struct iguana_block *block;
        bits256 hash2; double threshold; uint64_t datasize =0;
        //printf("bp.%p bundlecheck.%d emit.%d\n",bp,bp->ramchain.hdrsi,bp->emitfinish);
        if ( bp != 0 && bp->emitfinish == 0 )
        {
            remains = bp->n - bp->numrecv;
            qsize = queue_size(&coin->priorityQ);
            if ( bp->numrecv > coin->chain->bundlesize*.98 )
            {
                priorityflag = 1;
                if ( bp->numrecv > coin->chain->bundlesize-3 )
                    threshold = bp->avetime;
                else threshold = bp->avetime * 2;
            } else threshold = bp->avetime * 5;
            lasti = -1;
            for (i=0; i<bp->n && i<coin->chain->bundlesize; i++)
            {
                hash2 = iguana_bundleihash2(coin,bp,i);
                if ( bits256_nonz(hash2) == 0 )
                    continue;
                if ( (block= bp->blocks[i]) == 0 )
                    block = bp->blocks[i] = iguana_blockfind(coin,hash2);
                if ( block != 0 && block->ipbits != 0 )
                {
                    //char str[65];
                    if ( block->recvlen != 0 )
                        datasize += block->recvlen;
                    if ( block->hdrsi != bp->ramchain.hdrsi )
                        block->hdrsi = bp->ramchain.hdrsi;
                    if ( block->bundlei != i )
                        block->bundlei = i;
                    /*    printf("%s %d[%d] != %d[%d]\n",bits256_str(str,block->hash2),block->hdrsi,block->bundlei,bp->ramchain.hdrsi,i);
                     CLEARBIT(bp->recv,i);
                     //memset(&bp->blocks[i]->txdatabits,0,sizeof(bp->blocks[i]->txdatabits));
                     bp->issued[i] = milliseconds();
                     iguana_blockQ(coin,bp,i,bp->blocks[i]->hash2,1);
                     bp->blocks[i] = 0;
                     }
                     else if ( block->bundlei != i )
                     {
                     printf("%s %d[%d] != %d[%d]\n",bits256_str(str,block->hash2),block->hdrsi,block->bundlei,bp->ramchain.hdrsi,i);
                     CLEARBIT(bp->recv,i);
                     //memset(&bp->blocks[i]->txdatabits,0,sizeof(bp->blocks[i]->txdatabits));
                     bp->issued[i] = milliseconds();
                     iguana_blockQ(coin,bp,i,bp->blocks[i]->hash2,1);
                     bp->blocks[i] = 0;
                     } else */
                    n++;
                }
                else if ( priorityflag != 0 && qsize == 0 )//&& (bp->issued[i] == 0 || milliseconds() > (bp->issued[i] + threshold)) )
                {
                    //if ( (rand() % 1000) == 0 )
                    //    printf("priorityQ submit threshold %.3f [%d].%d\n",threshold,bp->ramchain.hdrsi,i);
                    if ( bp->blocks[i] == 0 || bp->blocks[i]->ipbits == 0 )
                    {
                        //CLEARBIT(bp->recv,i);
                        bp->issued[i] = 0;//milliseconds();
                        //if ( i < 2 )
                        //   iguana_blockQ(coin,bp,i,hash2,1);
                        //iguana_blockQ(coin,bp,i,hash2,1);
                        //bp->blocks[i] = 0;
                    }
                    lasti = i;
                } else lasti = i;
            }
            //if ( n == coin->chain->bundlesize-1 )
            //if ( n > 490 )
            //    printf("bp.%d %d %d n.%d\n",bp->ramchain.hdrsi,bp->ramchain.bundleheight,lasti,n);
            bp->numrecv = n;
            bp->datasize = datasize;
            if ( n > 0 )
            {
                bp->estsize = ((uint64_t)datasize * coin->chain->bundlesize) / n;
                //printf("estsize %d datasize.%d hdrsi.%d numrecv.%d\n",(int32_t)bp->estsize,(int32_t)datasize,bp->ramchain.hdrsi,n);
            }
            if ( n == coin->chain->bundlesize )
            {
                printf("check %d blocks in hdrs.%d\n",n,bp->ramchain.hdrsi);
                for (i=incomplete=0; i<n-1; i++)
                {
                    if ( memcmp(bp->blocks[i]->hash2.bytes,bp->blocks[i+1]->prev_block.bytes,sizeof(bits256)) != 0 )
                    {
                        if ( bits256_nonz(bp->blocks[i]->prev_block) > 0 && bits256_nonz(bp->blocks[i+1]->prev_block) > 0 && bits256_nonz(bp->blocks[i+1]->hash2) > 0 )
                        {
                            char str[65],str2[65],str3[65];
                            bits256_str(str,bp->blocks[i]->hash2);
                            bits256_str(str2,bp->blocks[i+1]->prev_block);
                            bits256_str(str3,bp->blocks[i+1]->hash2);
                            printf("%s ->%d %d<- %s %s ",str,i,i+1,str2,str3);
                            printf("broken chain in hdrs.%d %d %p <-> %p %d\n",bp->ramchain.hdrsi,i,bp->blocks[i],bp->blocks[i+1],i+1);
                            CLEARBIT(bp->recv,i);
                            //memset(&bp->blocks[i]->txdatabits,0,sizeof(bp->blocks[i]->txdatabits));
                            //memset(&bp->blocks[i+1]->txdatabits,0,sizeof(bp->blocks[i+1]->txdatabits));
                            bp->issued[i] = bp->issued[i+1] = milliseconds();
                            //iguana_blockQ(coin,bp,i,bp->blocks[i]->hash2,1);
                            //iguana_blockQ(coin,bp,i+1,bp->blocks[i+1]->hash2,1);
                            bp->blocks[i] = bp->blocks[i+1] = 0;
                            break;
                        }
                        else incomplete++;
                    }
                }
                printf("i.%d n.%d incomplete.%d\n",i,n,incomplete);
                if ( i == n-1 && incomplete == 0 )
                {
                    //if ( bp->blockhashes != 0 )
                    //{
                    for (i=0; i<n; i++)
                        iguana_hash2set(coin,"check blocks",&bp->blockhashes[i],bp->blocks[i]->hash2);
                    // iguana_hash2set(coin,"check blockhashes[0]",&bp->blockhashes[0],bp->bundlehash2);
                    // iguana_hash2set(coin,"check firsthash2",&bp->blockhashes[1],bp->firstblockhash2);
                    //}
                    iguana_bundleblockadd(coin,bp,0,iguana_bundleihash2(coin,bp,0));
                    iguana_bundleblockadd(coin,bp,coin->chain->bundlesize-1,iguana_bundleihash2(coin,bp,coin->chain->bundlesize-1));
                    if ( bp->emitfinish <= 1 )
                        iguana_emitQ(coin,bp);
                    if ( bp->emitfinish == 0 )
                        bp->emitfinish = 1;
                    coin->numpendings--;
                    return(1);
                }
            }
        }
        return(0);
    }
    /******************************************************************************
     * Copyright © 2014-2015 The SuperNET Developers.                             *
     *                                                                            *
     * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
     * the top-level directory of this distribution for the individual copyright  *
     * holder information and the developer policies on copyright and licensing.  *
     *                                                                            *
     * Unless otherwise agreed in a custom licensing agreement, no part of the    *
     * SuperNET software, including this file may be copied, modified, propagated *
     * or distributed except according to the terms contained in the LICENSE file *
     *                                                                            *
     * Removal or modification of this copyright notice is prohibited.            *
     *                                                                            *
     ******************************************************************************/
    
#include "iguana777.h"
    
    // peer context, ie massively multithreaded -> bundlesQ
    
    struct iguana_bundlereq *iguana_bundlereq(struct iguana_info *coin,struct iguana_peer *addr,int32_t type,int32_t datalen)
    {
        struct iguana_bundlereq *req; int32_t allocsize;
        allocsize = (uint32_t)sizeof(*req) + datalen;
        req = mycalloc(type,1,allocsize);
        req->allocsize = allocsize;
        req->datalen = datalen;
        req->addr = addr;
        req->coin = coin;
        req->type = type;
        return(req);
    }
    
    void iguana_gotblockM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *txdata,struct iguana_msgtx *txarray,uint8_t *data,int32_t recvlen)
    {
        struct iguana_bundlereq *req; int32_t i,z,fpos,bundlei; FILE *fp; char fname[1024];
        if ( 0 )
        {
            for (i=0; i<txdata->space[0]; i++)
                if ( txdata->space[i] != 0 )
                    break;
            if ( i != txdata->space[0] )
            {
                for (i=0; i<txdata->space[0]; i++)
                    printf("%02x ",txdata->space[i]);
                printf("extra\n");
            }
        }
        req = iguana_bundlereq(coin,addr,'B',0);
        if ( addr != 0 )
        {
            if ( addr->pendblocks > 0 )
                addr->pendblocks--;
            addr->lastblockrecv = (uint32_t)time(NULL);
            addr->recvblocks += 1.;
            addr->recvtotal += recvlen;
            if ( (txdata= iguana_blockramchainPT(coin,addr,txdata,txarray,txdata->block.txn_count,data,recvlen)) != 0 )
            {
                //fpos = (addr->fp != 0) ? ftell(addr->fp) : 0;
                //txdatabits = iguana_calctxidbits(addr->addrind,addr->filecount,(uint32_t)fpos,txdata->datalen);
                //txdatabits = iguana_peerfilePT(coin,addr,txdata->block.hash2,txdatabits,txdata->datalen);
                fpos = 0;
                if ( (bundlei= iguana_peerfname(coin,fname,addr->ipbits,txdata->block.hash2)) < 0 )
                {
                    if ( (fp= fopen(fname,"wb")) != 0 )
                        coin->peers.numfiles++;
                }
                else
                {
                    if ( (fp= fopen(fname,"rb+")) == 0 )
                    {
                        if ( (fp= fopen(fname,"wb")) != 0 )
                        {
                            z = -1;
                            coin->peers.numfiles++;
                            for (i=0; i<coin->chain->bundlesize; i++)
                                fwrite(&z,1,sizeof(z),fp);
                            fclose(fp);
                            fp = fopen(fname,"rb+");
                        }
                    }
                    if ( fp != 0 )
                    {
                        fseek(fp,0,SEEK_END);
                        fpos = (int32_t)ftell(fp);
                    }
                }
                if ( fp != 0 )
                {
                    txdata->block.bundlei = bundlei;
                    //printf("fpos.%d: bundlei.%d datalen.%d\n",fpos,bundlei,txdata->datalen);
                    fwrite(&bundlei,1,sizeof(bundlei),fp);
                    fwrite(&txdata->block.hash2,1,sizeof(txdata->block.hash2),fp);
                    fwrite(&txdata->datalen,1,sizeof(txdata->datalen),fp);
                    fwrite(txdata,1,txdata->datalen,fp);
                    if ( bundlei >= 0 && bundlei < coin->chain->bundlesize )
                    {
                        fseek(fp,bundlei * sizeof(bundlei),SEEK_SET);
                        //printf("bundlei[%d] <- fpos.%d\n",bundlei,fpos);
                        fwrite(&fpos,1,sizeof(fpos),fp);
                    } else printf("error saving with bundlei.%d vs %d\n",bundlei,coin->chain->bundlesize);
                    fclose(fp);
                    //for (i=0; i<txdata->numpkinds; i++)
                    //    printf("%016lx ",*(long *)((struct iguana_pkhash *)((long)txdata + txdata->pkoffset))[i].rmd160);
                    //printf("create.(%s) %d ",fname,bundlei,coin->peers.numfiles);
                    //printf("bundlei.%d datalen.%d T.%d U.%d S.%d P.%d X.%d\n",bundlei,txdata->datalen,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,txdata->numexternaltxids);
                    {
                        struct iguana_txblock *checktxdata; struct iguana_memspace checkmem; int32_t checkbundlei;
                        memset(&checkmem,0,sizeof(checkmem));
                        iguana_meminit(&checkmem,"checkmem",0,txdata->block.recvlen + 4096,0);
                        if ( 0 && (checktxdata= iguana_peertxdata(coin,&checkbundlei,fname,&checkmem,addr->ipbits,txdata->block.hash2)) != 0 )
                        {
                            printf("check datalen.%d bundlei.%d T.%d U.%d S.%d P.%d X.%d\n",checktxdata->datalen,checkbundlei,checktxdata->numtxids,checktxdata->numunspents,checktxdata->numspends,checktxdata->numpkinds,checktxdata->numexternaltxids);
                        }
                    }
                }
                req->datalen = txdata->datalen;
            }
        }
        coin->recvcount++;
        coin->recvtime = (uint32_t)time(NULL);
        req->block = txdata->block;
        req->addr = addr;
        req->block.txn_count = req->numtx = txdata->block.txn_count;
        queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
    }
    
    void iguana_gottxidsM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *txids,int32_t n)
    {
        struct iguana_bundlereq *req;
        printf("got %d txids from %s\n",n,addr->ipaddr);
        req = iguana_bundlereq(coin,addr,'T',0);
        req->hashes = txids, req->n = n;
        queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
    }
    
    void iguana_gotunconfirmedM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgtx *tx,uint8_t *data,int32_t datalen)
    {
        struct iguana_bundlereq *req;
        char str[65]; bits256_str(str,tx->txid);
        printf("%s unconfirmed.%s\n",addr->ipaddr,str);
        req = iguana_bundlereq(coin,addr,'U',datalen);
        req->datalen = datalen;
        memcpy(req->serialized,data,datalen);
        //iguana_freetx(tx,1);
        queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
    }
    
    void iguana_gotheadersM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n)
    {
        struct iguana_bundlereq *req;
        if ( addr != 0 )
        {
            addr->recvhdrs++;
            if ( addr->pendhdrs > 0 )
                addr->pendhdrs--;
            //printf("%s blocks[%d] ht.%d gotheaders pend.%d %.0f\n",addr->ipaddr,n,blocks[0].height,addr->pendhdrs,milliseconds());
        }
        req = iguana_bundlereq(coin,addr,'H',0);
        req->blocks = blocks, req->n = n;
        queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
    }
    
    void iguana_gotblockhashesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *blockhashes,int32_t n)
    {
        struct iguana_bundlereq *req;
        if ( addr != 0 )
        {
            addr->recvhdrs++;
            if ( addr->pendhdrs > 0 )
                addr->pendhdrs--;
        }
        req = iguana_bundlereq(coin,addr,'S',0);
        req->hashes = blockhashes, req->n = n;
        //printf("bundlesQ blockhashes.%p[%d]\n",blockhashes,n);
        queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
    }
    
    // main context, ie single threaded
    
    struct iguana_block *iguana_recvblockhdr(struct iguana_info *coin,struct iguana_bundle **bpp,int32_t *bundleip,struct iguana_block *origblock,int32_t *newhwmp)
    {
        struct iguana_bundle *prevbp,*bp = 0; int32_t j,prevbundlei; struct iguana_block *block; char str[65];
        (*bpp) = 0;
        *bundleip = -2;
        if ( (block= iguana_blockhashset(coin,-1,origblock->hash2,1)) == 0 )
        {
            printf("error getting block for %s\n",bits256_str(str,origblock->hash2));
            return(0);
        }
        block->prev_block = origblock->prev_block;
        if ( (bp= iguana_bundlefind(coin,bundleip,block->hash2,IGUANA_SEARCHBUNDLE)) == 0 )
        {
            if ( (prevbp= iguana_bundlefind(coin,&prevbundlei,block->prev_block,IGUANA_SEARCHBUNDLE)) == 0 )
            {
                printf("cant find prev.%s either\n",bits256_str(str,block->prev_block));
                for (j=0; j<coin->bundlescount; j++)
                {
                    if ( (bp= coin->bundles[j]) != 0 )
                    {
                        if ( (bp= iguana_bundlescan(coin,bundleip,bp,block->hash2,IGUANA_SEARCHBUNDLE)) != 0 )
                        {
                            (*bpp) = bp;
                            char str[65];
                            bits256_str(str,block->hash2);
                            printf("FOUND.%s in bundle.[%d:%d] %d\n",str,bp->ramchain.hdrsi,*bundleip,bp->ramchain.bundleheight + *bundleip);
                            iguana_bundleblockadd(coin,bp,*bundleip,block->hash2);
                            return(block);
                        }
                    }
                }
                char str[65];
                bits256_str(str,block->hash2);
                printf("CANTFIND.%s\n",str);
                return(block);
            }
            else
            {
                (*bpp) = prevbp;
                char str[65];
                //printf("found bp.%p prevbundlei.%d\n",prevbp,prevbundlei);
                if ( prevbundlei >= 0 && prevbundlei < coin->chain->bundlesize-1 )
                {
                    *bundleip = prevbundlei + 1;
                    if ( prevbundlei == 0 )
                        iguana_blockQ(coin,bp,0,block->prev_block,1);
                    if ( prevbp != 0 )
                    {
                        //bits256_str(str,block->hash2);
                        //printf("prev FOUND.%s in bundle.[%d:%d] %d\n",str,prevbp->ramchain.hdrsi,*bundleip,prevbp->ramchain.bundleheight + *bundleip);
                        iguana_bundleblockadd(coin,prevbp,*bundleip,block->hash2);
                    }
                }
                if ( 0 && prevbundlei == coin->chain->bundlesize-1 )
                {
                    bits256 zero;
                    memset(zero.bytes,0,sizeof(zero));
                    bits256_str(str,block->hash2);
                    printf("prev AUTOCREATE.%s\n",str);
                    iguana_bundlecreate(coin,block->hash2,zero);
                }
                return(block);
            }
        }
        else
        {
            //char str[65],str2[65];
            (*bpp) = bp;
            //printf("blockadd.%s %s %d\n",bits256_str(str,block->hash2),bits256_str(str2,origblock->hash2),*bundleip);
            iguana_bundleblockadd(coin,bp,*bundleip,block->hash2);
            if ( *bundleip > 0 && bits256_nonz(block->prev_block) > 0 )
                iguana_bundleblockadd(coin,bp,(*bundleip) - 1,block->prev_block);
        }
        return(block);
    }
    
    struct iguana_bundlereq *iguana_recvblockhashes(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *blockhashes,int32_t num)
    {
        struct iguana_bundle *bp,*newbp; bits256 zero; int32_t i,j,newbundlei,missing,bundlei = -2,bundleheight = -1;
        memset(zero.bytes,0,sizeof(zero));
        if ( (bp= iguana_bundlefind(coin,&bundlei,blockhashes[1],IGUANA_SEARCHBUNDLE)) != 0 )
        {
            if ( bp->blockhashes == 0 )
            {
                //iguana_blockQ(coin,bp,0,bp->bundlehash2,1);
                bundleheight = bp->ramchain.bundleheight;
                if ( num > coin->chain->bundlesize+1 )
                    num = coin->chain->bundlesize+1;
                //printf("GOT blockhashes.%s[%d] %d %p hdrsi.%d bundlei.%d\n",bits256_str(str,blockhashes[1]),num,bundleheight,bp->blockhashes,bp->ramchain.hdrsi,bundlei);
                memcpy(bp->blockhashes,blockhashes,num * sizeof(*blockhashes));
                bp->n = num;
                bp->ramchain.bundleheight = bundleheight;
                if ( bundlei >= 0 && bundlei < bp->n )
                {
                    j = 1;
                    if ( bundlei != 1 )
                    {
                        /*if ( bundlei == 0 )
                         {
                         for (i=1; i<num-1; i++)
                         blockhashes[i] = blockhashes[i+1];
                         memset(blockhashes[i].bytes,0,sizeof(bits256));
                         } else*/
                        
                        printf("UNEXPECTED >>>>>>>>> hdrsi.%d bundlei.%d j.%d\n",bp->ramchain.hdrsi,bundlei,j);
                        return(req);
                    }
                    for (; j<bp->n && bundlei<=coin->chain->bundlesize; bundlei++,j++)
                    {
                        //printf("%d: bundlei.%d %s j.%d\n",bundlei % coin->chain->bundlesize,bundlei,bits256_str(str,blockhashes[j]),j);
                        if ( bundlei == coin->chain->bundlesize )
                        {
                            if ( (newbp= iguana_bundlefind(coin,&newbundlei,blockhashes[j],IGUANA_SEARCHBUNDLE)) == 0 )
                            {
                                //iguana_blockQ(coin,newbp,0,blockhashes[j],1);
                                if ( j < bp->n-1 )
                                {
                                    newbp = iguana_bundlecreate(coin,blockhashes[j],blockhashes[j+1]);
                                    //iguana_blockQ(coin,newbp,1,blockhashes[j+1],1);
                                }
                                else newbp = iguana_bundlecreate(coin,blockhashes[j],zero);
                                if ( newbp != 0 )
                                {
                                    char str[65];
                                    if ( bp->ramchain.bundleheight >= 0 )
                                        newbp->ramchain.bundleheight = (bp->ramchain.bundleheight + coin->chain->bundlesize);
                                    init_hexbytes_noT(str,blockhashes[j].bytes,sizeof(bits256));
                                    queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(str),1);
                                }
                            }
                        }
                        else if ( 1 && iguana_bundleblockadd(coin,bp,bundlei,blockhashes[j]) == 0 )
                            break;
                    }
                }
                //iguana_blockQ(coin,bp,1,blockhashes[1],1);
                //if ( bp->n < coin->chain->bundlesize )
                //    iguana_blockQ(coin,bp,bp->n-1,blockhashes[bp->n-1],1);
                //else iguana_blockQ(coin,bp,coin->chain->bundlesize-1,blockhashes[coin->chain->bundlesize-1],1);
            }
            else
            {
                if ( num > 2 )
                {
                    for (i=missing=0; i<num && i<bp->n && i<coin->chain->bundlesize; i++)
                    {
                        if ( iguana_bundlescan(coin,&bundlei,bp,blockhashes[i],IGUANA_SEARCHBUNDLE) == 0 )
                        {
                            missing++;
                        }
                    }
                    if ( missing != 0 )
                    {
                        //printf("GOT MISMATCHED %d blockhashes.%s[%d] missing.%d of %d\n",bp->ramchain.bundleheight,bits256_str(blockhashes[1]),num,missing,bp->n);
                        return(req);
                    }
                    if ( num > bp->n && bp->n <= coin->chain->bundlesize )
                    {
                        /*myfree(bp->blockhashes,sizeof(*bp->blockhashes) * bp->n);
                         bp->blockhashes = mycalloc('h',num,sizeof(*blockhashes));
                         printf("replace blockhashes.%s[%d] %d %p\n",bits256_str(blockhashes[0]),num,bp->ramchain.bundleheight,bp->blockhashes);
                         memcpy(bp->blockhashes,blockhashes,num * sizeof(*blockhashes));
                         i = bp->n, bp->n = num;
                         for (; i<num; i++)
                         iguana_bundleblockadd(coin,bp,i,blockhashes[i]);*/
                        return(req);
                    }
                    char str[65];
                    bits256_str(str,blockhashes[1]);
                    if ( bp->ramchain.bundleheight >= 0 && (rand() % 1000) == 0 )
                        printf("GOT duplicate.%s[%d] bheight.%d\n",str,num,bp->ramchain.bundleheight);
                }
            }
            if ( (num= bp->n) > coin->chain->bundlesize )
                num = coin->chain->bundlesize;
        }
        else
        {
            if ( num > coin->chain->bundlesize+1 )
                num = coin->chain->bundlesize+1;
            //for (i=1; i<num; i++)
            //    iguana_blockhashset(coin,-1,blockhashes[i],1);
            if ( num > 2 )
            {
                char str[65];
                bits256_str(str,blockhashes[1]);
                //printf("recvblockhashes cant find %s num.%d\n",str,num);
                //iguana_blockQ(coin,0,-1,blockhashes[1],1);
                //iguana_bundlecreate(coin,blockhashes[1],blockhashes[2]);
                if ( 0 && num == coin->chain->bundlesize+1 && iguana_bundlefind(coin,&bundlei,blockhashes[num - 1],IGUANA_SEARCHBUNDLE) == 0 )
                {
                    bits256 zero;
                    memset(zero.bytes,0,sizeof(zero));
                    bits256_str(str,blockhashes[num - 1]);
                    printf("AUTO EXTEND2.%s[%d]\n",str,num);
                    iguana_bundlecreate(coin,blockhashes[num - 1],zero);
                }
            }
        }
        return(req);
    }
    
    struct iguana_bundlereq *iguana_recvblockhdrs(struct iguana_info *coin,struct iguana_bundlereq *req,struct iguana_block *blocks,int32_t n,int32_t *newhwmp)
    {
        int32_t i,j; struct iguana_block *block; struct iguana_bundle *bp;
        if ( blocks == 0 )
            return(req);
        if ( n > coin->chain->bundlesize+1 )
            n = coin->chain->bundlesize+1;
        // blockhashes = mycalloc('h',n+1,sizeof(*blockhashes));
        // iguana_hash2set(coin,"recvhdrs0",&bp->blockhashes[0],blocks->prev_block);
        //for (i=0; i<n; i++)
        //     iguana_hash2set(coin,"recvhdrs0",&bp->blockhashes[i+1],blocks[i].hash2);
        n++;
        for (j=0; j<coin->bundlescount; j++)
        {
            if ( (bp= coin->bundles[j]) != 0 )
            {
                if ( memcmp(blocks[0].prev_block.bytes,bp->blockhashes[0].bytes,sizeof(bits256)) == 0 )
                {
                    // iguana_hash2set(coin,"recvhdrs0",&bp->blockhashes[0],blocks->prev_block);
                    //for (i=0; i<n; i++)
                    //     iguana_hash2set(coin,"recvhdrs0",&bp->blockhashes[i+1],blocks[i].hash2);
                    if ( bp->blockhashes == 0 )
                    {
                        bp->n = n < coin->chain->bundlesize ? n : coin->chain->bundlesize;
                        for (i=1; i<bp->n; i++)
                        {
                            iguana_hash2set(coin,"blockhdrs[i]",&bp->blockhashes[i],blocks[i].hash2);
                            if ( (block= iguana_blockfind(coin,bp->blockhashes[i])) != 0 )
                                iguana_copyblock(coin,block,&blocks[i-1]);
                        }
                        /*iguana_blockQ(coin,bp,0,bp->bundlehash2,1);
                         iguana_blockQ(coin,bp,1,blockhashes[1],1);
                         if ( bp->n < coin->chain->bundlesize )
                         iguana_blockQ(coin,bp,n-1,blockhashes[n-1],1);
                         else iguana_blockQ(coin,bp,coin->chain->bundlesize-1,blockhashes[coin->chain->bundlesize-1],1);*/
                        break;
                    }
                    else
                    {
                        //printf("free duplicate blockhashes\n");
                        // myfree(blockhashes,n*sizeof(*blockhashes));
                    }
                }
            }
        }
        return(req);
    }
    
    struct iguana_bundlereq *iguana_recvblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundlereq *req,struct iguana_block *origblock,int32_t numtx,int32_t datalen,int32_t *newhwmp)
    {
        struct iguana_bundle *bp; int32_t bundlei; struct iguana_block *block; double duration = 0.;
        if ( (block= iguana_recvblockhdr(coin,&bp,&bundlei,origblock,newhwmp)) != 0 )
        {
            iguana_copyblock(coin,block,origblock);
            //printf("recvblock.(%s) bp.%p bundlei.%d\n",bits256_str(str,block->hash2),bp,bundlei);
            if ( bp != 0 && datalen > 0 )
            {
                //printf("iguana_recvblock (%s) %d[%d] bit.%d recv.%d %02x %02x\n",bits256_str(str,block->hash2),bp->ramchain.hdrsi,bundlei,GETBIT(bp->recv,bundlei),bp->numrecv,bp->recv[0],bp->recv[bp->n/8]);
                SETBIT(bp->recv,bundlei);
                if ( bp->issued[bundlei] > 0 )
                {
                    duration = (int32_t)(milliseconds() - bp->issued[bundlei]);
                    if ( duration < bp->avetime/10. )
                        duration = bp->avetime/10.;
                    else if ( duration > bp->avetime*10. )
                        duration = bp->avetime * 10.;
                    dxblend(&bp->avetime,duration,.9);
                    dxblend(&coin->avetime,bp->avetime,.9);
                }
                /*if ( bundlei < 3 )
                 {
                 if ( bundlei > 0 )
                 iguana_blockQ(coin,bp,bundlei-1,block->prev_block,1);
                 iguana_blockQ(coin,bp,bundlei,block->hash2,1);
                 }
                 if ( bundlei == 2 )
                 {
                 bp->firstblockhash2 = bp->blockhashes[1] = block->prev_block;
                 iguana_blockQ(coin,bp,bundlei,block->prev_block,1);
                 }*/
                if ( bundlei >= 0 && bundlei < bp->n && bundlei < coin->chain->bundlesize )
                {
                    if ( 0 && bundlei == 1 )
                        printf("iguana_recvblock %d[%d] bit.%d recv.%d %02x %02x\n",bp->ramchain.hdrsi,bundlei,GETBIT(bp->recv,bundlei),bp->numrecv,bp->recv[0],bp->recv[bp->n/8]);
                    if ( req->addr != 0 && req->addr->ipbits != 0 )//&& req->addr->addrind != 0 )
                        block->ipbits = req->addr->ipbits;
                    else block->ipbits = 0xffff, printf("null addr\n");
                    block->recvlen = datalen;
                    bp->blocks[bundlei] = block;
                    bp->numrecv++;
                    //iguana_txdataQ(coin,req,bp,bundlei);
                }
                
                //printf("%s hdrsi.%d recv[%d] dur.%.0f avetimes.(%.2f %.2f) numpendinds.%d %f\n",bits256_str(block->hash2),hdrs->hdrsi,bundlei,duration,hdrs->avetime,coin->avetime,coin->numpendings,hdrs->issued[bundlei]);
            }
        }
        else //if ( (rand() % 100) == 0 )
            printf("cant create block.%llx\n",(long long)origblock->hash2.txid);
        return(req);
    }
    
    struct iguana_bundlereq *iguana_recvtxids(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *txids,int32_t n)
    {
        return(req);
    }
    
    struct iguana_bundlereq *iguana_recvunconfirmed(struct iguana_info *coin,struct iguana_bundlereq *req,uint8_t *data,int32_t datalen)
    {
        return(req);
    }
    
    int32_t iguana_processbundlesQ(struct iguana_info *coin,int32_t *newhwmp) // single threaded
    {
        int32_t flag = 0; struct iguana_bundlereq *req;
        *newhwmp = 0;
        while ( flag < 10000 && (req= queue_dequeue(&coin->bundlesQ,0)) != 0 )
        {
            //printf("%s bundlesQ.%p type.%c n.%d\n",req->addr != 0 ? req->addr->ipaddr : "0",req,req->type,req->n);
            if ( req->type == 'B' ) // one block with all txdata
                req = iguana_recvblock(coin,req->addr,req,&req->block,req->numtx,req->datalen,newhwmp);
            else if ( req->type == 'H' ) // blockhdrs (doesnt have txn_count!)
            {
                if ( (req= iguana_recvblockhdrs(coin,req,req->blocks,req->n,newhwmp)) != 0 )
                {
                    if ( req->blocks != 0 )
                        myfree(req->blocks,sizeof(*req->blocks) * req->n), req->blocks = 0;
                }
            }
            else if ( req->type == 'S' ) // blockhashes
            {
                if ( (req= iguana_recvblockhashes(coin,req,req->hashes,req->n)) != 0 && req->hashes != 0 )
                    myfree(req->hashes,sizeof(*req->hashes) * req->n), req->hashes = 0;
            }
            else if ( req->type == 'U' ) // unconfirmed tx
                req = iguana_recvunconfirmed(coin,req,req->serialized,req->datalen);
            else if ( req->type == 'T' ) // txids from inv
            {
                if ( (req= iguana_recvtxids(coin,req,req->hashes,req->n)) != 0 )
                    myfree(req->hashes,(req->n+1) * sizeof(*req->hashes)), req->hashes = 0;
            }
            else printf("iguana_updatebundles unknown type.%c\n",req->type);
            flag++;
            if ( req != 0 )
                myfree(req,req->allocsize), req = 0;
        }
        return(flag);
    }
    
    
    int32_t iguana_issueloop(struct iguana_info *coin)
    {
        static uint32_t lastdisp;
        int32_t i,closestbundle,bundlei,qsize,RTqsize,m,numactive,numwaiting,maxwaiting,lastbundle,n,dispflag = 0,flag = 0;
        int64_t remaining,closest; struct iguana_bundle *bp,*prevbp,*nextbp; bits256 hash2; struct iguana_block *block;
        if ( time(NULL) > lastdisp+13 )
        {
            dispflag = 1;
            lastdisp = (uint32_t)time(NULL);
        }
        qsize = queue_size(&coin->blocksQ);
        if ( qsize == 0 )
            coin->bcount++;
        else coin->bcount = 0;
        maxwaiting = (coin->MAXBUNDLES * coin->chain->bundlesize);
        numwaiting = 0;
        numactive = 0;
        prevbp = nextbp = 0;
        lastbundle = -1;
        for (i=coin->bundlescount-1; i>=0; i--)
            if ( (bp= coin->bundles[i]) != 0 && bp->emitfinish == 0 && bp->blockhashes != 0 )
            {
                lastbundle = i;
                break;
            }
        if ( lastbundle != coin->lastbundle )
            coin->lastbundletime = (uint32_t)time(NULL);
        coin->lastbundle = lastbundle;
        if ( 0 && time(NULL) < coin->starttime+60 )
            lastbundle = -1;
        n = 0;
        closest = closestbundle = -1;
        for (i=0; i<coin->bundlescount; i++)
        {
            qsize = queue_size(&coin->blocksQ);
            m = 0;
            if ( (bp= coin->bundles[i]) != 0 )
            {
                nextbp = (i < coin->bundlescount-1) ? coin->bundles[i+1] : 0;
                if ( bp->emitfinish == 0 )
                {
                    //iguana_bundlecheck(coin,bp,numactive == 0 || i == coin->closestbundle || i == lastbundle);
                    iguana_bundlecheck(coin,bp,i == coin->closestbundle);
                    if ( bp->numrecv > 3 || numactive == 0 )
                    {
                        numactive++;
                        remaining = (bp->estsize - bp->datasize) + (rand() % (1 + bp->estsize))/100;
                        if ( remaining > 0 && (closest < 0 || remaining < closest) )
                        {
                            //printf("closest.[%d] %d -> R.%d (%d - %d)\n",closestbundle,(int)closest,(int)remaining,(int)bp->estsize,(int)bp->datasize);
                            closest = remaining;
                            closestbundle = i;
                        }
                    }
                    //if (  i < (coin->numemitted+coin->MAXPENDING) && numactive >= coin->MAXPENDING && i != coin->closestbundle && i != lastbundle )
                    continue;
                    RTqsize = queue_size(&coin->blocksQ);
                    for (bundlei=0; bundlei<bp->n && bundlei<coin->chain->bundlesize; bundlei++)
                    {
                        if ( (block= bp->blocks[bundlei]) != 0 && block->ipbits != 0 )
                        {
                            m++;
                            //printf("hashes.%p numrecv.%d hdrs->n.%d qsize.%d\n",bp->blockhashes,bp->numrecv,bp->n,qsize);
                            continue;
                        }
                        hash2 = iguana_bundleihash2(coin,bp,bundlei);
                        if ( bits256_nonz(hash2) > 0 )
                        {
                            //printf("hdrsi.%d qsize.%d bcount.%d check bundlei.%d bit.%d %.3f lag %.3f ave %.3f\n",bp->ramchain.hdrsi,qsize,coin->bcount,bundlei,GETBIT(bp->recv,bundlei),bp->issued[bundlei],milliseconds() - bp->issued[bundlei],bp->avetime);
                            if ( (block= bp->blocks[bundlei]) == 0 || block->ipbits == 0 )
                                //if ( GETBIT(bp->recv,bundlei) == 0 )
                            {
                                if ( bp->issued[bundlei] > SMALLVAL )
                                    numwaiting++;
                                if ( numwaiting < maxwaiting && (bp->issued[bundlei] == 0 || (qsize == 0 && coin->bcount > 100 && milliseconds() > (bp->issued[bundlei] + bp->avetime*2))) )//()) )
                                {
                                    if ( RTqsize < maxwaiting && (i == lastbundle || i == coin->closestbundle) )
                                    {
                                        char str[65];
                                        bits256_str(str,hash2);
                                        if ( (rand() % 10000) == 0 && bp->issued[bundlei] > SMALLVAL )
                                            printf("issue.%d:%d of %d %s lag %f ave %f\n",bp->ramchain.hdrsi,bundlei,bp->n,str,milliseconds() - bp->issued[bundlei],bp->avetime);
                                        bp->issued[bundlei] = milliseconds();
                                        n++;
                                        flag += (iguana_blockQ(coin,bp,bundlei,hash2,0) > 0);
                                    }
                                }
                            }
                        } //lse printf("skip.%d %s\n",numbundles,bits256_str(hash2));
                    }
                } else m = coin->chain->bundlesize;
            }
            prevbp = bp;
            if ( dispflag != 0 && bp != 0 && bp->emitfinish == 0 && m > 0 )
                printf("%s",iguana_bundledisp(coin,prevbp,bp,nextbp,m));
        }
        //if ( closestbundle >= 0 && (coin->closestbundle < 0 || coin->bundles[coin->closestbundle]->numrecv >= coin->chain->bundlesize) )
        coin->closestbundle = closestbundle;
        char str[65];
        if ( dispflag != 0 )
            printf(" PENDINGBUNDLES lastbundle.%d closest.[%d] %s | %d\n",lastbundle,closestbundle,mbstr(str,closest),coin->closestbundle);
        return(flag);
    }
    
    int32_t iguana_reqhdrs(struct iguana_info *coin)
    {
        int32_t i,n = 0; struct iguana_bundle *bp; char hashstr[65];
        //printf("needhdrs.%d qsize.%d zcount.%d\n",iguana_needhdrs(coin),queue_size(&coin->hdrsQ),coin->zcount);
        if ( iguana_needhdrs(coin) > 0 && queue_size(&coin->hdrsQ) == 0 )
        {
            if ( coin->zcount++ > 10 )
            {
                for (i=0; i<coin->bundlescount; i++)
                {
                    if ( (bp= coin->bundles[i]) != 0 )
                    {
                        if ( time(NULL) > bp->issuetime+7 )//&& coin->numpendings < coin->MAXBUNDLES )
                        {
                            if ( bp->issuetime == 0 )
                                coin->numpendings++;
                            if ( bp->blockhashes == 0 || bp->n < coin->chain->bundlesize )
                            {
                                char str[65];
                                bits256_str(str,bp->blockhashes[0]);
                                printf("(%s %d).%d ",str,bp->ramchain.bundleheight,i);
                                init_hexbytes_noT(hashstr,bp->blockhashes[0].bytes,sizeof(bits256));
                                queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
                                n++;
                            }
                            bp->issuetime = (uint32_t)time(NULL);
                        }
                    }
                }
                if ( n > 0 )
                    printf("REQ HDRS pending.%d\n",coin->numpendings);
                coin->zcount = 0;
            }
        } else coin->zcount = 0;
        return(n);
    }
    
    int32_t iguana_updatecounts(struct iguana_info *coin)
    {
        int32_t h,flag = 0;
        //SETBIT(coin->havehash,0);
        //while ( iguana_havetxdata(coin,coin->blocks.recvblocks) != 0 )
        //    coin->blocks.recvblocks++;
        //if ( coin->blocks.recvblocks < 1 )
        //    coin->blocks.recvblocks = 1;
        //while ( GETBIT(coin->havehash,coin->blocks.hashblocks) > 0 )
        //    coin->blocks.hashblocks++;
        h = coin->blocks.hwmheight - coin->chain->bundlesize;
        flag = 0;
        while ( 0 && iguana_bundleready(coin,h) > 0 )
        {
            h += coin->chain->bundlesize;
            flag++;
        }
        if ( flag != 0 )
            iguana_savehdrs(coin);
        return(flag);
    }
    
    int32_t iguana_processrecv(struct iguana_info *coin) // single threaded
    {
        int32_t newhwm = 0,flag = 0;
        //printf("process bundlesQ\n");
        flag += iguana_processbundlesQ(coin,&newhwm);
        //printf("iguana_updatecounts\n");
        flag += iguana_updatecounts(coin);
        //printf("iguana_reqhdrs\n");
        flag += iguana_reqhdrs(coin);
        //printf("iguana_issueloop\n");
        flag += iguana_issueloop(coin);
        //if ( newhwm != 0 )
        //    flag += iguana_lookahead(coin,&hash2,coin->blocks.hwmheight);
        return(flag);
    }
    
    
    struct iguana_block *iguana_recvblockhdr(struct iguana_info *coin,struct iguana_bundle **bpp,int32_t *bundleip,struct iguana_block *origblock,int32_t *newhwmp)
    {
        struct iguana_bundle *prevbp,*bp = 0; int32_t j,prevbundlei; struct iguana_block *block; char str[65];
        (*bpp) = 0;
        *bundleip = -2;
        if ( (block= iguana_blockhashset(coin,-1,origblock->hash2,1)) == 0 )
        {
            printf("error getting block for %s\n",bits256_str(str,origblock->hash2));
            return(0);
        }
        block->prev_block = origblock->prev_block;
        if ( (bp= iguana_bundlefind(coin,bundleip,block->hash2,IGUANA_SEARCHBUNDLE)) == 0 )
        {
            if ( (prevbp= iguana_bundlefind(coin,&prevbundlei,block->prev_block,IGUANA_SEARCHBUNDLE)) == 0 )
            {
                printf("cant find prev.%s either\n",bits256_str(str,block->prev_block));
                for (j=0; j<coin->bundlescount; j++)
                {
                    if ( (bp= coin->bundles[j]) != 0 )
                    {
                        if ( (bp= iguana_bundlescan(coin,bundleip,bp,block->hash2,IGUANA_SEARCHBUNDLE)) != 0 )
                        {
                            (*bpp) = bp;
                            char str[65];
                            bits256_str(str,block->hash2);
                            printf("FOUND.%s in bundle.[%d:%d] %d\n",str,bp->ramchain.hdrsi,*bundleip,bp->ramchain.bundleheight + *bundleip);
                            iguana_bundleblockadd(coin,bp,*bundleip,block->hash2);
                            return(block);
                        }
                    }
                }
                char str[65];
                bits256_str(str,block->hash2);
                printf("CANTFIND.%s\n",str);
                return(block);
            }
            else
            {
                (*bpp) = prevbp;
                char str[65];
                //printf("found bp.%p prevbundlei.%d\n",prevbp,prevbundlei);
                if ( prevbundlei >= 0 && prevbundlei < coin->chain->bundlesize-1 )
                {
                    *bundleip = prevbundlei + 1;
                    if ( prevbundlei == 0 )
                        iguana_blockQ(coin,bp,0,block->prev_block,1);
                    if ( prevbp != 0 )
                    {
                        //bits256_str(str,block->hash2);
                        //printf("prev FOUND.%s in bundle.[%d:%d] %d\n",str,prevbp->ramchain.hdrsi,*bundleip,prevbp->ramchain.bundleheight + *bundleip);
                        iguana_bundleblockadd(coin,prevbp,*bundleip,block->hash2);
                    }
                }
                if ( 0 && prevbundlei == coin->chain->bundlesize-1 )
                {
                    bits256 zero;
                    memset(zero.bytes,0,sizeof(zero));
                    bits256_str(str,block->hash2);
                    printf("prev AUTOCREATE.%s\n",str);
                    iguana_bundlecreate(coin,block->hash2,zero);
                }
                return(block);
            }
        }
        else
        {
            //char str[65],str2[65];
            (*bpp) = bp;
            //printf("blockadd.%s %s %d\n",bits256_str(str,block->hash2),bits256_str(str2,origblock->hash2),*bundleip);
            iguana_bundleblockadd(coin,bp,*bundleip,block->hash2);
            if ( *bundleip > 0 && bits256_nonz(block->prev_block) > 0 )
                iguana_bundleblockadd(coin,bp,(*bundleip) - 1,block->prev_block);
        }
        return(block);
    }
    
    /*static int32_t _sort_by_itemind(struct iguana_block *a, struct iguana_block *b)
     {
     if (a->hh.itemind == b->hh.itemind) return 0;
     return (a->hh.itemind < b->hh.itemind) ? -1 : 1;
     }*/
    
    int32_t _iguana_verifysort(struct iguana_info *coin)
    {
        int32_t height,prevheight = -1,i = 0,run = 0; struct iguana_block *block,*tmp;
        HASH_ITER(hh,coin->blocks.hash,block,tmp)
        {
            if ( (height= block->hh.itemind) < 0 )
                printf("sortblocks error i.%d height.%d?\n",i,height), getchar();
            if ( height <= prevheight )
                printf("sortblocks error i.%d height.%d vs prevheight.%d\n",i,height,prevheight), getchar();
            if ( height == run )
                run++;
            i++;
        }
        printf("_iguana_verifysort: n.%d run.%d\n",i,run);
        return(run);
    }
    
    /*int32_t iguana_blocksort(struct iguana_info *coin)
     {
     int32_t hashblocks;
     portable_mutex_lock(&coin->blocks_mutex);
     HASH_SORT(coin->blocks.hash,_sort_by_itemind);
     hashblocks = _iguana_verifysort(coin);
     portable_mutex_unlock(&coin->blocks_mutex);
     return(hashblocks);
     }*/
    
    int32_t _iguana_blocklink(struct iguana_info *coin,struct iguana_block *block)
    {
        int32_t height,n = 0; struct iguana_block *prev,*next;
        if ( block == 0 )
            printf("iguana_blockslink: illegal null block %p\n",block), getchar();
        block->hh.next = 0, block->hh.prev = 0;
        if ( (height= (int32_t)block->hh.itemind) > 0 && (prev= iguana_block(coin,height-1)) != 0 )
        {
            prev->hh.next = block;
            block->hh.prev = prev;
            n++;
        }
        if ( (next= iguana_block(coin,height+1)) != 0 )
        {
            block->hh.next = next;
            next->hh.prev = block;
            n++;
        }
        return(n);
    }
    
    /*bits256 iguana_prevblockhash(struct iguana_info *coin,bits256 hash2)
     {
     struct iguana_block *block; bits256 tmp;
     if ( bits256_nonz(hash2) > 0 && (block= iguana_blockfind(coin,hash2)) != 0 )
     return(block->prev_block);
     else
     {
     memset(tmp.bytes,0,sizeof(tmp));
     return(tmp);
     }
     }*/
    
    int32_t iguana_hash2height(struct iguana_info *coin,bits256 hash2)
    {
        struct iguana_block *block;
        if ( (block= iguana_blockfind(coin,hash2)) != 0 )
        {
            if ( block->height >= 0 )
                return(block->height);
            else return(block->hh.itemind);
        }
        else return(-1);
    }
    
    int32_t iguana_blockheight(struct iguana_info *coin,struct iguana_block *block)
    {
        struct iguana_block *prev; int32_t height;
        if ( (height= iguana_hash2height(coin,block->hash2)) < 0 )
        {
            if ( (prev= iguana_blockfind(coin,block->prev_block)) != 0 )
            {
                if ( prev->height >= 0 )
                    return(prev->height+1);
                else if ( (int32_t)prev->hh.itemind >= 0 )
                    return(prev->hh.itemind + 1);
            }
        }
        return(-1);
    }
    
    int32_t iguana_chainheight(struct iguana_info *coin,struct iguana_block *block)
    {
        if ( block->mainchain != 0 && block->height >= 0 )
            return(block->height);
        return(-1);
    }
    
    void *iguana_blockptr(struct iguana_info *coin,int32_t height)
    {
        struct iguana_block *block;
        if ( height < 0 || height >= coin->blocks.maxbits )
        {
            //printf("iguana_blockptr height.%d vs maxbits.%d\n",height,coin->blocks.maxbits);
            return(0);
        }
        if ( (block= coin->blocks.ptrs[height]) != 0 )
            return(block);
        return(0);
    }
    
    /*void *iguana_bundletxdata(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei)
     {
     struct iguana_block *block; void *txdata = 0;
     if ( bp != 0 && bundlei >= 0 && bundlei < coin->chain->bundlesize && GETBIT(bp->recv,bundlei) != 0 && (block= bp->blocks[bundlei]) != 0 )
     {
     txdata = block->txdata;
     }
     //printf("txdata.%p\n",txdata);
     return(txdata);
     }*/
    
    int32_t iguana_avail(struct iguana_info *coin,int32_t height,int32_t n)
    {
        int32_t i,nonz = 0;
        for (i=0; i<n; i++)
            if ( iguana_blockptr(coin,height+i) != 0 )
                nonz++;
        return(nonz);
    }
    
    /*int32_t iguana_bundleready(struct iguana_info *coin,int32_t height)
     {
     int32_t i,num = coin->chain->bundlesize;
     if ( GETBIT(coin->bundleready,height/num) != 0 )
     return(1);
     for (i=0; i<num; i++)
     if ( iguana_havehash(coin,height+i) <= 0 )
     return(0);
     SETBIT(coin->bundleready,height/num);
     return(1);
     }
     
     int32_t iguana_fixblocks(struct iguana_info *coin,int32_t startheight,int32_t endheight)
     {
     struct iguana_block *block,space,origblock; int32_t height,n = 0;
     for (height=startheight; height<=endheight; height++)
     {
     if ( (block= iguana_block(coin,&space,height)) != 0 )
     {
     origblock = space;
     iguana_setdependencies(coin,block);
     if ( memcmp(&origblock,block,sizeof(origblock)) != 0 )
     {
     printf("%d ",height);
     n++;
     iguana_kvwrite(coin,coin->blocks.db,0,block,(uint32_t *)&block->height);
     }
     }
     }
     iguana_syncmap(&coin->blocks.db->M,0);
     return(n);
     }
     
     int32_t iguana_blockcmp(struct iguana_info *coin,struct iguana_block *A,struct iguana_block *B,int32_t fastflag)
     {
     struct iguana_block tmpA,tmpB;
     tmpA = *A, tmpB = *B;
     memset(&tmpA.L,0,sizeof(tmpA.L)), memset(&tmpB.L,0,sizeof(tmpB.L));
     memset(&tmpA.hh,0,sizeof(tmpA.hh)), memset(&tmpB.hh,0,sizeof(tmpB.hh));
     tmpA.numvouts = tmpA.numvins = tmpA.tbd = tmpB.numvouts = tmpB.numvins = tmpB.tbd = 0;
     if ( memcmp(&tmpA,&tmpB,sizeof(tmpA)) != 0 )
     return(-1);
     if ( fastflag == 0 )
     {
     if ( iguana_setdependencies(coin,&tmpA) != iguana_setdependencies(coin,&tmpB) || memcmp(&tmpA,&tmpB,sizeof(tmpA)) == 0 )
     return(-1);
     }
     return(0);
     }*/
    
    /*
     int32_t iguana_checkblock(struct iguana_info *coin,int32_t dispflag,struct iguana_block *block,bits256 hash2)
     {
     struct iguana_block checkspace,prevspace,*checkblock,*prev; bits256 prevhash; int32_t retval = 0;
     if ( block != 0 )
     {
     if ( (checkblock= iguana_block(coin,&checkspace,block->height)) == 0 )
     {
     if ( dispflag != 0 )
     printf("cant find checkblock %s at %d\n",bits256_str(hash2),block->height);
     return(-2);
     }
     if ( memcmp(block,checkblock,sizeof(*block)) != 0 )
     {
     if ( dispflag != 0 )
     printf("compare error %s block.%d vs checkblock.%d\n",bits256_str(hash2),block->height,checkblock->height);
     return(-3);
     }
     prevhash = iguana_prevblockhash(coin,hash2);
     if ( bits256_nonz(prevhash) != 0 )
     {
     if ( memcmp(prevhash.bytes,block->prev_block.bytes,sizeof(prevhash)) != 0 )
     {
     if ( dispflag != 0 )
     {
     printf("height.%d block->prev %s vs ",block->height,bits256_str(block->prev_block));
     printf("prevhash mismatch %s\n",bits256_str(prevhash));
     }
     return(-4);
     }
     } else prevhash = block->prev_block;
     if ( block->height == 0 )
     {
     //printf("reached genesis! numvalid.%d from %s\n",numvalid,bits256_str(coin->blocks.best_chain));
     return(0);
     }
     //printf("block.%d\n",block->height);
     if ( (prev= iguana_blockfind(coin,&prevspace,prevhash)) == 0 )
     {
     if ( dispflag != 0 )
     printf("cant find prevhash for (%s).%d\n",bits256_str(hash2),block->height);
     return(-5);
     } //else printf("block->height.%d prev height.%d %s\n",block->height,prev->height,bits256_str(prevhash));
     if ( fabs(block->L.PoW - (prev->L.PoW + PoW_from_compact(block->bits,coin->chain->unitval))) > SMALLVAL )
     {
     if ( dispflag != 0 )
     printf("PoW mismatch: %s %.15f != %.15f (%.15f %.15f)\n",bits256_str(hash2),block->L.PoW,(prev->L.PoW + PoW_from_compact(block->bits,coin->chain->unitval)),prev->L.PoW,PoW_from_compact(block->bits,coin->chain->unitval));
     block->L.PoW = (prev->L.PoW + PoW_from_compact(block->bits,coin->chain->unitval));
     retval = -1000;
     }
     if ( block->txn_count != 0 && block->L.numtxids != (prev->L.numtxids + prev->txn_count) && block->L.numunspents != (prev->L.numunspents + prev->numvouts) && block->L.numspends != (prev->L.numspends + prev->numvins) )
     {
     if ( dispflag != 0 )
     printf("firsttxidind mismatch %s T%d != %d (%d + %d) || U%d != %d (%d + %d) || S%d != %d (%d + %d)\n",bits256_str(hash2),block->L.numtxids,(prev->L.numtxids + prev->txn_count),prev->L.numtxids,prev->txn_count,block->L.numunspents,(prev->L.numunspents + prev->numvouts),prev->L.numunspents,prev->numvouts,block->L.numspends,(prev->L.numspends + prev->numvins),prev->L.numspends,prev->numvins);
     block->L.numtxids = (prev->L.numtxids + prev->txn_count);
     block->L.numunspents = (prev->L.numunspents + prev->numvouts);
     block->L.numspends = (prev->L.numspends + prev->numvins);
     return(retval - 10000);
     }
     return(retval);
     }
     if ( dispflag != 0 )
     printf("iguana_checkblock: null ptr\n");
     return(-8);
     }
     
     int32_t _iguana_audit(struct iguana_info *coin)
     {
     bits256 hash2; struct iguana_block *block,space; int32_t numvalid = 0;
     hash2 = coin->blocks.hwmchain;
     while ( (block= iguana_blockfind(coin,&space,hash2)) != 0 )
     {
     if ( iguana_checkblock(coin,1,block,hash2) == 0 )
     {
     numvalid++;
     if ( block->height == 0 )
     return(numvalid);
     hash2 = block->prev_block;
     }
     }
     printf("iguana_audit numvalid.%d vs %d\n",numvalid,coin->blocks.hwmheight);
     return(numvalid);
     }
     
     void iguana_audit(struct iguana_info *coin)
     {
     int32_t numvalid;
     if ( (numvalid= _iguana_audit(coin)) < 0 || numvalid != coin->blocks.hwmheight )
     {
     printf("iguana_audit error.%d\n",numvalid);
     iguana_kvdisp(coin,coin->blocks.db);
     }
     }*/
    
    
    /*int32_t iguana_lookahead(struct iguana_info *coin,bits256 *hash2p,int32_t height)
     {
     struct iguana_block space,*block; bits256 hash2; int32_t err,h,n = 0;
     while ( (block= iguana_block(coin,&space,height)) != 0 )
     {
     *hash2p = hash2 = iguana_blockhash(coin,height);
     if ( (err= iguana_checkblock(coin,1,block,hash2)) == 0 || err <= -1000 )
     {
     if ( err < 0 )
     {
     h = height;
     printf("fixup height.%d\n",height);
     iguana_kvwrite(coin,coin->blocks.db,hash2.bytes,block,(uint32_t *)&h);
     //getchar();
     }
     if ( (h= iguana_addblock(coin,hash2,block)) != height )
     {
     printf("height.%d h.%d n.%d didnt work\n",height,h,n);
     //getchar();
     break;
     }
     n++;
     height++;
     coin->blocks.hwmheight = height;
     }
     else
     {
     printf("height.%d %s error.%d\n",height,bits256_str(hash2),err);
     break;
     }
     }
     printf("lookahead stopped at height.%d\n",height);
     return(n);
     }
     */
    
    int32_t iguana_setchainvars(struct iguana_info *coin,struct iguana_prevdep *lp,bits256 hash2,uint32_t nBits,bits256 prevhash,int32_t txn_count) // uint32_t *firsttxidindp,uint32_t *firstvoutp,uint32_t *firstvinp,double *PoWp
    {
        int32_t height=-1,firstvout=0,firstvin=0,firsttxidind=0; double PoW;
        struct iguana_prevdep *prevlp; struct iguana_block *prev;
        memset(lp,0,sizeof(*lp));
        if ( memcmp(coin->chain->genesis_hashdata,hash2.bytes,sizeof(hash2)) == 0 )
        {
            PoW = PoW_from_compact(nBits,coin->chain->unitval);
            height = 0;
            firsttxidind = firstvout = firstvin = 1;
            printf("set genesis vars nBits.%x\n",nBits);
        }
        else
        {
            if ( (prev= iguana_blockfind(coin,prevhash)) == 0 )
            {
                if ( iguana_needhdrs(coin) == 0 )
                {
                    char str[65],str2[65];
                    bits256_str(str,hash2);
                    bits256_str(str2,prevhash);
                    printf("hash2.(%s) ",str);
                    fprintf(stderr,"iguana_blockchain no prev block.(%s)\n",str2);
                    //getchar();
                }
                return(-1);
            }
            else
            {
                height = prev->height + 1;
                if ( (prevlp= iguana_prevdepfind(coin,prev)) != 0 )
                {
                    PoW = (PoW_from_compact(nBits,coin->chain->unitval) + prevlp->PoW);
                    if ( txn_count > 0 && prevlp->numtxids > 0 && prev->numvouts > 0 && prevlp->numunspents > 0 && prevlp->numspends > 0 )
                    {
                        firsttxidind = prevlp->numtxids + prev->txn_count;
                        firstvout = prevlp->numunspents + prev->numvouts;
                        firstvin = prevlp->numspends + prev->numvins;
                        //printf("PREV.%d firsttxidind.%d firstvout.%d+%d firstvin.%d+%d (%d %d %d)\n",prev->height,prev->L.numtxids,prev->L.numunspents,prev->numvouts,prev->L.numspends,prev->numvins,firsttxidind,firstvout,firstvin);
                    }
                }
            }
        }
        if ( lp != 0 )
        {
            lp->PoW = PoW;
            lp->numtxids = firsttxidind;
            lp->numunspents = firstvout;
            lp->numspends = firstvin;
        }
        //printf("set height.%d: %d %f firstvin.%d firstvout.%d\n",height,firsttxidind,PoW,firstvin,firstvout);
        return(height);
    }
    
    int32_t iguana_setdependencies(struct iguana_info *coin,struct iguana_block *block,struct iguana_prevdep *lp)
    {
        int32_t h,height;
        if ( block == 0 )
            return(-1);
        height = block->height;
        if ( (h= iguana_setchainvars(coin,lp,block->hash2,block->bits,block->prev_block,block->txn_count)) == height )
        {
            // place to make sure connected to ramchain
            return(height);
        }
        if ( height < 0 )
            block->height = h;
        //printf("dependencies returned %d vs %d\n",h,height);
        return(-1);
    }
    
    int32_t iguana_chainextend(struct iguana_info *coin,struct iguana_block *newblock)
    {
        int32_t h;
        if ( (newblock->height= iguana_setdependencies(coin,newblock,lp)) >= 0 )
        {
            if ( lp->PoW > coin->blocks.hwmPoW )
            {
                if ( newblock->height+1 > coin->blocks.maxblocks )
                    coin->blocks.maxblocks = (newblock->height + 1);
                h = newblock->height;
                iguana_kvwrite(coin,coin->blocks.db,hash2.bytes,newblock,(uint32_t *)&h);
                coin->blocks.hwmheight = newblock->height;
                coin->blocks.hwmPoW = lp->PoW;
                coin->blocks.hwmchain = hash2;
                coin->latest.blockhash = hash2;
                coin->latest.merkle_root = newblock->merkle_root;
                coin->latest.timestamp = newblock->timestamp;
                coin->latest.height = coin->blocks.hwmheight;
                char str[65],str2[65];
                bits256_str(str,newblock->hash2);
                bits256_str(str2,coin->blocks.hwmchain);
                printf("ADD %s %d:%d <- (%s) n.%u max.%u PoW %f 1st.%d numtx.%d\n",str,h,newblock->height,str2,coin->blocks.hwmheight+1,coin->blocks.maxblocks,lp->PoW,lp->numtxids,newblock->txn_count);
            }
        } else printf("error from setchain.%d\n",newblock->height);
        if ( memcmp(hash2.bytes,coin->blocks.hwmchain.bytes,sizeof(hash2)) != 0 )
        {
            char str[65];
            bits256_str(str,hash2);
            if ( iguana_needhdrs(coin) == 0 )
                printf("ORPHAN.%s height.%d PoW %f vs best %f\n",str,newblock->height,lp->PoW,coin->blocks.hwmPoW);
            newblock->height = -1;
        }
        return(newblock->height);
    }
    
    else if ( strcmp(H->command,"headers") == 0 )
    {
        struct iguana_msgblock msg; struct iguana_block *blocks; uint32_t n; struct iguana_prevdep L;
        len = iguana_rwvarint32(0,data,&n);
        if ( n <= IGUANA_MAXINV )
        {
            blocks = mycalloc('i',1,sizeof(*blocks) * n);
            height = -1;
            memset(&L,0,sizeof(L));
            for (i=0; i<n; i++)
            {
                len += iguana_rwblock(0,&hash2,&data[len],&msg);
                if ( i == 0 )
                    height = iguana_setchainvars(coin,&L,hash2,msg.H.bits,msg.H.prev_block,msg.txn_count);
                    iguana_convblock(&blocks[i],&msg,hash2,height);
                    if ( L.numtxids > 0 )
                    {
                        height++;
                        L.numtxids += blocks[i].txn_count;
                        L.PoW += PoW_from_compact(blocks[i].bits,coin->chain->unitval);
                    }
            }
            //printf("GOT HEADERS n.%d len.%d\n",n,len);
            iguana_gotheadersM(coin,addr,blocks,n);
            //myfree(blocks,sizeof(*blocks) * n);
            if ( len == datalen && addr != 0 )
                addr->msgcounts.headers++;
        } else printf("got unexpected n.%d for headers\n",n);
            }
    
    /*int32_t iguana_chainheight(struct iguana_info *coin,struct iguana_block *origblock)
     {
     static const bits256 zero; struct iguana_block *next,*block = origblock;
     bits256 *blockhashes; char str[65]; int32_t i,max,toofar=0,height,n=0;
     next = origblock;
     iguana_memreset(&coin->blockMEM);
     max = (int32_t)(coin->blockMEM.totalsize / sizeof(*blockhashes));
     blockhashes = iguana_memalloc(&coin->blockMEM,max*sizeof(*blockhashes),1);
     while ( memcmp(block->prev_block.bytes,zero.bytes,sizeof(bits256)) != 0 )
     {
     if ( n < max-1 )
     blockhashes[n++] = block->hash2;
     else toofar = 1;
     if ( (block= iguana_blockfind(coin,block->prev_block)) != 0 )
     {
     //printf("i.%d %s chainheight.%d mainchain.%d\n",n,bits256_str(str,block->hash2),block->height,block->mainchain);
     if ( block->mainchain != 0 && (height= block->height) >= 0 )
     {
     iguana_chainextend(coin,next);
     //printf("%s extend.%d from %d toofar.%d\n",bits256_str(str,block->hash2),n,height,toofar);
     if ( toofar == 0 )
     {
     for (i=0; i<n; i++)
     {
     if ( (block= iguana_blockfind(coin,blockhashes[n-1-i])) == 0 )
     {
     printf("%d of %d: cant find block.%s or cant extend\n",i,n,bits256_str(str,blockhashes[n-1-i]));
     return(origblock->height);
     }
     if ( iguana_chainextend(coin,next) < 0 )
     {
     //printf("%d of %d: cant extend block.%s\n",i,n,bits256_str(str,blockhashes[n-1-i]));
     return(origblock->height);
     }
     next = block;
     }
     return(origblock->height);
     }
     //printf("toofar means neg height\n");
     return(-1);
     }
     next = block;
     } else break;
     } // reached deadend or too far to link in
     //printf("out of chainheight loop\n");
     return(origblock->height);
     }*/
    
    
    /*int32_t iguana_issueloop(struct iguana_info *coin)
     {
     static uint32_t lastdisp;
     int32_t i,closestbundle,qsize,m,numactive,numwaiting,maxwaiting,lastbundle,n,dispflag = 0,flag = 0;
     int64_t remaining,closest; struct iguana_bundle *bp,*prevbp,*nextbp;
     flag = iguana_reqhdrs(coin);
     if ( time(NULL) > lastdisp+13 )
     {
     dispflag = 1;
     lastdisp = (uint32_t)time(NULL);
     }
     qsize = queue_size(&coin->blocksQ);
     if ( qsize == 0 )
     coin->bcount++;
     else coin->bcount = 0;
     maxwaiting = (coin->MAXBUNDLES * coin->chain->bundlesize);
     numwaiting = 0;
     numactive = 0;
     prevbp = nextbp = 0;
     lastbundle = -1;
     for (i=coin->bundlescount-1; i>=0; i--)
     if ( (bp= coin->bundles[i]) != 0 && bp->emitfinish == 0 && bp->blockhashes != 0 )
     {
     lastbundle = i;
     break;
     }
     if ( lastbundle != coin->lastbundle )
     coin->lastbundletime = (uint32_t)time(NULL);
     coin->lastbundle = lastbundle;
     if ( 0 && time(NULL) < coin->starttime+60 )
     lastbundle = -1;
     n = 0;
     closest = closestbundle = -1;
     for (i=0; i<coin->bundlescount; i++)
     {
     qsize = queue_size(&coin->blocksQ);
     m = 0;
     if ( (bp= coin->bundles[i]) != 0 )
     {
     nextbp = (i < coin->bundlescount-1) ? coin->bundles[i+1] : 0;
     if ( bp->emitfinish == 0 )
     {
     m = (bp->n - bp->numrecv);
     if ( bp->numrecv > 3 || numactive == 0 )
     {
     numactive++;
     remaining = (bp->estsize - bp->datasize) + (rand() % (1 + bp->estsize))/100;
     if ( remaining > 0 && (closest < 0 || remaining < closest) )
     {
     //printf("closest.[%d] %d -> R.%d (%d - %d)\n",closestbundle,(int)closest,(int)remaining,(int)bp->estsize,(int)bp->datasize);
     closest = remaining;
     closestbundle = i;
     }
     }
     if ( dispflag != 0 )
     printf("%s",iguana_bundledisp(coin,prevbp,bp,nextbp,m));
     }
     }
     prevbp = bp;
     }
     //if ( closestbundle >= 0 && (coin->closestbundle < 0 || coin->bundles[coin->closestbundle]->numrecv >= coin->chain->bundlesize) )
     coin->closestbundle = closestbundle;
     char str[65];
     if ( dispflag != 0 )
     printf(" PENDINGBUNDLES lastbundle.%d closest.[%d] %s | %d\n",lastbundle,closestbundle,mbstr(str,closest),coin->closestbundle);
     return(flag);
     }*/
    int32_t iguana_updatecounts(struct iguana_info *coin)
    {
        int32_t flag = 0;
        //SETBIT(coin->havehash,0);
        //while ( iguana_havetxdata(coin,coin->blocks.recvblocks) != 0 )
        //    coin->blocks.recvblocks++;
        //if ( coin->blocks.recvblocks < 1 )
        //    coin->blocks.recvblocks = 1;
        //while ( GETBIT(coin->havehash,coin->blocks.hashblocks) > 0 )
        //    coin->blocks.hashblocks++;
        return(flag);
    }
    
    //printf("iguana_issueloop\n");
    //flag += iguana_issueloop(coin);
    //if ( newhwm != 0 )
    //    flag += iguana_lookahead(coin,&hash2,coin->blocks.hwmheight);
    
    /*struct iguana_block *iguana_blockadd(struct iguana_info *coin,struct iguana_bundle **bpp,int32_t *bundleip,struct iguana_block *origblock)
     {
     struct iguana_block *checkblock,*block = 0; char str[65]; struct iguana_bundle *bp = *bpp;
     int32_t setval,checki,bundlei,bundleheight,bundlesize = coin->chain->bundlesize;
     bundlei = *bundleip;
     *bundleip = -2;
     *bpp = 0;
     if ( origblock == 0 )
     return(0);
     //iguana_blockhashset(coin,-1,origblock->prev_block,1);
     if ( bits256_nonz(origblock->hash2) > 0 && (block= iguana_blockhashset(coin,-1,origblock->hash2,1)) != 0 )
     {
     //printf("blockadd.(%s) -> %d (%s)\n",bits256_str(str,origblock->prev_block),block->height,bits256_str(str2,origblock->hash2));
     if ( bits256_nonz(block->prev_block) == 0 )
     iguana_blockcopy(coin,block,origblock);
     if ( (bp= *bpp) == 0 )
     {
     if ( (bp= iguana_bundlefind(coin,bpp,&bundlei,block->hash2)) == 0 )
     {
     *bpp = 0, bundlei = -2;
     //printf("a bundlefind.(%s) -> bundlei.%d\n",bits256_str(str,block->hash2),*bundleip);
     if ( (bp= iguana_bundlefind(coin,bpp,&bundlei,block->prev_block)) == 0 )
     {
     //iguana_chainheight(coin,block);
     //printf("a prev bundlefind.(%s) -> bundlei.%d ht.%d\n",bits256_str(str,block->prev_block),*bundleip,block->height);
     *bpp = 0;
     *bundleip = -2;
     return(block);
     }
     else
     {
     if ( *bundleip == bundlesize-1 )
     {
     printf("b prev bundlefind.(%s) -> bundlei.%d\n",bits256_str(str,block->prev_block),*bundleip);
     bundleheight = (bp->ramchain.bundleheight >= 0) ? (bp->ramchain.bundleheight + bundlesize) : -1;
     printf("autocreateA: bundleheight.%d\n",bundleheight);
     bundlei = -2;
     *bpp = bp = iguana_bundlecreate(coin,&bundlei,bundleheight,block->hash2);
     *bpp = 0;
     *bundleip = -2;
     return(block);
     }
     else if ( bundlei < coin->chain->bundlesize-1 )
     {
     bundlei++;
     if ( bp->n <= bundlei )
     bp->n = bundlei+1;
     iguana_hash2set(coin,"add",bp,bundlei,block->hash2);
     //printf("found prev.%s -> bundlei.%d\n",bits256_str(str,block->prev_block),bundlei);
     }
     }
     }
     else
     {
     // printf("found bp.%p bundlei.%d\n",bp,bundlei);
     }
     }
     else if ( bundlei < -1 )
     {
     bp = iguana_bundlefind(coin,bpp,&bundlei,block->hash2);
     printf("c bundlefind.(%s) -> bundlei.%d\n",bits256_str(str,block->hash2),bundlei);
     } else printf("last case bundleip %d\n",bundlei);
     *bpp = bp;
     *bundleip = bundlei;
     //printf("bundlei.%d for %s\n",bundlei,bits256_str(str,block->hash2));
     if ( memcmp(bp->hashes[bundlei].bytes,block->hash2.bytes,sizeof(bits256)) != 0 )
     printf("honk? find error %s\n",bits256_str(str,bp->hashes[bundlei])), getchar();
     if ( bp == 0 || bundlei < -1 )
     {
     printf("%s null bp? %p or illegal bundlei.%d block.%p\n",bits256_str(str,block->hash2),bp,bundlei,block);
     return(block);
     }
     if ( (setval= iguana_bundlehash2add(coin,&checkblock,bp,bundlei,block->hash2)) == 0 && checkblock == block )
     {
     if ( bp->blocks[bundlei] != 0 )
     {
     if ( bp->blocks[bundlei] != block )
     printf("blockadd: error blocks[%d] %p %d != %d %p\n",bundlei,bp->blocks[bundlei],bp->blocks[bundlei]->height,block->height,block);
     } else bp->blocks[bundlei] = block;
     //iguana_bundlehash2add(coin,0,bp,bundlei-1,block->prev_block);
     //printf("setval.%d bp.%p bundlei.%d\n",setval,bp,bundlei);
     }
     else if ( setval > 0 )
     {
     if ( bundlei == bundlesize )
     {
     bundleheight = (bp->ramchain.bundleheight >= 0) ? (bp->ramchain.bundleheight + bundlesize) : -1;
     printf("autocreate: bundleheight.%d\n",bundleheight);
     iguana_bundlecreate(coin,&checki,bundleheight,block->hash2);
     }
     printf("setval.%d bundlei.%d\n",setval,bundlei);
     } else printf("blockadd: error.%d adding hash2, checkblock.%p vs %p\n",setval,checkblock,block);
     //printf("bundleblockadd.[%d] of %d <- %s setval.%d %p\n",bundlei,bp->n,bits256_str(str,block->hash2),setval,block);
     } else printf("bundleblockadd: block.%p error\n",block);
     return(block);
     }
     
     struct iguana_block *iguana_bundleblockadd(struct iguana_info *coin,struct iguana_bundle **bpp,int32_t *bundleip,struct iguana_block *origblock)
     {
     struct iguana_block *block,*retblock; int32_t i,oldhwm; struct iguana_bundle *bp;
     bits256 *hash2p,hash2; char str[65]; struct iguana_bloominds bit;
     oldhwm = coin->blocks.hwmchain.height;
     *bpp = 0, *bundleip = -2;
     if ( (retblock= iguana_blockadd(coin,bpp,bundleip,origblock)) != 0 )
     {
     block = retblock;
     //iguana_chainextend(coin,block);
     if ( block->height >= 0 && (hash2p= iguana_blockhashptr(coin,coin->blocks.hashblocks)) != 0 )
     *hash2p = block->hash2;
     if ( oldhwm != coin->blocks.hwmchain.height )
     {
     if ( oldhwm < coin->blocks.hashblocks )
     coin->blocks.hashblocks = oldhwm;
     while ( coin->blocks.hashblocks < coin->blocks.hwmchain.height && (hash2p= iguana_blockhashptr(coin,coin->blocks.hashblocks)) != 0 )
     {
     hash2 = *hash2p;
     if ( bits256_nonz(hash2) > 0 && (block= iguana_blockfind(coin,hash2)) != 0 )
     {
     if ( hash2p == 0 )
     {
     printf("iguana_bundleblockadd B cant find coin->blocks.hashblocks %d\n",coin->blocks.hashblocks);
     break;
     }
     *hash2p = hash2;
     for (i=0; i<coin->bundlescount; i++)
     {
     if ( (bp= coin->bundles[i]) != 0 )
     {
     if ( coin->blocks.hashblocks >= bp->ramchain.bundleheight && coin->blocks.hashblocks < bp->ramchain.bundleheight+bp->n )
     {
     bit = iguana_calcbloom(block->hash2);
     if ( iguana_bloomfind(coin,&bp->bloom,0,bit) < 0 )
     iguana_bloomset(coin,&bp->bloom,0,bit);
     break;
     }
     }
     }
     //printf("ht.%d %s %p\n",block->height,bits256_str(str,hash2),hash2p);
     bp = 0;
     *bundleip = -2;
     iguana_blockadd(coin,&bp,bundleip,block);
     bp = 0;
     *bundleip = -2;
     if ( iguana_bundlefind(coin,&bp,bundleip,block->hash2) == 0 )
     {
     printf("iguana_bundleblockadd A cant find just added.%s bundlei.%d\n",bits256_str(str,hash2),*bundleip);
     bp = 0;
     *bundleip = -2;
     iguana_bundlefind(coin,&bp,bundleip,block->hash2);
     break;
     }
     coin->blocks.hashblocks++;
     block = 0;
     }
     else
     {
     //printf("break loop block.%p %s coin->blocks.hashblocks %d vs %d\n",block,bits256_str(str,hash2),coin->blocks.hashblocks,coin->blocks.hwmheight);
     break;
     }
     }
     }
     } else printf("iguana_bundleblockadd returns null\n");
     return(retblock);
     }*/
    int64_t iguana_ramchain_compact(struct iguana_ramchain *ramchain,int32_t numpkinds,int32_t numexternaltxids)
    {
        int32_t i,diff; int64_t offset; bits256 *src,*dest,tmp;
        diff = (ramchain->data->numpkinds - numpkinds);
        src = (bits256 *)((long)ramchain->mem->ptr + (long)ramchain->data->Xoffset);
        offset = ramchain->data->Poffset + (sizeof(struct iguana_pkhash) * numpkinds);
        ramchain->data->Xoffset = offset + ((sizeof(struct iguana_account)+sizeof(struct iguana_pkextra)) * numpkinds);
        if ( numpkinds < ramchain->data->numpkinds )
        {
            ramchain->data->numpkinds = numpkinds;
            dest = (bits256 *)((long)ramchain->mem->ptr + (long)offset);
            for (i=0; i<numexternaltxids; i++,offset+=sizeof(bits256))
                tmp = src[i], dest[i] = tmp; // might be shifting by less than 32 bytes
        } else offset += (sizeof(bits256) * numexternaltxids);
        ramchain->data->numexternaltxids = numexternaltxids;
        ramchain->mem->used = offset;
        return(offset);
    }
    
    long iguana_blockramchainPT(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *origtxdata,struct iguana_msgtx *txarray,int32_t txn_count,uint8_t *data,int32_t recvlen)
    {
        RAMCHAIN_PTRS; struct iguana_ramchain *ramchain = &addr->ramchain;
        struct iguana_msgtx *tx; int32_t i,j,err,bundlei = -2; struct iguana_bundle *bp = 0;
        if ( iguana_bundlefind(coin,&bp,&bundlei,origtxdata->block.hash2) == 0 )
            return(-1);
        SETBIT(bp->recv,bundlei);
        bp->fpos[bundlei] = -1;
        bp->recvlens[bundlei] = recvlen;
        if ( iguana_ramchain_init(ramchain,&addr->TXDATA,&addr->HASHMEM,0,txn_count,origtxdata->numunspents,origtxdata->numspends,0,0) == 0 )
            return(-1);
        iguana_ramchain_link(ramchain,origtxdata->block.hash2,origtxdata->block.hash2,bp->hdrsi,bp->bundleheight+bundlei,1);
        _iguana_ramchain_setptrs(ramchain,&T,&U,&U2,&S,&P,&P2,&A,&X);
        if ( T == 0 || U == 0 || S == 0 || P == 0 || X == 0 )
        {
            printf("fatal error getting txdataptrs\n");
            return(-1);
        }
        for (i=0; i<txn_count; i++)
        {
            tx = &txarray[i];
            iguana_ramchain_addtxid(ramchain,T,U,U2,S,P,P2,A,X,tx->txid,tx->tx_out,tx->tx_in);
            for (j=0; j<tx->tx_out; j++)
                iguana_ramchain_addunspent(ramchain,T,U,U2,S,P,P2,A,X,tx->vouts[j].value,tx->vouts[j].pk_script,tx->vouts[j].pk_scriptlen);
            for (j=0; j<tx->tx_in; j++)
                iguana_ramchain_addspend(ramchain,T,U,U2,S,P,P2,A,X,tx->vins[j].prev_hash,tx->vins[j].prev_vout,tx->vins[j].script,tx->vins[j].scriptlen,tx->vins[j].sequence);
        }
        ramchain->data->numpkinds = ramchain->pkind;
        ramchain->data->numexternaltxids = ramchain->externalind;
        ramchain->data->allocsize = iguana_ramchain_size(ramchain);
        if ( (err= iguana_ramchainverify(ramchain)) == 0 )
        {
            if ( (bp->fpos[bundlei]= iguana_ramchain_save(ramchain,addr->ipbits,bp->hashes[0],bundlei)) >= 0 )
                bp->ipbits[bundlei] = addr->ipbits;
        } else printf("ramchain verification error.%d hdrsi.%d bundlei.%d\n",err,bp->hdrsi,bundlei);
        iguana_ramchain_free(ramchain);
        return(bp->fpos[bundlei]);
        //iguana_hashfree(addr->txids,0);
        //iguana_hashfree(addr->pkhashes,0);
        
        /*txidind = unspentind = spendind = pkind = 0;
         for (i=numvouts=numpkinds=0; i<txn_count; i++,txidind++)
         {
         tx = &txarray[i];
         t = &T[txidind];
         t->txid = tx->txid, t->txidind = txidind, t->firstvout = unspentind, t->numvouts = tx->tx_out;
         iguana_hashsetPT(ramchain,hashmem,'T',t->txid.bytes,txidind);
         for (j=0; j<tx->tx_out; j++,numvouts++,unspentind++)
         {
         u = &U[unspentind];
         script = tx->vouts[j].pk_script, scriptlen = tx->vouts[j].pk_scriptlen;
         iguana_calcrmd160(coin,rmd160,script,scriptlen,tx->txid);
         //char str[65]; init_hexbytes_noT(str,rmd160,20), printf("pkhashes.%p %s %s new pkind.%d pkoffset.%d %d\n",addr->pkhashes,addr->ipaddr,str,numpkinds,txdata->pkoffset,(int32_t)((long)&P[numpkinds] - (long)txdata));
         if ( (ptr= iguana_hashfind(ramchain,'P',rmd160)) == 0 )
         {
         memcpy(P[numpkinds].rmd160,rmd160,sizeof(rmd160));
         if ( (ptr= iguana_hashsetPT(ramchain,hashmem,'P',&P[numpkinds],numpkinds)) == 0 )
         printf("fatal error adding pkhash\n"), getchar();
         //printf("added ptr.%p\n",ptr);
         numpkinds++;
         } //else printf("found %p[%d] for (%s)\n",ptr,ptr->hh.itemind,str);
         u->value = tx->vouts[j].value, u->txidind = txidind;
         u->pkind = ptr->hh.itemind;
         P[u->pkind].firstunspentind = unspentind;
         // prevunspentind requires having accts, so that waits for third pass
         }
         }
         //printf("reallocP.%p -> ",P);
         if ( (txdata->numpkinds= numpkinds) > 0 )
         P = iguana_memalloc(txmem,sizeof(*P) * numpkinds,0);
         //printf("%p\n",P);
         externalT = iguana_memalloc(txmem,0,1);
         txidind = 0;
         for (i=numvins=numexternal=0; i<txn_count; i++,txidind++)
         {
         tx = &txarray[i];
         t = &T[txidind];
         t->firstvin = spendind;
         for (j=0; j<tx->tx_in; j++)
         {
         script = tx->vins[j].script, scriptlen = tx->vins[j].scriptlen;
         s = &S[spendind];
         if ( (sequence= tx->vins[j].sequence) != (uint32_t)-1 )
         s->diffsequence = 1;
         s->vout = tx->vins[j].prev_vout;
         if ( s->vout != 0xffff )
         {
         if ( (ptr= iguana_hashfind(ramchain,'T',tx->vins[j].prev_hash.bytes)) != 0 )
         {
         if ( (s->spendtxidind= ptr->hh.itemind) >= txdata->numtxids )
         {
         s->external = 1;
         s->spendtxidind -= txdata->numtxids;
         }
         }
         else
         {
         s->external = 1;
         externalT[numexternal] = tx->vins[j].prev_hash;
         iguana_hashsetPT(ramchain,hashmem,'T',externalT[numexternal].bytes,txdata->numtxids + numexternal);
         s->spendtxidind = numexternal++;
         }
         spendind++;
         numvins++;
         //printf("spendind.%d\n",spendind);
         } //else printf("vout.%x\n",s->vout);
         // prevspendind requires having accts, so that waits for third pass
         }
         t->numvins = numvins;
         }
         if ( (txdata->numexternaltxids= numexternal) > 0 )
         externalT = iguana_memalloc(txmem,sizeof(*externalT) * numexternal,0);
         txdata->datalen = (int32_t)txmem->used;
         txdata->numspends = numvins;
         txdata->numpkinds = numpkinds;
         txdata->numtxids = txn_count;
         //char str[65],buf[9999];
         //for (j=buf[0]=0; j<numpkinds; j++)
         //    init_hexbytes_noT(str,P[j].rmd160,20), sprintf(buf+strlen(buf),"(%d %s) ",j,str);
         //printf("%s bundlei.%d T.%d U.%d S.%d P.%d recvlen.%d -> %d\n",buf,bundlei,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,recvlen,txdata->datalen);
         if ( numvouts != txdata->numunspents || i != txdata->numtxids )
         {
         printf("counts mismatch: numvins %d != %d txdata->numvins || numvouts %d != %d txdata->numvouts || i %d != %d txdata->numtxids\n",numvins,txdata->numspends,numvouts,txdata->numunspents,i,txdata->numtxids);
         getchar();
         exit(-1);
         }
         else
         {
         static int32_t maxrecvlen,maxdatalen,maxhashmem; static double recvsum,datasum;
         recvsum += recvlen, datasum += txdata->datalen;
         if ( recvlen > maxrecvlen )
         printf("[%.3f] %.0f/%.0f maxrecvlen %d -> %d\n",recvsum/datasum,recvsum,datasum,maxrecvlen,recvlen), maxrecvlen = recvlen;
         if ( txdata->datalen > maxdatalen )
         printf("[%.3f] %.0f/%.0f maxdatalen %d -> %d\n",recvsum/datasum,recvsum,datasum,maxdatalen,txdata->datalen), maxdatalen = txdata->datalen;
         if ( hashmem != 0 && hashmem->used > maxhashmem )
         printf("[%.3f] %.0f/%.0f maxhashmem %d -> %ld\n",recvsum/datasum,recvsum,datasum,maxhashmem,hashmem->used), maxhashmem = (int32_t)hashmem->used;
         if ( (rand() % 10000) == 0 )
         printf("[%.3f] %.0f/%.0f recvlen vs datalen\n",recvsum/datasum,recvsum,datasum);
         if ( origtxdata != 0 )
         {
         origtxdata->numspends = txdata->numspends;
         origtxdata->numpkinds = txdata->numpkinds;
         origtxdata->numexternaltxids = txdata->numexternaltxids;
         }
         }
         if ( iguana_peertxsave(coin,&hdrsi,&bundlei,fname,addr,txdata) == txdata )
         {
         #ifdef __APPLE__
         int32_t checki; struct iguana_txblock *checktx; struct iguana_ramchain R,*ptr = &R;
         if ( 1 && (checktx= iguana_peertxdata(coin,&checki,fname,txmem,addr->ipbits,txdata->block.hash2)) != 0 && checki == bundlei )
         {
         if ( iguana_ramchainset(coin,ptr,checktx) == ptr )
         {
         char str[65]; int32_t j,err;
         ptr->txids = ramchain->txids;
         ptr->pkhashes = ramchain->pkhashes;
         if ( (err= iguana_ramchainverifyPT(coin,ptr)) != 0 )
         {
         for (j=0; j<ptr->numpkinds; j++)
         init_hexbytes_noT(str,ptr->P[j].rmd160,20), printf("[%d %s] ",j,str);
         printf("check err.%d ramchain.%s bundlei.%d T.%d U.%d S.%d P.%d\n",err,bits256_str(str,ptr->hash2),bundlei,ptr->numtxids,ptr->numunspents,ptr->numspends,ptr->numpkinds);
         }
         }
         }
         #endif
         }*/
        //printf("free addrtables %p %p\n",addr->txids,addr->pkhashes);
        // printf("numpkinds.%d numspends.%d\n",txdata->numpkinds,txdata->numspends);
    }
    
    
    /*void iguana_flushQ(struct iguana_info *coin,struct iguana_peer *addr)
     {
     struct iguana_helper *ptr;
     if ( time(NULL) > addr->lastflush+3 )
     {
     ptr = mycalloc('i',1,sizeof(*ptr));
     ptr->allocsize = sizeof(*ptr);
     ptr->coin = coin;
     ptr->addr = addr;
     ptr->type = 'F';
     //printf("FLUSH.%s %u lag.%d\n",addr->ipaddr,addr->lastflush,(int32_t)(time(NULL)-addr->lastflush));
     addr->lastflush = (uint32_t)time(NULL);
     queue_enqueue("helperQ",&helperQ,&ptr->DL,0);
     }
     }*/
    
    struct iguana_txblock *iguana_peertxsave(struct iguana_info *coin,int32_t *hdrsip,int32_t *bundleip,char *fname,struct iguana_peer *addr,struct iguana_txblock *txdata)
    {
        int32_t fpos,bundlei,i,z; FILE *fp;
        fpos = 0;
        *bundleip = bundlei = iguana_peerfname(coin,hdrsip,fname,addr->ipbits,txdata->block.hash2);
        if ( bundlei < 0 || bundlei >= coin->chain->bundlesize )
        {
            printf(" wont save.(%s) bundlei.%d\n",fname,bundlei);
            return(0);
        }
        txdata->block.hdrsi = *hdrsip;
        txdata->block.bundlei = bundlei;
        if ( (fp= fopen(fname,"rb+")) == 0 )
        {
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                z = -1;
                coin->peers.numfiles++;
                for (i=0; i<coin->chain->bundlesize; i++)
                    fwrite(&z,1,sizeof(z),fp);
                fclose(fp);
                fp = fopen(fname,"rb+");
            }
        }
        if ( fp != 0 )
        {
            fseek(fp,0,SEEK_END);
            fpos = (int32_t)ftell(fp);
            //printf("%s fpos.%d: bundlei.%d datalen.%d\n",fname,fpos,bundlei,txdata->datalen);
            fwrite(&bundlei,1,sizeof(bundlei),fp);
            fwrite(&txdata->block.hash2,1,sizeof(txdata->block.hash2),fp);
            fwrite(&txdata->datalen,1,sizeof(txdata->datalen),fp);
            fwrite(txdata,1,txdata->datalen,fp);
            fseek(fp,bundlei * sizeof(bundlei),SEEK_SET);
            //printf("bundlei[%d] <- fpos.%d\n",bundlei,fpos);
            fwrite(&fpos,1,sizeof(fpos),fp);
            fclose(fp);
            //for (i=0; i<txdata->numpkinds; i++)
            //    printf("%016lx ",*(long *)((struct iguana_pkhash *)((long)txdata + txdata->pkoffset))[i].rmd160);
            //printf("create.(%s) %d ",fname,bundlei,coin->peers.numfiles);
            //printf("bundlei.%d datalen.%d T.%d U.%d S.%d P.%d X.%d\n",bundlei,txdata->datalen,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,txdata->numexternaltxids);
            return(txdata);
        }
        return(0);
    }
    
    struct iguana_txblock *iguana_peertxdata(struct iguana_info *coin,int32_t *bundleip,char *fname,struct iguana_memspace *mem,uint32_t ipbits,bits256 hash2)
    {
        int32_t bundlei,datalen,checki,hdrsi,fpos; char str[65],str2[65]; FILE *fp;
        bits256 checkhash2; struct iguana_txblock *txdata = 0;
        if ( (bundlei= iguana_peerfname(coin,&hdrsi,fname,ipbits,hash2)) >= 0 )
        {
            if ( (fp= fopen(fname,"rb")) != 0 )
            {
                fseek(fp,bundlei * sizeof(bundlei),SEEK_SET);
                fread(&fpos,1,sizeof(fpos),fp);
                fseek(fp,fpos,SEEK_SET);
                fread(&checki,1,sizeof(checki),fp);
                if ( ftell(fp)-sizeof(checki) == fpos && bundlei == checki )
                {
                    fread(&checkhash2,1,sizeof(checkhash2),fp);
                    if ( memcmp(hash2.bytes,checkhash2.bytes,sizeof(hash2)) == 0 )
                    {
                        fread(&datalen,1,sizeof(datalen),fp);
                        if ( datalen < (mem->totalsize - mem->used - 4) )
                        {
                            if ( (txdata= iguana_memalloc(mem,datalen,0)) != 0 )
                            {
                                fread(txdata,1,datalen,fp);
                                if ( txdata->datalen != datalen || txdata->block.bundlei != bundlei )
                                {
                                    printf("%s peertxdata txdata->datalen.%d != %d bundlei.%d vs %d\n",bits256_str(str,txdata->block.hash2),txdata->datalen,datalen,txdata->block.bundlei,bundlei);
                                    getchar();
                                    txdata = 0;
                                    iguana_memreset(mem);
                                } //else printf("SUCCESS txdata.%s bundlei.%d fpos.%d T.%d U.%d S.%d P.%d\n",bits256_str(str,txdata->block.hash2),bundlei,fpos,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds);
                            } else printf("peertxdata error allocating txdata\n");
                        } else printf("mismatch peertxdata datalen %d vs %ld totalsize %ld\n",datalen,mem->totalsize - mem->used - 4,(long)mem->totalsize);
                    } else printf("peertxdata hash mismatch %s != %s\n",bits256_str(str,hash2),bits256_str(str2,checkhash2));
                } else printf("peertxdata bundlei.%d != checki.%d, fpos.%d ftell.%ld\n",bundlei,checki,fpos,ftell(fp));
                fclose(fp);
            } else printf("cant find file.(%s)\n",fname);
        } //else printf("bundlei.%d\n",bundlei);
        *bundleip = bundlei;
        return(txdata);
    }
    
    /*if ( (n= ramchain->data->numtxids) > 0 )
     {
     for (ramchain->txidind=ramchain->data->firsti; ramchain->txidind<n; ramchain->txidind++)
     {
     tx = &T[ramchain->txidind];
     //printf("tx.%p (%d) %d txidind.%d\n",tx,(int32_t)((long)tx - (long)ramchain->mem->ptr),(int32_t)ramchain->mem->totalsize,ramchain->txidind);
     iguana_ramchain_addtxid(coin,RAMCHAIN_ARG,tx->txid,tx->numvouts,tx->numvins);
     //if ( (ptr= iguana_hashsetPT(ramchain,'T',&tx->txid.bytes,ramchain->txidind)) != 0 )
     {
     for (j=0; j<tx->numvouts; j++)
     {
     iguana_ramchain_addunspent(coin,RAMCHAIN_ARG,U[ramchain->unspentind].value,P[U[ramchain->unspentind].pkind].rmd160,-20,tx->txid,j);
     }
     }
     ramchain->spendind += tx->numvins;
     }
     ramchain->externalind = ramchain->data->numexternaltxids;
     }
     if ( (err= iguana_ramchainverify(coin,ramchain)) != 0 )
     {
     printf("iguana_ramchain_map.(%s) err.%d verifying ramchain\n",fname,err);
     iguana_ramchain_free(ramchain,hashmem == 0);
     munmap(ptr,filesize);
     }*/
    //printf("mapped ramchain verified\n");
    
#define iguana_hashfind(hashtable,key,keylen) iguana_hashsetHT(hashtable,0,key,keylen,-1)
    
    struct iguana_kvitem *iguana_hashsetHT(struct iguana_kvitem *hashtable,struct iguana_memspace *mem,void *key,int32_t keylen,int32_t itemind)
    {
        struct iguana_kvitem *ptr = 0; int32_t allocsize;
        HASH_FIND(hh,hashtable,key,keylen,ptr);
        if ( ptr == 0 && itemind >= 0 )
        {
            allocsize = (int32_t)(sizeof(*ptr));
            if ( mem != 0 )
                ptr = iguana_memalloc(mem,allocsize,1);
            else ptr = mycalloc('t',1,allocsize);
            if ( ptr == 0 )
                printf("fatal alloc error in hashset\n"), exit(-1);
            //printf("ptr.%p allocsize.%d key.%p keylen.%d itemind.%d\n",ptr,allocsize,key,keylen,itemind);
            ptr->hh.itemind = itemind;
            HASH_ADD_KEYPTR(hh,hashtable,key,keylen,ptr);
        }
        if ( ptr != 0 )
        {
            struct iguana_kvitem *tmp;
            HASH_FIND(hh,hashtable,key,keylen,tmp);
            char str[65];
            init_hexbytes_noT(str,key,keylen);
            if ( tmp != ptr )
                printf("%s itemind.%d search error %p != %p\n",str,itemind,ptr,tmp);
            // else printf("added.(%s) height.%d %p\n",str,itemind,ptr);
        }
        return(ptr);
    }
    
    int32_t iguana_parseblock(struct iguana_info *coin,struct iguana_block *block,struct iguana_msgtx *tx,int32_t numtx)
    {
#ifdef oldway
        int32_t txind,pkind,i; uint16_t numvouts,numvins;
        pkind = block->L.numpkinds = coin->latest.dep.numpkinds;
        block->L.supply = coin->latest.dep.supply;
        if ( block->L.numtxids != coin->latest.dep.numtxids || block->L.numunspents != coin->latest.dep.numunspents || block->L.numspends != coin->latest.dep.numspends || block->L.numpkinds != coin->latest.dep.numpkinds )
        {
            printf("Block.(h%d t%d u%d s%d p%d) vs coin.(h%d t%d u%d s%d p%d)\n",block->height,block->L.numtxids,block->L.numunspents,block->L.numspends,block->L.numpkinds,coin->blocks.parsedblocks,coin->latest.dep.numtxids,coin->latest.dep.numunspents,coin->latest.dep.numspends,coin->latest.dep.numpkinds);
            block->L.numtxids = coin->latest.dep.numtxids;
            block->L.numunspents = coin->latest.dep.numunspents;
            block->L.numspends = coin->latest.dep.numspends;
            block->L.numpkinds = coin->latest.dep.numpkinds;
            iguana_kvwrite(coin,coin->blocks.db,0,block,(uint32_t *)&block->height);
            //getchar();
        }
        vcalc_sha256(0,coin->latest.ledgerhash.bytes,coin->latest.lhashes[0].bytes,sizeof(coin->latest.lhashes));
        coin->LEDGER.snapshot.dep = block->L;
        memcpy(&coin->LEDGER.snapshot.ledgerhash,&coin->latest.ledgerhash,sizeof(coin->latest.ledgerhash));
        memcpy(coin->LEDGER.snapshot.lhashes,coin->latest.lhashes,sizeof(coin->latest.lhashes));
        memcpy(coin->LEDGER.snapshot.states,coin->latest.states,sizeof(coin->latest.states));
        //printf("%08x Block.(h%d t%d u%d s%d p%d) vs (h%d t%d u%d s%d p%d)\n",(uint32_t)coin->latest.ledgerhash.txid,block->height,block->L.numtxids,block->L.numunspents,block->L.numspends,block->L.numpkinds,coin->blocks.parsedblocks,coin->latest.dep.numtxids,coin->latest.dep.numunspents,coin->latest.dep.numspends,coin->latest.dep.numpkinds);
        if ( (coin->blocks.parsedblocks % 1000) == 0 )
        {
            for (i=0; i<IGUANA_NUMAPPENDS; i++)
                printf("%llx ",(long long)coin->LEDGER.snapshot.lhashes[i].txid);
            char str[65];
            bits256_str(str,coin->LEDGER.snapshot.ledgerhash);
            printf("-> pre parse %s ledgerhashes.%d\n",str,coin->blocks.parsedblocks);
        }
        coin->LEDGER.snapshot.blockhash = block->hash2;
        coin->LEDGER.snapshot.merkle_root = block->merkle_root;
        coin->LEDGER.snapshot.timestamp = block->timestamp;
        coin->LEDGER.snapshot.credits = coin->latest.credits;
        coin->LEDGER.snapshot.debits = coin->latest.debits;
        coin->LEDGER.snapshot.height = block->height;
        //if ( coin->blocks.parsedblocks > 0 && (coin->blocks.parsedblocks % coin->chain->bundlesize) == 0 )
        //    coin->R.bundles[coin->blocks.parsedblocks / coin->chain->bundlesize].presnapshot = coin->LEDGER.snapshot;
        for (txind=block->numvouts=block->numvins=0; txind<block->txn_count; txind++)
        {
            //printf("block.%d txind.%d numvouts.%d numvins.%d block->(%d %d) U%d coin.%d\n",block->height,txind,numvouts,numvins,block->numvouts,block->numvins,block->L.numunspents,coin->latest.dep.numunspents);
            //fprintf(stderr,"t");
            if ( ramchain_parsetx(coin,&coin->mining,&coin->totalfees,&numvouts,&numvins,block->height,txind,&tx[txind],block->L.numtxids+txind,block->L.numunspents + block->numvouts,block->L.numspends + block->numvins) < 0 )
                return(-1);
            block->numvouts += numvouts;
            block->numvins += numvins;
            //printf("block.%d txind.%d numvouts.%d numvins.%d block->(%d %d) 1st.(%d %d)\n",block->height,txind,numvouts,numvins,block->numvouts,block->numvins,block->L.numunspents,block->L.numspends);
        }
        //printf(" Block.(h%d t%d u%d s%d p%d) vs coin.(h%d t%d u%d s%d p%d)\n",block->height,block->L.numtxids,block->L.numunspents,block->L.numspends,block->L.numpkinds,coin->blocks.parsedblocks,coin->latest.dep.numtxids,coin->latest.dep.numunspents,coin->latest.dep.numspends,coin->latest.dep.numpkinds);
        if ( coin->latest.dep.supply != (coin->latest.credits - coin->latest.debits) )
        {
            printf("height.%d supply %.8f != %.8f (%.8f - %.8f)\n",block->height,dstr(coin->latest.dep.supply),dstr(coin->latest.credits)-dstr(coin->latest.debits),dstr(coin->latest.credits),dstr(coin->latest.debits));
            getchar();
        }
#ifdef IGUANA_VERIFYFLAG
        while ( pkind < coin->latest.dep.numpkinds )
        {
            int64_t err;
            if ( (err= iguana_verifyaccount(coin,&coin->accounts[pkind],pkind)) < 0 )
                printf("pkind.%d err.%lld %.8f last.(U%d S%d)\n",pkind,(long long)err,dstr(coin->accounts[pkind].balance),coin->accounts[pkind].lastunspentind,coin->accounts[pkind].lastspendind), getchar();
            pkind++;
        }
#endif
        coin->parsetime = (uint32_t)time(NULL);
        coin->parsemillis = milliseconds();
        iguana_kvwrite(coin,coin->blocks.db,0,block,(uint32_t *)&block->height);
        if ( (coin->blocks.parsedblocks > coin->longestchain-100000 && (coin->blocks.parsedblocks % 100) == 0) || (coin->blocks.parsedblocks > coin->longestchain-1000 && (coin->blocks.parsedblocks % 10) == 0) || coin->blocks.parsedblocks > coin->longestchain-100 || (coin->blocks.parsedblocks % 100) == 0 )
        {
            printf("PARSED.%d T.%d U.%d+%d S.%d+%d P.%d hwm.%d longest.%d | %.8f - %.8f %.8f [%.8f] M %.8f F %.8f | %.02f minutes %.2f%% %.2f%% %.2f%% avail\n",coin->blocks.parsedblocks,coin->latest.dep.numtxids,block->L.numunspents,block->numvouts,block->L.numspends,block->numvins,block->L.numpkinds,coin->blocks.hwmheight,coin->longestchain,dstr(coin->latest.credits),dstr(coin->latest.debits),dstr(coin->latest.credits)-dstr(coin->latest.debits),(dstr(coin->latest.credits)-dstr(coin->latest.debits))/coin->blocks.parsedblocks,dstr(coin->mining),dstr(coin->totalfees),((double)time(NULL)-coin->starttime)/60.,(double)iguana_avail(coin,coin->blocks.parsedblocks+1,1000)/10.,(double)iguana_avail(coin,coin->blocks.parsedblocks+1,25000)/250.,100.*(double)iguana_avail(coin,coin->blocks.parsedblocks+1,coin->longestchain-coin->blocks.parsedblocks-1)/(coin->longestchain-coin->blocks.parsedblocks));
            myallocated(0,0);
        }
        if ( 0 && coin->loadedLEDGER.snapshot.height == coin->blocks.parsedblocks )
        {
            memcpy(&coin->latest.ledgerhash,&coin->loadedLEDGER.snapshot.ledgerhash,sizeof(coin->loadedLEDGER.snapshot.ledgerhash));
            memcpy(coin->latest.lhashes,coin->loadedLEDGER.snapshot.lhashes,sizeof(coin->loadedLEDGER.snapshot.lhashes));
            printf("restore lhashes, special alignement case\n");
        } //else printf("loaded.%d vs parsed.%d\n",coin->loadedLEDGER.snapshot.height,coin->blocks.parsedblocks);
        coin->blocks.parsedblocks++;
#endif
        return(0);
    }
    
    int32_t iguana_updateramchain(struct iguana_info *coin)
    {
        return(0);
    }
    
    int32_t iguana_hashfree(struct iguana_kvitem *hashtable,int32_t delitem)
    {
        struct iguana_kvitem *item,*tmp; int32_t n = 0;
        if ( hashtable != 0 )
        {
            HASH_ITER(hh,hashtable,item,tmp)
            {
                //printf("hashdelete.%p allocsize.%d itemind.%d delitem.%d\n",item,item->allocsize,item->hh.itemind,delitem);
                if ( delitem != 0 )
                {
                    HASH_DEL(hashtable,item);
                    //if ( delitem > 1 )
                    //    myfree(item,item->allocsize);
                }
                n++;
            }
        }
        return(n);
    }
    
    struct iguana_txblock *iguana_ramchainptrs(struct iguana_txid **Tptrp,struct iguana_unspent20 **Uptrp,struct iguana_spend256 **Sptrp,struct iguana_pkhash **Pptrp,bits256 **externalTptrp,struct iguana_memspace *mem,struct iguana_txblock *origtxdata)
    {
        char str[65]; struct iguana_txblock *txdata; int32_t allocsize,extralen,rwflag = (origtxdata != 0);
        iguana_memreset(mem);
        allocsize = (int32_t)(sizeof(*txdata) - sizeof(txdata->space) + ((origtxdata != 0) ? origtxdata->extralen : 0));
        mem->alignflag = sizeof(uint32_t);
        if ( (txdata= iguana_memalloc(mem,allocsize,0)) == 0 )
            return(0);
        //printf("ptr.%p alloctxdata.%p T.%d U.%d S.%d P.%d\n",mem->ptr,txdata,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds);
        extralen = (origtxdata != 0) ? origtxdata->extralen : txdata->extralen;
        if ( origtxdata != 0 )
        {
            //printf("copy %d bytes from %p to %p extralen.%d size.%ld  T.%d U.%d S.%d P.%d \n",allocsize,origtxdata,txdata,extralen,sizeof(*txdata),txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds);
            memcpy(txdata,origtxdata,allocsize);
        } else iguana_memalloc(mem,txdata->extralen,0);
        *Tptrp = iguana_memalloc(mem,sizeof(**Tptrp) * txdata->numtxids,rwflag);
        *Uptrp = iguana_memalloc(mem,sizeof(**Uptrp) * txdata->numunspents,rwflag);
        *Sptrp = iguana_memalloc(mem,sizeof(**Sptrp) * txdata->numspends,rwflag);
        //printf("rwflag.%d ptr.%p alloctxdata.%p T.%d U.%d S.%d P.%d  pkoffset.%ld X.%d\n",rwflag,mem->ptr,txdata,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,mem->used,txdata->numexternaltxids);
        if ( externalTptrp != 0 )
        {
            if ( txdata->pkoffset < (int32_t)mem->used )
                printf("allocsize.%d size.%ld %p %s (T.%d U.%d S.%d P.%d X.%d) iguana_ramchainptrs pkoffset.%d != %ld numspends.%d\n",allocsize,sizeof(*txdata),txdata,bits256_str(str,txdata->block.hash2),txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,txdata->numexternaltxids,txdata->pkoffset,mem->used,txdata->numspends), getchar();
            mem->used = txdata->pkoffset;
            *Pptrp = iguana_memalloc(mem,sizeof(**Pptrp) * txdata->numpkinds,rwflag);
            *externalTptrp = iguana_memalloc(mem,txdata->numexternaltxids * sizeof(**externalTptrp),rwflag);
        }
        else
        {
            txdata->pkoffset = (int32_t)mem->used;
            // printf("set pkoffset.%d\n",txdata->pkoffset);
            *Pptrp = iguana_memalloc(mem,0,rwflag);
        }
        if ( 0 && rwflag == 0 )
            printf("datalen.%d rwflag.%d origtxdat.%p allocsize.%d extralen.%d T.%d U.%d S.%d P.%d X.%p[%d]\n",(int32_t)mem->totalsize,rwflag,origtxdata,allocsize,extralen,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,externalTptrp!=0?*externalTptrp:0,txdata->numexternaltxids);
        return(txdata);
    }
    
    int32_t iguana_ramchainsave(struct iguana_info *coin,struct iguana_ramchain *ramchain)
    {
        FILE *fp; char fname[1024],str[65];
        sprintf(fname,"DB/%s/%s.%d",coin->symbol,bits256_str(str,ramchain->H.data->firsthash2),ramchain->H.hdrsi);
        if ( (fp= fopen(fname,"wb")) != 0 )
        {
            fwrite(ramchain,1,ramchain->H.data->allocsize,fp);
            fclose(fp);
        }
        printf("ramchainsave.%s %d[%d] %s\n",coin->symbol,ramchain->H.hdrsi,ramchain->numblocks,mbstr(str,ramchain->H.data->allocsize));
        return(0);
    }
    
    int32_t iguana_ramchainfree(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_ramchain *ramchain)
    {
        if ( ramchain->txids != 0 )
            iguana_hashfree(ramchain->txids,1);
        if ( ramchain->pkhashes != 0 )
            iguana_hashfree(ramchain->pkhashes,1);
        iguana_mempurge(mem);
        return(0);
    }
    
    /*struct iguana_ramchain *iguana_ramchainset(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct iguana_txblock *txdata)
     {
     struct iguana_memspace txmem;
     memset(&txmem,0,sizeof(txmem));
     iguana_meminit(&txmem,"bramchain",txdata,txdata->datalen,0);
     //printf("ramchainset <- txdata.%p memptr.%p T.%d U.%d S.%d P.%d X.%d\n",txdata,txmem.ptr,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,txdata->numexternaltxids);
     if ( iguana_ramchainptrs(&ramchain->T,&ramchain->U,&ramchain->S,&ramchain->P,&ramchain->externalT,&txmem,0) != txdata || ramchain->T == 0 || ramchain->U == 0 || ramchain->S == 0 || ramchain->P == 0 )
     {
     printf("iguana_ramchainset: cant set pointers txdata.%p\n",txdata);
     return(0);
     }
     //int32_t i;
     // for (i=0; i<344; i++)
     //     printf("%02x ",((uint8_t *)txdata)[i]);
     //for (i=-1; i<2; i++)
     //    printf("%016lx ",*(long *)((struct iguana_pkhash *)((long)txdata + txdata->pkoffset))[i].rmd160);
     //printf("datalen.%d T.%d U.%d S.%d P.%d X.%d | %d vs %d ramchain.%p txdata.%p\n",txdata->datalen,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,txdata->numexternaltxids,txdata->pkoffset,(int32_t)((long)ramchain->P - (long)txdata),ramchain,txdata);
     ramchain->numtxids = txdata->numtxids;
     ramchain->numunspents = txdata->numunspents;
     ramchain->numspends = txdata->numspends;
     ramchain->numpkinds = txdata->numpkinds;
     ramchain->numexternaltxids = txdata->numexternaltxids;
     //printf("ramchain T.%d U.%d S.%d P.%d X.%d %p\n",ramchain->numtxids,ramchain->numunspents,ramchain->numspends,ramchain->numpkinds,ramchain->numexternaltxids,ramchain->externalT);
     if ( ramchain->numexternaltxids != 0 && ramchain->externalT == 0 )
     getchar();
     ramchain->prevhash2 = txdata->block.prev_block;
     ramchain->hash2 = txdata->block.hash2;
     return(ramchain);
     }
     
     int32_t iguana_ramchaintxid(struct iguana_info *coin,bits256 *txidp,struct iguana_ramchain *ramchain,struct iguana_spend *s)
     {
     memset(txidp,0,sizeof(*txidp));
     //printf("s.%p ramchaintxid vout.%x spendtxidind.%d numexternals.%d isext.%d numspendinds.%d\n",s,s->vout,s->spendtxidind,ramchain->numexternaltxids,s->external,ramchain->numspends);
     if ( s->vout == 0xffff )
     return(0);
     if ( s->external != 0 && s->spendtxidind < ramchain->numexternaltxids )
     {
     *txidp = ramchain->externalT[s->spendtxidind];
     return(0);
     }
     else if ( s->external == 0 && s->spendtxidind < ramchain->numtxids )
     {
     *txidp = ramchain->T[s->spendtxidind].txid;
     return(0);
     }
     return(-1);
     }*/
    
    /*if ( ptr->type == 'F' )
     {
     if ( addr != 0 && addr->fp != 0 )
     {
     //printf("flush.%s %p\n",addr->ipaddr,addr->fp);
     fflush(addr->fp);
     }
     }
     else*/
    
    /*    struct iguana_txblock *ptr; struct iguana_ramchain *ptrs[IGUANA_MAXBUNDLESIZE],*ramchains;
     struct iguana_block *block; char fname[1024]; uint64_t estimatedsize = 0;
     int32_t i,maxrecv,addrind,flag,bundlei,numdirs=0; struct iguana_ramchain *ramchain;
     flag = maxrecv = 0;
     memset(ptrs,0,sizeof(ptrs));
     ramchains = mycalloc('p',coin->chain->bundlesize,sizeof(*ramchains));
     for (i=0; i<bp->n && i<coin->chain->bundlesize; i++)
     {
     if ( (block= iguana_blockfind(coin,bp->hashes[i])) != 0 )
     {
     iguana_meminit(&memB[i],"ramchainB",0,block->recvlen*2 + 8192,0);
     if ( (ptr= iguana_peertxdata(coin,&bundlei,fname,&memB[i],block->ipbits,block->hash2)) != 0 )
     {
     if ( bundlei != i || ptr->block.bundlei != i )
     printf("peertxdata.%d bundlei.%d, i.%d block->bundlei.%d\n",bp->hdrsi,bundlei,i,ptr->block.bundlei);
     ptrs[i] = &ramchains[i];
     //char str[65];
     //printf("received txdata.%s bundlei.%d T.%d U.%d S.%d P.%d\n",bits256_str(str,ptr->block.hash2),bundlei,ptr->numtxids,ptr->numunspents,ptr->numspends,ptr->numpkinds);
     if ( iguana_ramchainset(coin,ptrs[i],ptr) == ptrs[i] )
     {
     char str[65]; int32_t err;
     //for (j=0; j<ptrs[i]->numpkinds; j++)
     //    init_hexbytes_noT(str,ptrs[i]->P[j].rmd160,20), printf("%s ",str);
     err = iguana_ramchainverifyPT(coin,ptrs[i]);
     printf("conv err.%d ramchain.%s bundlei.%d T.%d U.%d S.%d P.%d\n",err,bits256_str(str,ptrs[i]->data->firsthash2),bundlei,ptrs[i]->data->numtxids,ptrs[i]->data->numunspents,ptrs[i]->data->numspends,ptrs[i]->data->numpkinds);
     ptrs[i]->data->firsti = 0;
     if ( block->recvlen > maxrecv )
     maxrecv = block->recvlen;
     estimatedsize += block->recvlen;
     flag++;
     } else printf("error setting ramchain.%d\n",i);
     }
     else
     {
     printf("error (%s) hdrs.%d ptr[%d]\n",fname,bp->hdrsi,i);
     CLEARBIT(bp->recv,i);
     bp->issued[i] = 0;
     block = 0;
     }
     }
     }
     if ( flag == i )
     {
     printf("numpkinds >>>>>>>>> start MERGE.(%ld) i.%d flag.%d estimated.%ld maxrecv.%d\n",(long)mem->totalsize,i,flag,(long)estimatedsize,maxrecv);
     if ( (ramchain= iguana_ramchainmergeHT(coin,mem,ptrs,i,bp)) != 0 )
     {
     iguana_ramchainsave(coin,ramchain);
     iguana_ramchainfree(coin,mem,ramchain);
     //printf("ramchain saved\n");
     bp->emitfinish = (uint32_t)time(NULL);
     for (addrind=0; addrind<IGUANA_MAXPEERS; addrind++)
     {
     if ( coin->peers.active[addrind].ipbits != 0 )
     {
     if ( iguana_peerfile_exists(coin,&coin->peers.active[addrind],fname,bp->hashes[0]) >= 0 )
     {
     //printf("remove.(%s)\n",fname);
     //iguana_removefile(fname,0);
     //coin->peers.numfiles--;
     }
     }
     }
     } else bp->emitfinish = 0;
     }
     else
     {
     printf(">>>>> bundlesaveHT error: numdirs.%d i.%d flag.%d\n",numdirs,i,flag);
     bp->emitfinish = 0;
     }
     for (i=0; i<bp->n && i<coin->chain->bundlesize; i++)
     iguana_mempurge(&memB[i]);
     myfree(ramchains,coin->chain->bundlesize * sizeof(*ramchains));
     return(flag);*/
    
#ifdef oldway
    int32_t iguana_verifyiAddr(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize)
    {
        struct iguana_iAddr *iA = value;
        if ( itemind == 0 || iA->ipbits != 0 )
            return(0);
        else return(-1);
    }
    
    int32_t iguana_initiAddr(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,int32_t itemind,int32_t itemsize,int32_t numitems)
    {
        struct iguana_iAddr *iA = value;
        if ( key == 0 && value == 0 && itemind < 0 && numitems == 0 )
        {
        }
        else
        {
            if ( iA != 0 )
                iA->status = 0;
            coin->numiAddrs++;
            //printf("%x numiAddrs.%d\n",iA->ipbits,coin->numiAddrs);
        }
        return(0);
    }
    
    int32_t iguana_verifyblock(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize)
    {
        struct iguana_block *block;
        block = value;
        if ( bits256_nonz(block->hash2) != 0 )
            return(0);
        else return(-1);
    }
    
    int32_t iguana_initblock(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,int32_t itemind,int32_t itemsize,int32_t numitems)
    {
        bits256 genesis; //struct iguana_block *block = value;
        if ( key == 0 && value == 0 && itemind < 0 && numitems == 0 )
        {
            if ( coin->blocks.db == 0 )
                coin->blocks.db = kv;
            genesis = iguana_genesis(coin,coin->chain);
            if ( bits256_nonz(genesis) == 0 )
                return(-1);
            else return(0);
        }
        return(0);
    }
    
    int32_t iguana_nullinit(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,int32_t itemind,int32_t itemsize,int32_t numitems)
    {
        if ( key != 0 && value != 0 && itemind > 0 )
        {
        }
        return(0);
    }
    
    int32_t iguana_verifyunspent(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize)
    {
        if ( itemind < coin->latest.dep.numunspents )
            return(0);
        else return(-1);
    }
    
    int32_t iguana_verifyspend(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize)
    {
        if ( itemind < coin->latest.dep.numspends )
            return(0);
        else return(-1);
    }
    
    int32_t iguana_verifytxid(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize)
    {
        if ( itemind < coin->latest.dep.numtxids )
            return(0);
        else return(-1);
    }
    
    int32_t iguana_inittxid(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,int32_t itemind,int32_t itemsize,int32_t numitems)
    {
        //uint32_t checktxidind,firstvout,firstvin; struct iguana_txid *tx = value;
        if ( key != 0 && value != 0 && itemind > 0 )
        {
            /*printf("inittxid.(%s) itemind.%d (%d %d)\n",bits256_str(tx->txid),itemind,tx->firstvout,tx->firstvin);
             checktxidind = iguana_txidind(coin,&firstvout,&firstvin,tx->txid);
             if ( checktxidind != itemind )
             {
             printf("init checktxidind != itemind: %s -> %d vs %d\n",bits256_str(tx->txid),checktxidind,itemind);
             return(-1);
             }*/
        }
        return(0);
    }
    
    int32_t iguana_verifypkhash(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize)
    {
        if ( itemind < coin->latest.dep.numpkinds )
            return(0);
        else return(-1);
    }
    
    struct iguanakv *iguana_kvinit(char *name,int32_t keysize,int32_t threadsafe,int32_t mapped_datasize,int32_t RAMvaluesize,int32_t keyoffset,int32_t flags,int32_t valuesize2,int32_t valuesize3)
    {
        struct iguanakv *kv;
        printf("iguana_kvinit.(%s) keysize.%d mapped_datasize.%d keyoffset.%d\n",name,keysize,mapped_datasize,keyoffset);
        kv = mycalloc('K',1,sizeof(*kv));
        portable_mutex_init(&kv->MMlock);
        //portable_mutex_init(&kv->MEM.mutex);
        portable_mutex_init(&kv->HASHPTRS.mutex);
        portable_mutex_init(&kv->KVmutex);
        strcpy(kv->name,name);
        kv->flags = flags;
        kv->valuesize2 = valuesize2, kv->valuesize3 = valuesize3;
        kv->RAMvaluesize = RAMvaluesize;
        kv->HDDvaluesize = mapped_datasize;
        kv->keyoffset = keyoffset;
        kv->mult = IGUANA_ALLOC_MULT;
        kv->threadsafe = threadsafe;
        kv->keysize = keysize;
        return(kv);
    }
    
    int32_t iguana_loadkvfile(struct iguana_info *coin,struct iguanakv *kv,int32_t valuesize,int32_t (*verifyitem)(struct iguana_info *coin,void *key,void *ptr,int32_t itemind,int32_t itemsize),int32_t (*inititem)(struct iguana_info *coin,struct iguanakv *kv,void *key,void *ptr,int32_t itemind,int32_t itemsize,int32_t numitems),int32_t maxind)
    {
        FILE *fp; long fpos; uint8_t *ptr; double lastdisp,factor; int32_t numitems=0,itemind,j,n,skip = 0;
        factor = 1.;
        if ( (fp= fopen(kv->fname,"rb")) != 0 )
        {
            fseek(fp,0,SEEK_END);
            fpos = ftell(fp);
            numitems = (int32_t)(fpos / valuesize);
            fclose(fp);
            if ( kv->RAMvaluesize > 0  && kv->HDDvaluesize > 0 && kv->RAMvaluesize > kv->HDDvaluesize && numitems > 0 )
                numitems--;
            iguana_kvensure(coin,kv,0);
            if ( numitems > 2 || maxind > 0 )
            {
                if ( maxind == 0 )
                {
                    for (itemind=numitems-2; itemind>0; itemind--)
                    {
                        ptr = (uint8_t *)((unsigned long)kv->M.fileptr + ((unsigned long)itemind * kv->HDDvaluesize));
                        if ( (*verifyitem)(coin,(void *)&ptr[kv->keyoffset],(void *)ptr,itemind,kv->RAMvaluesize) < 0 )
                        {
                            numitems = itemind + 1;
                            printf("numitems.%d\n",numitems);
                            break;
                        }
                    }
                } else numitems = maxind;
                if ( numitems > 0 )
                {
                    lastdisp = 0.;
                    for (itemind=0; itemind<numitems; itemind++)
                    {
                        if ( numitems > 1000000 && ((double)itemind / numitems) > lastdisp+.01*factor )
                        {
                            if ( factor == 1. )
                                fprintf(stderr,"%.0f%% ",100. * lastdisp);
                            else fprintf(stderr,"%.2f%% ",100. * lastdisp);
                            lastdisp = ((double)itemind / numitems);
                        }
                        ptr = (uint8_t *)((uint64_t)kv->M.fileptr + ((uint64_t)itemind * kv->HDDvaluesize));
                        if ( 0 && kv->keysize > 0 )
                        {
                            for (j=0; j<kv->keysize; j++)
                                if ( ptr[j] != 0 )
                                    break;
                            if ( j != kv->keysize && iguana_kvread(coin,kv,(void *)&ptr[kv->keyoffset],kv->space,(uint32_t *)&n) != 0 )
                            {
                                printf("%s: skip duplicate %llx itemind.%d already at %d\n",kv->name,*(long long *)&ptr[kv->keyoffset],itemind,n);
                                continue;
                            }
                            //printf("%s uniq item at itemind.%d\n",kv->name,itemind);
                        }
                        if ( (*verifyitem)(coin,(void *)&ptr[kv->keyoffset],(void *)ptr,itemind,kv->RAMvaluesize) == 0 )
                        {
                            //if ( strcmp("txids",kv->name) == 0 )
                            //printf("inititem.%d %p (%s)\n",itemind,ptr,bits256_str(*(bits256 *)&ptr[kv->keyoffset]));
                            //    iguana_kvwrite(coin,kv,(void *)&ptr[kv->keyoffset],sp->space,(uint32_t *)&n);
                            if ( (*inititem)(coin,kv,(void *)&ptr[kv->keyoffset],(void *)ptr,itemind,kv->RAMvaluesize,numitems) == 0 )
                            {
                                kv->numvalid++;
                                n = itemind;
                                memcpy(kv->space,ptr,kv->RAMvaluesize);
                                if ( kv->keysize > 0 )
                                    iguana_kvwrite(coin,kv,(void *)&ptr[kv->keyoffset],kv->space,(uint32_t *)&n);
                                else iguana_kvwrite(coin,kv,0,kv->space,(uint32_t *)&n);
                            } else skip++;
                        } else break;
                    }
                }
            }
            kv->numitems = numitems;
            kv->numkeys = numitems;
            kv->maxitemind = (numitems > 0 ) ? numitems - 1 : 0;
            printf("%s: numkeys.%d numitems.%d numvalid.%d maxitemind.%d skipped.%d ELAPSED %.2f minutes\n",kv->name,kv->numkeys,kv->numitems,kv->numvalid,kv->maxitemind,skip,(double)(time(NULL)-coin->starttime)/60.);
            if ( (kv->flags & IGUANA_ITEMIND_DATA) != 0 )
                iguana_syncmap(&kv->M,0);
            /*if ( strcmp(kv->name,"iAddrs") == 0 && kv->numkeys < numitems/2 )
             {
             iguana_closemap(&kv->M);
             printf("truncate?\n"), getchar();
             truncate(kv->fname,(kv->numkeys+100)*kv->HDDvaluesize);
             }*/
        }
        return(numitems);
    }
    
    struct iguanakv *iguana_stateinit(struct iguana_info *coin,int32_t flags,char *coinstr,char *subdir,char *name,int32_t keyoffset,int32_t keysize,int32_t HDDvaluesize,int32_t RAMvaluesize,int32_t inititems,int32_t (*verifyitem)(struct iguana_info *coin,void *key,void *ptr,int32_t itemind,int32_t itemsize),int32_t (*inititem)(struct iguana_info *coin,struct iguanakv *kv,void *key,void *ptr,int32_t itemind,int32_t itemsize,int32_t numitems),int32_t valuesize2,int32_t valuesize3,int32_t maxind,int32_t initialnumitems,int32_t threadsafe)
    {
        struct iguanakv *kv; int32_t valuesize;
        if ( maxind <= 1 )
            maxind = 0;
        printf("%s MAX.%d\n",name,maxind);
        if ( HDDvaluesize == 0 )
            valuesize = HDDvaluesize = RAMvaluesize;
        else valuesize = HDDvaluesize;
        kv = iguana_kvinit(name,keysize,threadsafe,HDDvaluesize,RAMvaluesize,keyoffset,flags,valuesize2,valuesize3);
        if ( kv == 0 )
        {
            printf("cant initialize kv.(%s)\n",name);
            exit(-1);
        }
        if ( (kv->incr= inititems) == 0 )
            kv->incr = IGUANA_ALLOC_INCR;
        strcpy(kv->name,name);
        sprintf(kv->fname,"DB/%s/%s",coin->symbol,kv->name), iguana_compatible_path(kv->fname);
        portable_mutex_init(&kv->MMmutex);
        kv->space = mycalloc('K',1,RAMvaluesize + kv->keysize);
        kv->maxitemind = kv->numvalid = kv->numitems = 0;
        if ( strcmp("txids",kv->name) == 0 )
            coin->txids = kv;
        else if ( strcmp("pkhashes",kv->name) == 0 )
            coin->pkhashes = kv;
        printf("kv.%p chain.%p\n",kv,coin->chain);
        (*inititem)(coin,kv,0,0,-1,valuesize,0);
        iguana_loadkvfile(coin,kv,valuesize,verifyitem,inititem,maxind);
        if ( initialnumitems != 0 )
            iguana_kvensure(coin,kv,initialnumitems);
        return(kv);
    }
    
    uint32_t iguana_syncs(struct iguana_info *coin)
    {
        FILE *fp; char fnameold[512],fnameold2[512],fname[512],fname2[512]; int32_t i,height,flag = 0;
        if ( (coin->blocks.parsedblocks > coin->longestchain-1000 && (coin->blocks.parsedblocks % 100) == 1) ||
            (coin->blocks.parsedblocks > coin->longestchain-10000 && (coin->blocks.parsedblocks % 1000) == 1) ||
            (coin->blocks.parsedblocks > coin->longestchain-2000000 && (coin->blocks.parsedblocks % 10000) == 1) ||
            (coin->blocks.parsedblocks > coin->firstblock+100 && (coin->blocks.parsedblocks % 100000) == 1) )
        {
            if ( coin->blocks.parsedblocks > coin->loadedLEDGER.snapshot.height+2 )
                flag = 1;
        }
        if ( flag != 0 )
        {
            height = coin->blocks.parsedblocks - (coin->firstblock != 0);
            for (i=0; i<IGUANA_NUMAPPENDS; i++)
                printf("%llx ",(long long)coin->LEDGER.snapshot.lhashes[i].txid);
            char str[65];
            bits256_str(str,coin->LEDGER.snapshot.ledgerhash);
            printf("-> syncs %s ledgerhashes.%d\n",str,height);
            //iguana_syncmap(&coin->iAddrs->M,0);
            iguana_syncmap(&coin->blocks.db->M,0);
            iguana_syncmap(&coin->unspents->M,0);
            iguana_syncmap(&coin->unspents->M2,0);
            iguana_syncmap(&coin->spends->M,0);
            iguana_syncmap(&coin->spends->M2,0);
            iguana_syncmap(&coin->txids->M,0);
            iguana_syncmap(&coin->pkhashes->M,0);
            iguana_syncmap(&coin->pkhashes->M2,0);
            iguana_syncmap(&coin->pkhashes->M3,0);
            printf("%s threads.%d iA.%d ranked.%d hwm.%u parsed.%u T.%d U.%d %.8f S.%d %.8f net %.8f P.%d\n",coin->symbol,iguana_numthreads(coin,-1),coin->numiAddrs,coin->peers.numranked,coin->blocks.hwmheight+1,height,coin->latest.dep.numtxids,coin->latest.dep.numunspents,dstr(coin->latest.credits),coin->latest.dep.numspends,dstr(coin->latest.debits),dstr(coin->latest.credits)-dstr(coin->latest.debits),coin->latest.dep.numpkinds);
            sprintf(fname,"tmp/%s/ledger.%d",coin->symbol,height);
            sprintf(fname2,"DB/%s/ledger",coin->symbol);
            sprintf(fnameold,"tmp/%s/ledger.old",coin->symbol);
            sprintf(fnameold2,"tmp/%s/ledger.old2",coin->symbol);
            iguana_renamefile(fnameold,fnameold2);
            iguana_renamefile(fname2,fnameold);
            if ( (fp= fopen(fname,"wb")) != 0 )
            {
                if ( fwrite(coin->accounts,sizeof(*coin->accounts),coin->LEDGER.snapshot.dep.numpkinds,fp) != coin->LEDGER.snapshot.dep.numpkinds )
                    printf("WARNING: error saving %s accounts[%d]\n",fname,coin->LEDGER.snapshot.dep.numpkinds);
                if ( fwrite(&coin->LEDGER,1,sizeof(coin->LEDGER),fp) != sizeof(coin->LEDGER) )
                    printf("WARNING: error saving %s\n",fname);
                fclose(fp);
                iguana_copyfile(fname,fname2,1);
            }
            printf("backups created\n");
        }
        return((uint32_t)time(NULL));
    }
    
    // 480a886f78a52d94 2c16330bdd8565f2 fbfb8ba91a6cd871 d1feb1e96190d4ff b8fef8854847e7db 8d2692bcfe41c777 ec86c8502288022f 789ebb3966bb640f -> pre parse 35ee0080a9a132e88477e8809a6e2a0696a06b8c7b13fbfde2955998346dd5c8 ledgerhashes.120000
    // 9d1025feba33725a d69751b2f8d3f626 1f19457ce24411f1 76e12fd68b3b5b3c 2ad1a1e4b3b7014e a699f2904d073771 989c145c04a7a0d0 e888ab12de678518 -> syncs b8cf6b625de1d921695d1d2247ad68b86d047adf417c09562dc620ada993c47d ledgerhashes.140000
    // 53faf4c08ae7cd66 60af0f6074a4460a 8fa0f21eb4996161 7d695aa60788e52c 45a5c96ef55a1797 7b3225a83646caec d2d5788986315066 27372b0616caacf0 -> syncs c874aa3554c69038574e7da352eb624ac539fed97bf73b605d00df0c8cec4c1b ledgerhashes.200000
    // 739df50dbbaedada b83cbd69f08d2a0f 7a8ffa182706c5b7 8215ff6c7ffb9985 4d674a6d386bd759 f829283534a1804 aeb3b0644b01e07f 7ffe4899a261ca96 -> syncs fba47203d5c1d08e5cf55fa461f4deb6d0c97dcfa364ee5b51f0896ffcbcbaa7 ledgerhashes.300000
    // 739df50dbbaedada b83cbd69f08d2a0f 7a8ffa182706c5b7 8215ff6c7ffb9985 4d674a6d386bd759 f829283534a1804 b5e66cbe3a2bdbea 7ffe4899a261ca96 -> syncs 6b3620ba67fad34a29dd86cd5ec9fe6afd2a81d8a5296aa33b03da74fdd20a9b ledgerhashes.300001
    
    int32_t iguana_loadledger(struct iguana_info *coin,int32_t hwmheight)
    {
        FILE *fp; char fname[512],mapname[512],newfname[512]; struct iguana_block *block; struct iguana_prevdep L;
        struct iguana_prevdep *dep; int32_t height,i,valid = 0;
        dep = &coin->latest.dep;
        sprintf(fname,"DB/%s/ledger",coin->symbol);
        mapname[0] = newfname[0] = 0;
        if ( (fp= fopen(fname,"rb")) == 0 )
        {
            sprintf(fname,"tmp/%s/ledger.old",coin->symbol);
            if ( (fp= fopen(fname,"rb")) == 0 )
            {
                sprintf(fname,"tmp/%s/ledger.old2",coin->symbol);
                fp = fopen(fname,"rb");
            }
        }
        if ( fp != 0 )
        {
            sprintf(mapname,"DB/%s/pkhashes2",coin->symbol);
            sprintf(newfname,"DB/%s/pkhashes2.over",coin->symbol);
            fseek(fp,-sizeof(coin->LEDGER),SEEK_END);
            if ( fread(&coin->LEDGER,1,sizeof(coin->LEDGER),fp) != sizeof(coin->LEDGER) )
                printf("WARNING: error loading %s\n",fname);
            if ( (block= iguana_blockptr(coin,coin->LEDGER.snapshot.height)) != 0 )
            {
                if ( memcmp(block->hash2.bytes,coin->LEDGER.snapshot.blockhash.bytes,sizeof(block->hash2)) == 0 )
                {
                    fclose(fp);
                    iguana_renamefile(mapname,newfname);
                    iguana_renamefile(fname,mapname);
                    *dep = coin->LEDGER.snapshot.dep;
                    coin->loadedLEDGER = coin->LEDGER;
                    memcpy(&coin->latest.ledgerhash,&coin->LEDGER.snapshot.ledgerhash,sizeof(coin->LEDGER.snapshot.ledgerhash));
                    memcpy(coin->latest.lhashes,coin->LEDGER.snapshot.lhashes,sizeof(coin->LEDGER.snapshot.lhashes));
                    memcpy(coin->latest.states,coin->LEDGER.snapshot.states,sizeof(coin->LEDGER.snapshot.states));
                    printf("found ledger height.%d loadedht.%d\n",block->height,coin->LEDGER.snapshot.height); //getchar();
                    for (i=0; i<IGUANA_NUMAPPENDS; i++)
                        printf("%llx ",(long long)coin->LEDGER.snapshot.lhashes[i].txid);
                    char str[65];
                    bits256_str(str,coin->LEDGER.snapshot.ledgerhash);
                    printf("-> %s ledgerhashes.%x\n",str,calc_crc32(0,&coin->latest.states[IGUANA_LHASH_TXIDS],sizeof(coin->latest.states[IGUANA_LHASH_TXIDS])));
                    printf("loaded H.%d T%d U%d S%d P%d\n",coin->LEDGER.snapshot.height,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds); //getchar();
                    coin->latest.credits = coin->LEDGER.snapshot.credits;
                    coin->latest.debits = coin->LEDGER.snapshot.debits;
                    coin->latest.dep.supply = (coin->LEDGER.snapshot.credits - coin->LEDGER.snapshot.debits);
                    return(block->height);
                }
            }
            fclose(fp);
        }
        dep->numpkinds = dep->numtxids = dep->numunspents = dep->numspends = 1;
        while ( hwmheight > 0 )
        {
            if ( (block= iguana_blockptr(coin,hwmheight)) != 0 )
            {
                iguana_setdependencies(coin,block,&L);
                //printf("block.%d: T.%d (%d %d) U.%d S.%d A.%d\n",hwmheight,dep->numtxids,block->numvouts,block->numvins,dep->numunspents,dep->numspends,dep->numpkhashes);
                if ( L.numtxids != 0 && L.numunspents != 0 && L.numspends != 0 && block->numvouts != 0 && block->txn_count != 0 && L.numpkinds != 0 )
                {
                    if ( valid++ > 25 )
                        break;
                }
            } else printf("missing block.%d\n",hwmheight);
            hwmheight--;
        }
        for (height=0; height<=hwmheight; height++)
        {
            if ( iguana_setdependencies(coin,iguana_blockptr(coin,height),&L) < 0 )
                break;
            dep->numtxids = L.numtxids + 0*block->txn_count;
            dep->numunspents = L.numunspents + 0*block->numvouts;
            dep->numspends = L.numspends + 0*block->numvins;
            dep->numpkinds = L.numpkinds;
        }
        return(hwmheight);
    }
    
    int32_t iguana_validateramchain(struct iguana_info *coin,int64_t *netp,uint64_t *creditsp,uint64_t *debitsp,int32_t height,struct iguana_block *block,int32_t hwmheight,struct iguana_prevdep *lp)
    {
        uint32_t i,n,m,u,txidind,unspentind,spendind,pkind,checkind,numvins,numvouts,txind,firstvout,firstvin,nextfirstvout,nextfirstvin; struct iguana_prevdep *nextlp;
        struct iguana_txid T,nextT; uint64_t credits,debits,nets; struct iguana_block *nextblock;
        credits = debits = nets = *creditsp = *debitsp = *netp = numvouts = numvins = 0;
        if ( block->height == height )
        {
            txidind = lp->numtxids, unspentind = lp->numunspents, spendind = lp->numspends, pkind = lp->numpkinds;
            //printf("validate.%d (t%d u%d s%d p%d)\n",height,txidind,unspentind,spendind,pkind);
            for (txind=0; txind<block->txn_count; txind++,txidind++)
            {
                T = coin->T[txidind], nextT = coin->T[txidind+1];
                //printf("h%d i%d T.%d (%d %d) -> (%d %d)\n",height,txind,txidind,T.firstvout,T.firstvin,nextT.firstvout,nextT.firstvin);
                if ( height == 0 && (T.firstvout == 0 || T.firstvin == 0) )
                    return(-1);
                //printf(">>>> h%d i%d T.%d (%d %d) -> (%d %d) cmp.(%d %d)\n",height,txind,txidind,T.firstvout,T.firstvin,nextT.firstvout,nextT.firstvin,height == 0,(T.firstvout == 0 || T.firstvin == 0));
                if ( (checkind= iguana_txidind(coin,&firstvout,&firstvin,T.txid)) == txidind )
                {
                    if ( T.firstvout != firstvout || T.firstvin != firstvin )
                    {
                        printf("mismatched rwtxidind %d != %d, %d != %d\n",T.firstvout,firstvout,T.firstvin,firstvin);
                        getchar();
                        return(-1);
                    }
                    if ( txind == 0 && (firstvout != unspentind || firstvin != spendind) )
                    {
                        char str[65];
                        bits256_str(str,T.txid);
                        printf("h.%d txind.%d txidind.%d %s firstvout.%d != U%d firstvin.%d != S%d\n",height,txind,txidind,str,firstvout,unspentind,firstvin,spendind);
                        iguana_txidind(coin,&firstvout,&firstvin,T.txid);
                        iguana_txidind(coin,&firstvout,&firstvin,T.txid);
                        return(-1);
                    }
                    nextfirstvout = nextT.firstvout, nextfirstvin = nextT.firstvin;
                    if ( nextfirstvout < unspentind || nextfirstvin < spendind )
                    {
                        printf("h.%d txind.%d nexttxidind.%d firstvout.%d != U%d firstvin.%d != S%d\n",height,txind,txidind,nextfirstvout,unspentind,nextfirstvin,spendind);
                        if ( nextfirstvout == 0 && nextfirstvin == 0 )
                        {
                            coin->T[txidind+1].firstvout = unspentind;
                            coin->T[txidind+1].firstvin = spendind;
                            printf("autofixed\n");
                        }
                        else
                        {
                            getchar();
                            return(-1);
                        }
                    }
                    n = (nextfirstvout - T.firstvout);
                    m = (nextfirstvin - T.firstvin);
                    //printf("height.%d n.%d m.%d U.(%d - %d) S.(%d - %d)\n",height,n,m,nextfirstvout,T.firstvout,nextfirstvin,T.firstvin);
                    for (i=0; i<n; i++,unspentind++)
                    {
                        credits += coin->U[unspentind].value;
                        if ( coin->Uextras[unspentind].spendind == 0 )
                            nets += coin->U[unspentind].value;
                        if ( coin->U[unspentind].pkind > pkind )
                            pkind = coin->U[unspentind].pkind;
                        //printf("i.%d: unspentind.%d\n",i,unspentind);
                    }
                    for (i=0; i<m; i++,spendind++)
                    {
                        if ( (u= coin->S[spendind].spendtxidind) > 0 && u < coin->latest.dep.numunspents )
                            debits += coin->U[u].value;
                        else
                        {
                            printf("cant read spendind.%d or S.unspentind %d\n",spendind+i,u);
                            getchar();
                        }
                    }
                    numvouts += n;
                    numvins += m;
                }
                else
                {
                    char str[65];
                    bits256_str(str,T.txid);
                    printf("height.%d txind.%d txid.%s txidind.%d != %d\n",height,txind,str,txidind,checkind);
                    getchar();
                    return(-1);
                }
            }
            if ( numvins != block->numvins || numvouts != block->numvouts )
            {
                printf("height.%d numvins or numvouts error %d != %d || %d != %d\n",height,numvins,block->numvins,numvouts,block->numvouts);
                if ( block->numvins == 0 && block->numvouts == 0 )
                {
                    block->numvins = numvins;
                    block->numvouts = numvouts;
                    iguana_kvwrite(coin,coin->blocks.db,0,block,(uint32_t *)&block->height);
                    m = 0;//iguana_fixblocks(coin,height,hwmheight);
                    printf("autocorrected.%d\n",m);
                    exit(1);
                }
                else
                {
                    getchar();
                    return(-1);
                }
            }
            *creditsp = credits, *debitsp = debits, *netp = nets;
            if ( (nextblock= iguana_blockptr(coin,height+1)) != 0 )
            {
                nextlp = 0;
                if ( 0 && lp->supply+credits-debits != nextlp->supply )
                {
                    printf("nextblock.%d supply mismatch %.8f (%.8f - %.8f)  %.8f != %.8f\n",height+1,dstr(lp->supply),dstr(credits),dstr(debits),dstr(lp->supply+credits-debits),dstr(nextlp->supply));
                    getchar();
                    return(-1);
                }
                if ( txidind != nextlp->numtxids || unspentind != nextlp->numunspents || spendind != nextlp->numspends )//|| pkind+1 != nextlp->numpkinds )
                {
                    printf("Block.(h%d t%d u%d s%d p%d) vs next.(h%d t%d u%d s%d p%d)\n",block->height,txidind,unspentind,spendind,pkind,height+1,nextlp->numtxids,nextlp->numunspents,nextlp->numspends,nextlp->numpkinds);
                    return(-1);
                }
                return(0);
            }
            printf("cant find next block at %d\n",height+1);
            //printf("block.%d %.8f (%.8f - %.8f)\n",height,dstr(nets),dstr(credits),dstr(debits));
        } else printf("height mismatch %d != %d\n",height,block->height);
        //getchar();
        return(-1);
    }
    
    int32_t iguana_fixsecondary(struct iguana_info *coin,int32_t numtxids,int32_t numunspents,int32_t numspends,int32_t numpkinds,struct iguana_Uextra *Uextras,struct iguana_pkextra *pkextras,struct iguana_account *accounts)
    {
        uint32_t i; int32_t m,err;
        if ( numtxids < 2 || numunspents < 2 || numspends < 2 || numpkinds < 2 )
            return(0);
        //struct iguana_Uextra { uint32_t spendind; }; // unspentind
        //struct iguana_unspent { uint64_t value; uint32_t pkind,txidind,prevunspentind; };
        for (i=m=err=0; i<numunspents; i++)
        {
            if ( Uextras[i].spendind >= numspends )
                m++, Uextras[i].spendind = 0;//, printf("%d ",Uextras[i].spendind);
            if ( coin->U[i].prevunspentind != 0 && coin->U[i].prevunspentind >= i )
                err++, printf("preverr.%d/%d ",coin->U[i].prevunspentind,i);
            if ( coin->U[i].txidind >= numtxids )
                err++, printf("errtxidind.%d ",coin->U[i].txidind);
            if ( coin->U[i].pkind >= numpkinds )
                err++, printf("errpkind.%d ",coin->U[i].pkind);
        }
        if ( (err+m) != 0 )
            iguana_syncmap(&coin->unspents->M2,0);
        printf("cleared %d Uextras before numunspents.%d beyond errs.%d\n",m,numunspents,err);
        if ( err != 0 )
            getchar();
        //struct iguana_pkextra { uint32_t firstspendind; }; // pkind
        for (i=m=0; i<numpkinds; i++)
        {
            if ( pkextras[i].firstspendind >= numspends )
                m++, pkextras[i].firstspendind = 0;//, printf("firstS.%d ",pkextras[i].firstspendind);
        }
        if ( m != 0 )
            iguana_syncmap(&coin->pkhashes->M3,0);
        printf("pkextras beyond numspends.%d m.%d accounts.%p\n",numspends,m,accounts);
        //struct iguana_spend { uint32_t unspentind,prevspendind; }; // dont need nextspend
        /*for (i=err=m=0; i<numspends; i++)
         {
         if ( coin->S[i].unspentind >= numunspents )
         err++, coin->S[i].unspentind = 0;//, printf("S->U%d ",coin->S[i].unspentind);
         //printf("%d ",coin->S[i].prevspendind);
         if ( coin->Sextras[i].prevspendind != 0 && coin->Sextras[i].prevspendind >= i )
         m++, coin->Sextras[i].prevspendind = 0, printf("preverr.%d:%d ",coin->Sextras[i].prevspendind,i);
         }
         printf("errs.%d in spends numspends.%d\n",err,numspends);
         if ( err != 0 )
         getchar();*/
        return(0);
    }
    
    void clearmem(void *ptr,int32_t len)
    {
        static const uint8_t zeroes[512];
        if ( len > sizeof(zeroes) || memcmp(ptr,zeroes,len) != 0 )
            memset(ptr,0,len);
    }
    
    int32_t iguana_clearoverage(struct iguana_info *coin,int32_t numtxids,int32_t numunspents,int32_t numspends,int32_t numpkinds,struct iguana_Uextra *Uextras,struct iguana_pkextra *pkextras,struct iguana_account *accounts)
    {
        uint32_t i,n;
        printf("clear txids\n");
        n = (uint32_t)((uint64_t)coin->txids->M.allocsize / coin->txids->HDDvaluesize) - 2;
        for (i=numtxids+1; i<n; i++) // diff with next txid's firstv's give numv's
            clearmem(&coin->T[i],sizeof(coin->T[i]));
        
        printf("clear pkinds\n");
        n = (uint32_t)((uint64_t)coin->pkhashes->M.allocsize / coin->pkhashes->HDDvaluesize) - 2;
        for (i=numpkinds; i<n; i++)
            clearmem(&coin->P[i],sizeof(coin->P[i]));
        n = (uint32_t)((uint64_t)coin->pkhashes->M2.allocsize / coin->pkhashes->valuesize2) - 2;
        for (i=numpkinds; i<n; i++)
            clearmem(&accounts[i],sizeof(accounts[i]));
        n = (uint32_t)((uint64_t)coin->pkhashes->M3.allocsize / coin->pkhashes->valuesize3) - 2;
        for (i=numpkinds; i<n; i++)
            pkextras[i].firstspendind = 0;
        
        printf("clear unspents\n");
        n = (uint32_t)((uint64_t)coin->unspents->M.allocsize / coin->unspents->HDDvaluesize) - 2;
        for (i=numunspents; i<n; i++)
            clearmem(&coin->U[i],sizeof(coin->U[i]));
        n = (uint32_t)((uint64_t)coin->unspents->M2.allocsize / coin->unspents->valuesize2) - 2;
        for (i=numunspents; i<n; i++)
            clearmem(&Uextras[i],sizeof(Uextras[i]));
        
        printf("clear spends\n");
        n = (uint32_t)((uint64_t)coin->spends->M.allocsize / coin->spends->HDDvaluesize) - 2;
        for (i=numspends; i<n; i++)
            clearmem(&coin->S[i],sizeof(coin->S[i]));
        //n = (uint32_t)((uint64_t)coin->spends->M2.allocsize / coin->spends->valuesize2) - 2;
        //for (i=numspends; i<n; i++)
        //    clearmem(&coin->Sextras[i],sizeof(coin->Sextras[i]));
        return(0);
    }
    
    int64_t iguana_verifybalances(struct iguana_info *coin,int32_t fullverify)
    {
        int64_t err,balance = 0; int32_t i,numerrs = 0;
        for (i=0; i<coin->latest.dep.numpkinds; i++)
        {
            if ( fullverify != 0 )
            {
                if ( (err= iguana_verifyaccount(coin,&coin->accounts[i],i)) < 0 )
                {
                    printf("err.%d from pkind.%d\n",(int32_t)err,i);
                    numerrs++;
                }
            }
            balance += coin->accounts[i].balance;
        }
        printf("iguana_verifybalances %.8f numerrs.%d\n",dstr(balance),numerrs);
        if ( numerrs > 0 )
            getchar();
        return(balance);
    }
    
    int32_t iguana_initramchain(struct iguana_info *coin,int32_t hwmheight,int32_t mapflags,int32_t fullverify)
    {
        struct iguana_prevdep *dep; struct iguana_block *block,lastblock; double lastdisp = 0.;
        // init sequence is very tricky. must be done in the right order and make sure to only use data
        // that has already been initialized. and at the end all the required fields need to be correct
        struct iguana_msghdr H; uint8_t buf[1024]; int32_t len,height,valid=0,flag=0;
        struct iguana_prevdep L,prevL;
        int64_t checkbalance,net,nets; uint64_t prevcredits,prevdebits,credit,debit,credits,debits,origsupply;
        dep = &coin->latest.dep;
        height = hwmheight;
        if ( (height= iguana_loadledger(coin,hwmheight)) < 0 )
        {
            printf("iguana_initramchain: unrecoverable loadledger error hwmheight.%d\n",hwmheight);
            return(-1);
        }
        hwmheight = height;
        printf("four ramchains start valid.%d height.%d txids.%d vouts.%d vins.%d pkhashes.%d\n",valid,hwmheight,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds);
        //four ramchains start valid.0 height.316904 txids.45082870 vouts.27183907 vins.107472009 pkhashes.44807925 3.57 minutes
        
        coin->unspents = iguana_stateinit(coin,IGUANA_ITEMIND_DATA,coin->symbol,coin->symbol,"unspents",0,0,sizeof(struct iguana_unspent),sizeof(struct iguana_unspent),100000,iguana_verifyunspent,iguana_nullinit,sizeof(*coin->Uextras),0,dep->numunspents,2500000,0);
        if ( coin->unspents == 0 )
            printf("cant create unspents\n"), exit(1);
        coin->unspents->HDDitemsp = (void **)&coin->U, coin->U = coin->unspents->M.fileptr;
        coin->unspents->HDDitems2p = (void **)&coin->Uextras, coin->Uextras = coin->unspents->M2.fileptr;
        printf("four ramchains start valid.%d height.%d txids.%d vouts.%d vins.%d pkhashes.%d %.2f minutes\n",valid,hwmheight,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,((double)time(NULL)-coin->starttime)/60.);
        
        coin->spends = iguana_stateinit(coin,IGUANA_ITEMIND_DATA,coin->symbol,coin->symbol,"spends",0,0,sizeof(struct iguana_spend),sizeof(struct iguana_spend),100000,iguana_verifyspend,iguana_nullinit,0,0,dep->numspends,2500000,0);
        if ( coin->spends == 0 )
            printf("cant create spends\n"), exit(1);
        printf("four ramchains start valid.%d height.%d txids.%d vouts.%d vins.%d pkhashes.%d %.2f minutes\n",valid,hwmheight,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,((double)time(NULL)-coin->starttime)/60.);
        coin->spends->HDDitemsp = (void **)&coin->S, coin->S = coin->spends->M.fileptr;
        coin->spends->HDDitems2p = (void **)&coin->Sextras, coin->Sextras = coin->spends->M2.fileptr;
        
        coin->txids = iguana_stateinit(coin,IGUANA_ITEMIND_DATA|((mapflags&IGUANA_MAPTXIDITEMS)!=0)*IGUANA_MAPPED_ITEM,coin->symbol,coin->symbol,"txids",0,sizeof(bits256),sizeof(struct iguana_txid),sizeof(struct iguana_txid),100000,iguana_verifytxid,iguana_inittxid,0,0,dep->numtxids,1000000,0);
        if ( coin->txids == 0 )
            printf("cant create txids\n"), exit(1);
        coin->txids->HDDitemsp = (void **)&coin->T, coin->T = coin->txids->M.fileptr;
        printf("four ramchains start valid.%d height.%d txids.%d vouts.%d vins.%d pkhashes.%d %.2f minutes\n",valid,hwmheight,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,((double)time(NULL)-coin->starttime)/60.);
        
        coin->pkhashes = iguana_stateinit(coin,IGUANA_ITEMIND_DATA|((mapflags&IGUANA_MAPPKITEMS)!=0)*IGUANA_MAPPED_ITEM,coin->symbol,coin->symbol,"pkhashes",0,20,sizeof(struct iguana_pkhash),sizeof(struct iguana_pkhash),100000,iguana_verifypkhash,iguana_nullinit,sizeof(*coin->accounts),sizeof(*coin->pkextras),dep->numpkinds,1000000,0);
        if ( coin->pkhashes == 0 )
            printf("cant create pkhashes\n"), exit(1);
        coin->pkhashes->HDDitemsp = (void **)&coin->P, coin->P = coin->pkhashes->M.fileptr;
        coin->pkhashes->HDDitems2p = (void **)&coin->accounts, coin->accounts = coin->pkhashes->M2.fileptr;
        coin->pkhashes->HDDitems3p = (void **)&coin->pkextras, coin->pkextras = coin->pkhashes->M3.fileptr;
        printf("four ramchains start valid.%d height.%d txids.%d vouts.%d vins.%d pkhashes.%d %.2f minutes\n",valid,hwmheight,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,((double)time(NULL)-coin->starttime)/60.);
        
        iguana_kvensure(coin,coin->txids,dep->numtxids + coin->txids->incr);
        iguana_kvensure(coin,coin->pkhashes,dep->numpkinds + coin->pkhashes->incr);
        iguana_kvensure(coin,coin->unspents,dep->numunspents + coin->unspents->incr);
        iguana_kvensure(coin,coin->spends,dep->numspends + coin->spends->incr);
        coin->txids->numkeys = dep->numtxids;
        coin->unspents->numkeys = dep->numunspents;
        coin->spends->numkeys = dep->numspends;
        coin->pkhashes->numkeys = dep->numpkinds;
        iguana_fixsecondary(coin,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,coin->Uextras,coin->pkextras,coin->accounts);
        printf("hwmheight.%d KV counts T.%d P.%d U.%d S.%d\n",hwmheight,coin->txids->numkeys,coin->pkhashes->numkeys,coin->unspents->numkeys,coin->spends->numkeys);
        memset(&lastblock,0,sizeof(lastblock));
        origsupply = dep->supply, dep->supply = 0;
        for (prevcredits=prevdebits=credits=debits=nets=height=0; height<=hwmheight; height++)
        {
            if ( hwmheight > 10000 && ((double)height / hwmheight) > lastdisp+.01 )
            {
                fprintf(stderr,"%.0f%% ",100. * lastdisp);
                lastdisp = ((double)height / hwmheight);
            }
            if ( (block= iguana_blockptr(coin,height)) == 0 )
            {
                printf("error getting height.%d\n",height);
                break;
            }
            lastblock = *block;
            if ( height == hwmheight )
                break;
            printf("need to set valid L\n");
            if ( iguana_validateramchain(coin,&net,&credit,&debit,height,block,hwmheight,&L) < 0 )
            {
                printf("UNRECOVERABLE error iguana_validateramchain height.%d\n",height);
                getchar();
                exit(1);
                break;
            }
            nets += net, credits += credit, debits += debit;
            if ( nets != (credits - debits) )
            {
                //printf("height.%d: net %.8f != %.8f (%.8f - %.8f)\n",height,dstr(nets),dstr(credits)-dstr(debits),dstr(credits),dstr(debits));
                //break;
            }
            prevcredits = credits;
            prevdebits = debits;
        }
        if ( lastblock.height == 0 )
            dep->numpkinds = dep->numspends = dep->numtxids = dep->numunspents = 1, dep->supply = 0, coin->latest.credits = coin->latest.debits = 0;
        else
        {
            printf("set prevL\n");
            dep->numtxids = prevL.numtxids;
            dep->numunspents = prevL.numunspents;
            dep->numspends = prevL.numspends;
            dep->numpkinds = prevL.numpkinds;
            dep->supply = prevL.supply;
            coin->latest.credits = prevcredits;
            coin->latest.debits = prevdebits;
            if ( dep->supply != (prevcredits - prevdebits) )
            {
                printf("override supply %.8f (%.8f - %.8f)\n",dstr(dep->supply),dstr(prevcredits),dstr(prevdebits));
                dep->supply = (prevcredits - prevdebits);
            }
            checkbalance = iguana_verifybalances(coin,0);
            if ( (checkbalance != dep->supply || fullverify != 0) && iguana_verifybalances(coin,1) != dep->supply )
            {
                printf("balances mismatch\n");
                getchar();
            }
        }
        coin->txids->numkeys = dep->numtxids;
        coin->unspents->numkeys = dep->numunspents;
        coin->spends->numkeys = dep->numspends;
        coin->pkhashes->numkeys = dep->numpkinds;
        coin->blocks.parsedblocks = lastblock.height;
        printf("\nhwmheight.%d KV counts T.%d P.%d U.%d S.%d %.8f (%.8f - %.8f)\n",hwmheight,coin->txids->numkeys,coin->pkhashes->numkeys,coin->unspents->numkeys,coin->spends->numkeys,dstr(coin->latest.dep.supply),dstr(coin->latest.credits),dstr(coin->latest.debits));
        printf("four ramchains start valid.%d height.%d txids.%d vouts.%d vins.%d pkhashes.%d %.2f minutes\n",valid,hwmheight,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,((double)time(NULL)-coin->starttime)/60.);
        printf("height.%d after validateramchain hwmheight.%d flag.%d parsed.%d\n",height,hwmheight,flag,coin->blocks.parsedblocks); //getchar();
        if ( coin->blocks.parsedblocks == 0 )
        {
            uint8_t txspace[32768]; struct iguana_memspace MEM;
            len = (int32_t)strlen(coin->chain->genesis_hex)/2;
            decode_hex(buf,len,(char *)coin->chain->genesis_hex);
            iguana_sethdr(&H,coin->chain->netmagic,"block",buf,len);
            iguana_meminit(&MEM,"genesis",txspace,sizeof(txspace),0);
            iguana_parser(coin,0,&MEM,&MEM,0,&H,buf,len);
            printf("coin->blocks.parsedblocks.%d KV counts T.%d P.%d U.%d S.%d\n",coin->blocks.parsedblocks,coin->txids->numkeys,coin->pkhashes->numkeys,coin->unspents->numkeys,coin->spends->numkeys);
            printf("auto parse genesis\n"); //getchar();
        }
        else iguana_clearoverage(coin,dep->numtxids,dep->numunspents,dep->numspends,dep->numpkinds,coin->Uextras,coin->pkextras,coin->accounts);
        return(coin->blocks.parsedblocks);
    }
#endif
    if ( 0 && queue_size(&coin->blocksQ) == 0 )
    {
        HASH_ITER(hh,coin->blocks.hash,block,tmp)
        {
            if ( bits256_nonz(block->prev_block) > 0 && (prev= iguana_blockfind(coin,block->prev_block)) != 0 )
            {
                if ( prev->mainchain != 0 )
                {
                    char str[65]; printf("idle issue %s %d\n",bits256_str(str,block->hash2),prev->height+1);
                    iguana_blockQ(coin,0,-1,block->hash2,0);
                }
            }
        }
    }
    struct iguana_ramchain *iguana_ramchainmergeHT(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_ramchain *ramchains[],int32_t n,struct iguana_bundle *bp)
    {
        /*    uint32_t numtxids,numunspents,numspends,numpkinds,numexternaltxids,i,j,k; uint64_t allocsize = 0;
         struct iguana_txid *tx;  struct iguana_account *acct; struct iguana_ramchain *ramchain,*item;
         struct iguana_pkhash *p,oldP; struct iguana_unspent *u; struct iguana_kvitem *ptr;
         bits256 txid; uint32_t txidind,unspentind,spendind,pkind,numblocks; struct iguana_spend *s;
         numtxids = numunspents = numspends = numpkinds = 1;
         numexternaltxids = 1;
         numblocks = 0;
         for (i=0; i<n; i++)
         {
         if ( (item= ramchains[i]) == 0 )
         {
         printf("iguana_ramchaininit null hdrsi.%d txdatas[%d]\n",bp->ramchain.hdrsi,i);
         return(0);
         }
         numtxids += item->numtxids, numunspents += item->numunspents, numspends += item->numspends;
         numpkinds += item->numpkinds, numexternaltxids += item->numexternaltxids;
         numblocks += item->numblocks;
         }
         allocsize = sizeof(*ramchain) +
         (numtxids * sizeof(*ramchain->T)) +
         (numunspents * (sizeof(*ramchain->U) + sizeof(*ramchain->Uextras))) +
         (numspends * sizeof(*ramchain->S)) +
         (numpkinds * (sizeof(*ramchain->P) + sizeof(*ramchain->pkextras) + sizeof(*ramchain->accounts))) +
         (numexternaltxids * sizeof(*ramchain->externalT));
         
         iguana_meminit(mem,"ramchain",0,allocsize,0);
         mem->alignflag = sizeof(uint32_t);
         ramchain= &bp->ramchain; //iguana_memalloc(mem,sizeof(*ramchain),1)) == 0 )
         ramchain->numblocks = numblocks;
         ramchain->numtxids = numtxids, ramchain->numunspents = numunspents;
         ramchain->numspends = numspends, ramchain->numpkinds = numpkinds;
         ramchain->numexternaltxids = numexternaltxids;
         ramchain->hdrsi = bp->ramchain.hdrsi, ramchain->bundleheight = bp->ramchain.bundleheight, ramchain->numblocks = n;
         ramchain->prevbundlehash2 = bp->prevbundlehash2, ramchain->nextbundlehash2 = bp->nextbundlehash2;
         ramchain->hash2 = ramchains[0]->hash2;
         ramchain->prevhash2 = ramchains[0]->prevhash2, ramchain->lasthash2 = ramchains[n-1]->hash2;
         ramchain->T = iguana_memalloc(mem,sizeof(*ramchain->T) * ramchain->numtxids,0);
         ramchain->U = iguana_memalloc(mem,sizeof(*ramchain->U) * ramchain->numunspents,0);
         if ( ramchain->numspends > 0 )
         ramchain->S = iguana_memalloc(mem,sizeof(*ramchain->S) * ramchain->numspends,0);
         ramchain->Uextras = iguana_memalloc(mem,sizeof(*ramchain->Uextras) * ramchain->numunspents,1);
         ramchain->P = iguana_memalloc(mem,sizeof(*ramchain->P) * ramchain->numpkinds,1);
         ramchain->pkextras = iguana_memalloc(mem,sizeof(*ramchain->pkextras) * ramchain->numpkinds,1);
         ramchain->accounts = iguana_memalloc(mem,sizeof(*ramchain->accounts) * ramchain->numpkinds,1);
         if ( ramchain->numexternaltxids > 0 )
         ramchain->externalT = iguana_memalloc(mem,ramchain->numexternaltxids * sizeof(*ramchain->externalT),1);
         if ( mem->used != allocsize )
         {
         printf("error allocating ramchain %ld != %ld\n",(long)mem->used,(long)allocsize);
         iguana_ramchainfree(coin,mem,ramchain);
         return(0);
         }
         ramchain->allocsize = allocsize;
         ramchain->firsti = 1;
         //printf("Allocated %s for bp %d\n",mbstr(str,allocsize),bp->ramchain.bundleheight);
         txidind = unspentind = numtxids = spendind = numunspents = numspends = numpkinds = ramchain->firsti;
         numexternaltxids = 0;
         for (i=0; i<n; i++)
         {
         if ( (item= ramchains[i]) != 0 )
         {
         // iguana_txid { bits256 txid; uint32_t txidind,firstvout,firstvin; uint16_t numvouts,numvins;}
         for (j=item->firsti; j<item->numtxids; j++,txidind++)
         {
         tx = &ramchain->T[txidind];
         *tx = item->T[j];
         tx->txidind = txidind;
         if ( (ptr= iguana_hashfind(ramchain->txids,tx->txid.bytes,sizeof(tx->txid))) != 0 )
         {
         printf("unexpected duplicate txid[%d]\n",txidind);
         iguana_ramchainfree(coin,mem,ramchain);
         return(0);
         }
         iguana_hashsetHT(ramchain->txids,0,tx->txid.bytes,sizeof(bits256),txidind);
         tx->firstvout = unspentind;
         for (k=item->firsti; k<tx->numvouts; k++,unspentind++)
         {
         u = &ramchain->U[unspentind];
         *u = item->U[k];
         u->txidind = txidind;
         oldP = item->P[item->U[k].pkind];
         if ( (ptr= iguana_hashfind(ramchain->pkhashes,oldP.rmd160,sizeof(oldP.rmd160))) == 0 )
         {
         pkind = numpkinds++;
         p = &ramchain->P[pkind];
         *p = oldP;
         p->firstunspentind = unspentind;
         if ( (ptr= iguana_hashsetHT(ramchain->pkhashes,0,p->rmd160,sizeof(p->rmd160),numpkinds)) == 0 )
         {
         iguana_ramchainfree(coin,mem,ramchain);
         printf("fatal error adding pkhash\n");
         return(0);
         }
         //printf("pkind.%d: %p %016lx <- %016lx\n",pkind,p,*(long *)p->rmd160,*(long *)oldP.rmd160);
         } else pkind = ptr->hh.itemind;
         u->pkind = pkind;
         acct = &ramchain->accounts[pkind];
         u->prevunspentind = acct->lastunspentind;
         acct->lastunspentind = unspentind;
         acct->balance += u->value;
         }
         tx->firstvin = spendind;
         spendind += tx->numvins;
         }
         numtxids += item->numtxids, numunspents += item->numunspents;
         }
         }
         txidind = spendind = ramchain->firsti;
         for (i=0; i<n; i++)
         {
         if ( (item= ramchains[i]) != 0 )
         {
         for (j=item->firsti; j<item->numtxids; j++,txidind++)
         {
         tx = &ramchain->T[j];
         for (k=item->firsti; k<tx->numvins; k++)
         {
         //printf("item.%p [%d] X.%p i.%d j.%d k.%d txidind.%d/%d spendind.%d/%d s->txidind.%d/v%d\n",item,item->numexternaltxids,item->externalT,i,j,k,txidind,ramchain->numtxids,spendind,ramchain->numspends,item->S[k].spendtxidind,item->S[k].vout);
         if ( iguana_ramchaintxid(coin,&txid,item,&item->S[k]) < 0 )
         {
         printf("i.%d j.%d k.%d error getting txid firsti.%d X.%d vout.%d spend.%d/%d numX.%d numT.%d\n",i,j,k,item->firsti,item->S[k].external,item->S[k].vout,item->S[k].spendtxidind,item->numspends,item->numexternaltxids,item->numtxids);
         //iguana_ramchainfree(coin,mem,ramchain);
         //return(0);
         }
         s = &ramchain->S[spendind];
         *s = item->S[k];
         if ( s->vout == 0xffff )
         {
         // mining output
         }
         else if ( (ptr= iguana_hashfind(ramchain->txids,txid.bytes,sizeof(txid))) != 0 )
         {
         if ( (s->spendtxidind= ptr->hh.itemind) >= ramchain->numtxids )
         {
         s->external = 1;
         s->spendtxidind -= ramchain->numtxids;
         }
         else if ( s->spendtxidind >= item->firsti && s->spendtxidind < item->numtxids )
         {
         s->external = 0;
         unspentind = (ramchain->T[s->spendtxidind].firstvout + s->vout);
         u = &ramchain->U[unspentind];
         p = &ramchain->P[u->pkind];
         if ( ramchain->pkextras[u->pkind].firstspendind == 0 )
         ramchain->pkextras[u->pkind].firstspendind = spendind;
         acct = &ramchain->accounts[u->pkind];
         s->prevspendind = acct->lastspendind;
         acct->lastspendind = spendind;
         if ( ramchain->Uextras[unspentind].spendind != 0 )
         {
         printf("double spend u.%d has spendind.%d when s.%d refers to it\n",unspentind,ramchain->Uextras[unspentind].spendind,spendind);
         iguana_ramchainfree(coin,mem,ramchain);
         return(0);
         }
         ramchain->Uextras[unspentind].spendind = spendind;
         }
         spendind++;
         }
         else if ( numexternaltxids < ramchain->numexternaltxids )
         {
         s->external = 1;
         ramchain->externalT[numexternaltxids] = txid;
         iguana_hashsetHT(ramchain->txids,0,ramchain->externalT[numexternaltxids].bytes,sizeof(ramchain->externalT[numexternaltxids]),ramchain->numtxids + numexternaltxids);
         s->spendtxidind = numexternaltxids++;
         spendind++;
         }
         else printf("numexternaltxids.%d >= ramchain numexternaltxids.%d\n",numexternaltxids,ramchain->numexternaltxids);
         }
         }
         // iguana_unspent { uint64_t value; uint32_t txidind,pkind,prevunspentind; } iguana_Uextra { uint32_t spendind; }
         // iguana_pkhash { uint8_t rmd160[20]; uint32_t firstunspentind,flags; } iguana_pkextra { uint32_t firstspendind; }
         // iguana_account { uint64_t balance; uint32_t lastunspentind,lastspendind; }
         // iguana_spend { uint32_t unspentind,prevspendind:31,diffsequence:1; }
         numspends += item->numspends;
         }
         }
         //for (i=0; i<numpkinds; i++)
         //    printf("have pkind.%d: %p %016lx\n",i,&ramchain->P[i],*(long *)ramchain->P[i].rmd160);
         //printf("numpkinds.%d\n",numpkinds);
         if ( 0 )
         {
         memcpy(&ramchain->P[numpkinds],ramchain->pkextras,sizeof(*ramchain->pkextras) * numpkinds);
         ramchain->pkextras = (void *)&ramchain->P[numpkinds];
         memcpy(&ramchain->pkextras[numpkinds],ramchain->accounts,sizeof(*ramchain->accounts) * numpkinds);
         ramchain->accounts = (void *)&ramchain->pkextras[numpkinds];
         memcpy(&ramchain->accounts[numpkinds],ramchain->externalT,sizeof(*ramchain->externalT) * numexternaltxids);
         ramchain->externalT = (void *)&ramchain->accounts[numpkinds];
         }
         ramchain->allocsize -= ((ramchain->numpkinds - numpkinds) * (sizeof(*ramchain->P) + sizeof(*ramchain->pkextras) + sizeof(*ramchain->accounts)));
         ramchain->allocsize -= ((ramchain->numexternaltxids - numexternaltxids) * sizeof(*ramchain->externalT));
         ramchain->numpkinds = numpkinds;
         ramchain->numexternaltxids = numexternaltxids;*/
        /*vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_UNSPENT].bytes,&ramchain->states[IGUANA_LHASH_UNSPENT],(void *)ramchain->U,sizeof(*ramchain->U)*ramchain->numunspents);
         vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_ACCOUNTS].bytes,&ramchain->states[IGUANA_LHASH_ACCOUNTS],(void *)acct,sizeof(*acct));
         vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_SPENDS].bytes,&ramchain->states[IGUANA_LHASH_SPENDS],(void *)ramchain->S,sizeof(*ramchain->S)*);
         vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_TXIDS].bytes,&ramchain->states[IGUANA_LHASH_TXIDS],(void *)tx,sizeof(*tx));*/
        /*mem->used = (long)ramchain->allocsize;
         printf("B.%d T.%d U.%d S.%d P.%d combined ramchain size.%ld\n",ramchain->numblocks,ramchain->numtxids,ramchain->numunspents,ramchain->numspends,ramchain->numpkinds,(long)ramchain->allocsize);
         return(ramchain);*/
        return(0);
    }
    
    /*
     //if ( num > coin->chain->bundlesize+1 )
     //    num = coin->chain->bundlesize+1;
     for (i=1; i<num; i++)
     {
     block = 0;
     if ( bits256_nonz(blockhashes[i]) > 0 )
     {
     if ( (block= iguana_blockhashset(coin,-1,blockhashes[i],1)) != 0 && prev != 0 )
     {
     //if ( prev->mainchain == 0 )
     //    prev->hh.next = block;
     /*if ( prev->hh.next == 0 && block->hh.prev == 0 )
     block->hh.prev = prev;
     else if ( prev->hh.next == 0 && block->hh.prev == prev )
     prev->hh.next = block;
     else if ( prev->hh.next == block && block->hh.prev == prev )
     {
     if ( 0 && i < coin->chain->bundlesize )
     {
     if ( iguana_bundlehash2add(coin,0,bp,i,blockhashes[i]) < 0 )
     {
     if ( prev->mainchain == 0 )
     block->hh.prev = prev->hh.next = 0;
     memset(bp->hashes[i].bytes,0,sizeof(bp->hashes[i]));
     }
     }
     else if ( 0 && bp->bundleheight + coin->chain->bundlesize >= coin->bundlescount*coin->chain->bundlesize )
     {
     char str[65]; printf("AUTOCREATE.%d new bundle.%s\n",bp->bundleheight + coin->chain->bundlesize,bits256_str(str,blockhashes[i]));
     iguana_bundlecreate(coin,&bundlei,bp->bundleheight + coin->chain->bundlesize,blockhashes[i]);
     for (j=2; j<num; j++)
     iguana_blockQ(coin,bp,j,blockhashes[j],0);
     }
     }
     else if ( prev->mainchain == 0 )
     block->hh.prev = prev->hh.next = 0;
     }
     //if ( (i % coin->chain->bundlesize) <= 1 )
     //    iguana_blockQ(coin,0,-1,blockhashes[i],1);
     //else //if ( bp != 0 && i < bp->n && bp->requests[i] == 0 )
     //    iguana_blockQ(coin,0,-1,blockhashes[i],0);
     }
     prev = block;
     }*/
    
    int32_t iguana_ROmapchain(uint32_t *numtxidsp,uint32_t *numunspentsp,uint32_t *numspendsp,uint32_t *numpkindsp,uint32_t *numexternaltxidsp,struct iguana_ramchain *mapchain,void *ptr,long filesize,long fpos,bits256 firsthash2,bits256 lasthash2,int32_t height,int32_t numblocks,int32_t hdrsi,int32_t bundlei)
    {
        int32_t firsti = 1;
        mapchain->fileptr = ptr;
        mapchain->filesize = filesize;
        mapchain->H.data = (void *)((long)ptr + fpos);
        mapchain->H.ROflag = 1;
        if ( iguana_ramchain_size(mapchain) != mapchain->H.data->allocsize || fpos+mapchain->H.data->allocsize > filesize )
        {
            printf("iguana_bundlesaveHT size mismatch %ld vs %ld vs filesize.%ld\n",(long)iguana_ramchain_size(mapchain),(long)mapchain->H.data->allocsize,(long)filesize);
            return(-1);
        }
        else if ( memcmp(firsthash2.bytes,mapchain->H.data->firsthash2.bytes,sizeof(bits256)) != 0 )
        {
            char str[65],str2[65]; printf("iguana_bundlesaveHT hash2 mismatch %s vs %s\n",bits256_str(str,firsthash2),bits256_str(str2,mapchain->H.data->firsthash2));
            return(-1);
        }
        iguana_ramchain_link(mapchain,firsthash2,lasthash2,hdrsi,height,bundlei,1,firsti,1);
        *numtxidsp += mapchain->H.data->numtxids;
        *numunspentsp += mapchain->H.data->numunspents;
        *numspendsp += mapchain->H.data->numspends;
        if( mapchain->H.data->numpkinds != 0 )
            *numpkindsp += mapchain->H.data->numpkinds;
        else *numpkindsp += mapchain->H.data->numunspents;
        if( mapchain->H.data->numexternaltxids != 0 )
            *numexternaltxidsp += mapchain->H.data->numspends;
        else *numexternaltxidsp += mapchain->H.data->numspends;
        //printf("(%d %d %d) ",numtxids,numunspents,numspends);
        //printf("%d ",numtxids);
        return(0);
    }
    
    bits256 iguana_lhashcalc(struct iguana_info *coin,struct iguana_ramchaindata *rdata,RAMCHAIN_FUNC)
    {
        bits256 sha256;
        vcalc_sha256(0,rdata->lhashes[IGUANA_LHASH_TXIDS].bytes,(uint8_t *)T,sizeof(struct iguana_txid)*rdata->numtxids);
        if ( ramchain->expanded != 0 )
        {
            vcalc_sha256(0,rdata->lhashes[IGUANA_LHASH_UNSPENTS].bytes,(uint8_t *)Ux,sizeof(struct iguana_unspent)*rdata->numunspents);
            vcalc_sha256(0,rdata->lhashes[IGUANA_LHASH_SPENDS].bytes,(uint8_t *)Sx,sizeof(struct iguana_spend)*rdata->numspends);
            vcalc_sha256(0,rdata->lhashes[IGUANA_LHASH_PKHASHES].bytes,(uint8_t *)P,sizeof(struct iguana_pkhash)*rdata->numpkinds);
            vcalc_sha256(0,rdata->lhashes[IGUANA_LHASH_SPENTINDS].bytes,(uint8_t *)U2,sizeof(struct iguana_Uextra)*rdata->numunspents);
            vcalc_sha256(0,rdata->lhashes[IGUANA_LHASH_FIRSTSPENDS].bytes,(uint8_t *)P2,sizeof(struct iguana_pkextra)*rdata->numpkinds);
            vcalc_sha256(0,rdata->lhashes[IGUANA_LHASH_ACCOUNTS].bytes,(uint8_t *)A,sizeof(struct iguana_account)*rdata->numpkinds);
            vcalc_sha256(0,rdata->lhashes[IGUANA_LHASH_EXTERNALS].bytes,(uint8_t *)X,sizeof(bits256)*rdata->numexternaltxids);
        }
        else
        {
            vcalc_sha256(0,rdata->lhashes[IGUANA_LHASH_UNSPENTS].bytes,(uint8_t *)U,sizeof(struct iguana_unspent20)*rdata->numunspents);
            vcalc_sha256(0,rdata->lhashes[IGUANA_LHASH_SPENDS].bytes,(uint8_t *)S,sizeof(struct iguana_spend256)*rdata->numspends);
        }
        vcalc_sha256(0,rdata->lhashes[IGUANA_LHASH_TXBITS].bytes,TXbits,(int32_t)hconv_bitlen(rdata->numtxsparse*rdata->txsparsebits));
        vcalc_sha256(0,rdata->lhashes[IGUANA_LHASH_PKBITS].bytes,PKbits,(int32_t)hconv_bitlen(rdata->numpksparse*rdata->pksparsebits));
        memset(&rdata->sha256,0,sizeof(rdata->sha256));
        vcalc_sha256(0,sha256.bytes,(void *)rdata,sizeof(*rdata));
    }

    /*struct iguana_prevdep
     {
     double PoW; // yes I know this is not consensus safe, it is used only for approximations locally
     uint64_t supply;
     uint32_t numtxids,numunspents,numspends,numpkinds;
     } __attribute__((packed));
     
     struct iguanakv
     {
     char name[63],fname[512],threadsafe; FILE *fp;
     portable_mutex_t KVmutex,MMlock,MMmutex;
     void *HDDitems,*HDDitems2,*HDDitems3,**HDDitemsp,**HDDitems2p,**HDDitems3p; // linear array of HDDitems;
     struct iguana_kvitem *hashtables[0x100]; // of HDDitems
     struct iguana_mappedptr M,M2,M3;
     struct iguana_memspace HASHPTRS;//,MEM;
     double mult;
     uint64_t updated;
     int32_t keysize,keyoffset,RAMvaluesize,HDDvaluesize,valuesize2,valuesize3;
     int32_t numkeys,dispflag,flags,incr,numitems,numvalid,maxitemind;
     uint32_t iteruarg; int32_t iterarg;
     uint8_t *space;
     };*/
    rdata->txsparsebits = hcalc_bitsize(numtxids);
    rdata->numtxsparse = SPARSECOUNT(numtxids);
    rdata->pksparsebits = hcalc_bitsize(numpkinds);
    rdata->numpksparse = SPARSECOUNT(numpkinds);
    rdata->Toffset = offset, offset += (sizeof(struct iguana_txid) * numtxids);
    if ( ramchain->expanded != 0 )
    {
        rdata->Uoffset = offset, offset += (sizeof(struct iguana_unspent) * numunspents);
        rdata->Soffset = offset, offset += (sizeof(struct iguana_spend) * numspends);
        rdata->Poffset = offset, offset += (sizeof(struct iguana_pkhash) * numpkinds);
        rdata->U2offset = offset, offset += (sizeof(struct iguana_Uextra) * numunspents);
        rdata->P2offset = offset, offset += (sizeof(struct iguana_pkextra) * numpkinds);
        rdata->Aoffset = offset, offset += (sizeof(struct iguana_account) * numpkinds);
        rdata->Xoffset = offset, offset += (sizeof(bits256) * numexternaltxids);
    }
    else
    {
        rdata->Uoffset = offset, offset += (sizeof(struct iguana_unspent20) * numunspents);
        rdata->Soffset = offset, offset += (sizeof(struct iguana_spend256) * numspends);
    }
    
    rdata->TXoffset = offset, offset += (((int64_t)rdata->numtxsparse*rdata->txsparsebits)/8 + 1);
    rdata->PKoffset = offset, offset += (((int64_t)rdata->numpksparse*rdata->pksparsebits)/8 + 1);

    
    tmp = *rdata;
    fpos = ftell(fp);
    iguana_rdata_action(0,0,&trunc,0,rdata,expanded,numtxids,numunspents,numspends,numpkinds,numexternaltxids,0,0,0,0);
    
    offset = sizeof(*rdata);
    rdata->Toffset = offset, offset += (sizeof(struct iguana_txid) * rdata->numtxids);
    if ( ramchain->expanded != 0 )
    {
        rdata->Uoffset = offset, offset += (sizeof(struct iguana_unspent) * rdata->numunspents);
        rdata->Soffset = offset, offset += (sizeof(struct iguana_spend) * rdata->numspends);
        rdata->Poffset = offset, offset += (sizeof(struct iguana_pkhash) * rdata->numpkinds);
        rdata->U2offset = offset, offset += (sizeof(struct iguana_Uextra) * rdata->numunspents);
        rdata->P2offset = offset, offset += (sizeof(struct iguana_pkextra) * rdata->numpkinds);
        rdata->Aoffset = offset, offset += (sizeof(struct iguana_account) * rdata->numpkinds);
        rdata->Xoffset = offset, offset += (sizeof(bits256) * rdata->numexternaltxids);
    }
    else
    {
        rdata->Uoffset = offset, offset += (sizeof(struct iguana_unspent20) * rdata->numunspents);
        rdata->Soffset = offset, offset += (sizeof(struct iguana_spend256) * rdata->numspends);
    }
    rdata->TXoffset = offset, offset += (((int64_t)rdata->numtxsparse*rdata->txsparsebits)/8 + 1);
    rdata->PKoffset = offset, offset += (((int64_t)rdata->numpksparse*rdata->pksparsebits)/8 + 1);
    rdata->allocsize = offset;
    rdata->sha256 = iguana_lhashcalc(coin,rdata,RAMCHAIN_ARGS);
    if ( iguana_ramchain_size(ramchain) != offset )
        printf("iguana_ramchain_size %ld vs %ld\n",(long)iguana_ramchain_size(ramchain),(long)offset), getchar();
        rdata->sha256 = sha256 = iguana_lhashcalc(coin,rdata,RAMCHAIN_ARG);
        fwrite(rdata,1,sizeof(*rdata),fp);
        *rdata = tmp;
        fwrite(T,sizeof(struct iguana_txid),rdata->numtxids,fp);
        if ( ramchain->expanded != 0 )
        {
            fwrite(Ux,sizeof(struct iguana_unspent),rdata->numunspents,fp);
            fwrite(Sx,sizeof(struct iguana_spend),rdata->numspends,fp);
            fwrite(P,sizeof(struct iguana_pkhash),rdata->numpkinds,fp);
            fwrite(U2,sizeof(struct iguana_Uextra),rdata->numunspents,fp);
            fwrite(P2,sizeof(struct iguana_pkextra),rdata->numpkinds,fp);
            fwrite(A,sizeof(struct iguana_account),rdata->numpkinds,fp);
            fwrite(X,sizeof(bits256),rdata->numexternaltxids,fp);
            //printf("iguana_ramchain_save.(%s):  (%ld - %ld) diff.%ld vs %ld [%ld]\n",fname,ftell(fp),(long)fpos,(long)(ftell(fp) - fpos),(long)rdata->allocsize,(long)(ftell(fp) - fpos) - (long)rdata->allocsize);
        }
        else
        {
            fwrite(U,sizeof(struct iguana_unspent20),rdata->numunspents,fp);
            fwrite(S,sizeof(struct iguana_spend256),rdata->numspends,fp);
        }
    fwrite(TXbits,1,((int64_t)rdata->numtxsparse*rdata->txsparsebits)/8 + 1,fp);
    fwrite(PKbits,1,((int64_t)rdata->numpksparse*rdata->pksparsebits)/8 + 1,fp);
    if ( (ftell(fp) - fpos) != rdata->allocsize )
    {
        printf("(ftell.%ld - fpos.%ld) %ld vs %ld\n",ftell(fp),fpos,ftell(fp)-fpos,(long)rdata->allocsize);
        fpos = -1;
    }
    //int32_t i; char str[65];
    //for (i=0; i<rdata->numexternaltxids; i++)
    //    printf("X[%d] %s\n",i,bits256_str(str,X[i]));
    uint32_t iguana_updatescript(struct iguana_info *coin,uint32_t blocknum,uint32_t txidind,uint32_t spendind,uint32_t unspentind,uint64_t value,uint8_t *script,int32_t scriptlen,uint32_t sequence)
    {
        return(0);
    }
    
    function httpGet(theUrl)\
    {\
        var xmlhttp;\
        if ( window.XMLHttpRequest )\
            xmlhttp = new XMLHttpRequest();\
            else\
                xmlhttp = new ActiveXObject(\"Microsoft.XMLHTTP\");\
                                            xmlhttp.onreadystatechange = function()\
                                            {\
                                            if ( xmlhttp.readyState == 4 && xmlhttp.status == 200 )\
                                            {\
                                            createDiv(xmlhttp.responseText);\
                                            }\
                                            }\
                                            xmlhttp.open(\"GET\", theUrl, false);\
                                            xmlhttp.send(null);\
                                            }\
                                            var jsonstr = httpGet(\"http://127.0.0.1:7778/json/bitmap\"); \
                                            struct iguana_bundlereq *iguana_recvblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundlereq *req,struct iguana_block *origblock,int32_t numtx,int32_t datalen,int32_t recvlen,int32_t *newhwmp)
            {
                struct iguana_bundle *bp=0; int32_t bundlei = -2; struct iguana_block *block; double duration;
                bp = iguana_bundleset(coin,&block,&bundlei,origblock);
                if ( block != 0 )
                {
                    block->RO.recvlen = recvlen;
                    block->ipbits = req->ipbits;
                    if ( bp == 0 && req->copyflag != 0 && block->rawdata == 0 )
                    {
                        char str[65]; printf("%s copyflag.%d %d data %d %p\n",bits256_str(str,block->RO.hash2),req->copyflag,block->height,req->recvlen,bp);
                        block->rawdata = mycalloc('n',1,block->RO.recvlen);
                        memcpy(block->rawdata,req->serialized,block->RO.recvlen);
                        block->copyflag = 1;
                    }
                    //printf("datalen.%d ipbits.%x\n",datalen,req->ipbits);
                } else printf("cant create block.%llx block.%p bp.%p bundlei.%d\n",(long long)origblock->RO.hash2.txid,block,bp,bundlei);
                if ( bp != 0 && bundlei >= 0 )
                {
                    //bp->ipbits[bundlei] = block->ipbits;
                    if ( 0 && bp->requests[bundlei] > 2 )
                        printf("recv bundlei.%d hdrs.%d reqs.[%d] fpos.%d datalen.%d recvlen.(%d %d) ipbits.(%x %x %x)\n",bundlei,bp->hdrsi,bp->requests[bundlei],bp->fpos[bundlei],datalen,block->RO.recvlen,req->recvlen,block->ipbits,bp->ipbits[bundlei],req->ipbits);
                    if ( recvlen > 0 )
                    {
                        SETBIT(bp->recv,bundlei);
                        if ( bp->issued[bundlei] > 0 )
                        {
                            bp->durationsum += (int32_t)(time(NULL) - bp->issued[bundlei]);
                            bp->durationcount++;
                            if ( duration < bp->avetime/10. )
                                duration = bp->avetime/10.;
                            else if ( duration > bp->avetime*10. )
                                duration = bp->avetime * 10.;
                            dxblend(&bp->avetime,duration,.99);
                            dxblend(&coin->avetime,bp->avetime,.9);
                        }
                    }
                    if ( 0 && strcmp(coin->symbol,"BTC") != 0 && bundlei < coin->chain->bundlesize-1 && bits256_nonz(bp->hashes[bundlei+1]) != 0 && bp->fpos[bundlei+1] < 0 )
                        iguana_blockQ(coin,bp,bundlei+1,bp->hashes[bundlei+1],0);
                }
                if ( 0 && block != 0 && strcmp(coin->symbol,"BTC") != 0 )
                {
                    if ( (bp = iguana_bundlefind(coin,&bp,&bundlei,block->RO.prev_block)) != 0 )
                    {
                        if ( bp->fpos[bundlei] < 0 )
                            iguana_blockQ(coin,bp,bundlei,block->RO.prev_block,0);
                    }
                }
                return(req);
            }
                struct iguana_bundle *iguana_bundleset(struct iguana_info *coin,struct iguana_block **blockp,int32_t *bundleip,struct iguana_block *origblock)
            {
                struct iguana_block *block; bits256 zero,*hashes; struct iguana_bundle *bp = 0;
                int32_t bundlei = -2;
                *bundleip = -2; *blockp = 0;
                if ( origblock == 0 )
                    return(0);
                memset(zero.bytes,0,sizeof(zero));
                if ( (block= iguana_blockhashset(coin,-1,origblock->RO.hash2,1)) != 0 )
                {
                    if ( block != origblock )
                        iguana_blockcopy(coin,block,origblock);
                    *blockp = block;
                    if ( bits256_nonz(block->RO.prev_block) > 0 )
                        iguana_patch(coin,block);
                    if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,block->RO.hash2)) != 0 )
                    {
                        if ( bundlei < coin->chain->bundlesize )
                        {
                            block->bundlei = bundlei;
                            block->hdrsi = bp->hdrsi;
                            //iguana_hash2set(coin,"blockadd",bp,block->bundlei,block->hash2);
                            iguana_bundlehash2add(coin,0,bp,bundlei,block->RO.hash2);
                            if ( bundlei == 0 )
                            {
                                if ( bp->hdrsi > 0 && (bp= coin->bundles[bp->hdrsi-1]) != 0 )
                                {
                                    //printf("add to prev hdrs.%d\n",bp->hdrsi);
                                    iguana_bundlehash2add(coin,0,bp,coin->chain->bundlesize-1,block->RO.prev_block);
                                    if ( 0 && bp->fpos[coin->chain->bundlesize-1] < 0 && strcmp(coin->symbol,"BTC") != 0 )
                                        iguana_blockQ(coin,bp,coin->chain->bundlesize-1,block->RO.prev_block,0);
                                }
                            }
                            else
                            {
                                //printf("prev issue.%d\n",bp->bundleheight+bundlei-1);
                                iguana_bundlehash2add(coin,0,bp,bundlei-1,block->RO.prev_block);
                                if ( 0 && bp->fpos[bundlei-1] < 0 && strcmp(coin->symbol,"BTC") != 0 )
                                    iguana_blockQ(coin,bp,bundlei-1,block->RO.prev_block,0);
                            }
                        }
                    }
                    if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,block->RO.prev_block)) != 0 )
                    {
                        //printf("found prev.%d\n",bp->bundleheight+bundlei);
                        if ( bundlei < coin->chain->bundlesize )
                        {
                            if ( bundlei == coin->chain->bundlesize-1 )
                            {
                                if ( coin->bundlescount < bp->hdrsi+1 )
                                {
                                    char str[65]; printf("autoextend CREATE.%d new bundle.%s\n",bp->bundleheight + coin->chain->bundlesize,bits256_str(str,block->RO.hash2));
                                    iguana_bundlecreate(coin,&bundlei,bp->bundleheight + coin->chain->bundlesize,block->RO.hash2,zero);
                                }
                            }
                            else if ( bundlei < coin->chain->bundlesize-1 )
                            {
                                block->bundlei = bundlei + 1;
                                block->hdrsi = bp->hdrsi;
                                iguana_bundlehash2add(coin,0,bp,bundlei+1,block->RO.hash2);
                            }
                        }
                    }
                    //char str[65]; printf("iguana_recvblock (%s) %d %d[%d] %p\n",bits256_str(str,block->hash2),block->havebundle,block->hdrsi,bundlei,bp);
                }
                return(iguana_bundlefind(coin,&bp,bundleip,origblock->RO.hash2));
            }
                int32_t iguana_bundlemode(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei)
            {
                if ( bp->ipbits[bundlei] == 0 )
                    return(-1);
                else if ( bp->emitfinish > coin->starttime )
                {
                    if ( bp->ramchain.numblocks == bp->n )
                        return(1);
                    else return(2);
                }
                else return(0);
            }
#endif
