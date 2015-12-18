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

uint32_t iguana_rwiAddrind(struct iguana_info *coin,int32_t rwflag,struct iguana_iAddr *iA,uint32_t ind)
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

uint32_t iguana_ipbits2ind(struct iguana_info *coin,struct iguana_iAddr *iA,uint32_t ipbits,int32_t createflag)
{
    uint32_t ind = -1; char ipaddr[64];
    expand_ipbits(ipaddr,ipbits);
    //printf("ipbits.%x %s to ind\n",ipbits,ipaddr);
    memset(iA,0,sizeof(*iA));
    if ( iguana_kvread(coin,coin->iAddrs,&ipbits,iA,&ind) == 0 )
    {
        if ( createflag == 0 )
            return(0);
        ind = -1;
        iA->ipbits = ipbits;
        if ( iguana_kvwrite(coin,coin->iAddrs,&ipbits,iA,&ind) == 0 )
        {
            printf("iguana_addr: cant save.(%s)\n",ipaddr);
            return(0);
        }
        else
        {
            iA->ind = ind;
            coin->numiAddrs = ind+1;
            if ( iguana_rwiAddrind(coin,1,iA,ind) == 0 )
                printf("error iAddr.%d: created %x %s\n",ind,ipbits,ipaddr);
        }
    }
    iA->ind = ind;
    return(ind);
}

int32_t iguana_set_iAddrheight(struct iguana_info *coin,uint32_t ipbits,int32_t height)
{
    struct iguana_iAddr iA; uint32_t ind;
    if ( (ind= iguana_ipbits2ind(coin,&iA,ipbits,0)) > 0 )
    {
        if ( (ind= iguana_rwiAddrind(coin,0,&iA,ind)) > 0 && height > iA.height )
        {
            iA.height = height;
            iguana_rwiAddrind(coin,1,&iA,ind);
        }
    }
    return(iA.height);
}

uint32_t iguana_rwipbits_status(struct iguana_info *coin,int32_t rwflag,uint32_t ipbits,int32_t *statusp)
{
    struct iguana_iAddr iA; uint32_t ind;
    if ( (ind= iguana_ipbits2ind(coin,&iA,ipbits,0)) > 0 )
    {
        if ( (ind= iguana_rwiAddrind(coin,0,&iA,ind)) > 0 )
        {
            if ( rwflag == 0 )
                *statusp = iA.status;
            else
            {
                iA.status = *statusp;
                //printf("set status.%d for ind.%d\n",iA.status,ind);
                if ( iguana_rwiAddrind(coin,1,&iA,ind) == 0 )
                {
                    printf("iguana_iAconnected (%x) save error\n",iA.ipbits);
                    return(0);
                }
            }
            return(ind);
        } else printf("iguana_rwiAstatus error getting iA[%d]\n",ind);
    }
    return(0);
}

void iguana_iAconnected(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct iguana_iAddr iA; int32_t ind;
    if ( (ind= iguana_ipbits2ind(coin,&iA,addr->ipbits,1)) > 0 )
    {
        if ( addr->height > iA.height )
            iA.height = addr->height;
        iA.numconnects++;
        iA.lastconnect = (uint32_t)time(NULL);
        if ( iguana_rwiAddrind(coin,1,&iA,ind) == 0 )
            printf("iguana_iAconnected (%s) save error\n",addr->ipaddr);
    } else printf("iguana_iAconnected error getting iA\n");
    //printf("iguana_iAconnected.(%s)\n",addr->ipaddr);
}

void iguana_iAkill(struct iguana_info *coin,struct iguana_peer *addr,int32_t markflag)
{
    struct iguana_iAddr iA; int32_t ind,rank,status = 0; char ipaddr[64];
    if ( addr->ipbits == 0 )
    {
        printf("cant iAkill null ipbits\n");
        return;
    }
    rank = addr->rank;
    strcpy(ipaddr,addr->ipaddr);
    if ( addr->usock >= 0 )
        close(addr->usock);
    if ( addr == coin->peers.localaddr )
        coin->peers.localaddr = 0;
    if ( markflag != 0 )
    {
        //printf("iAkill.(%s)\n",addr->ipaddr);
        if ( (ind= iguana_ipbits2ind(coin,&iA,addr->ipbits,1)) > 0 )
        {
            if ( addr->height > iA.height )
                iA.height = addr->height;
            iA.numkilled++;
            iA.lastkilled = (uint32_t)time(NULL);
            if ( iguana_rwiAddrind(coin,1,&iA,ind) == 0 )
                printf("killconnection (%s) save error\n",addr->ipaddr);
        } else printf("killconnection cant get ind for ipaddr.%s\n",addr->ipaddr);
    }
    else if ( iguana_rwipbits_status(coin,1,addr->ipbits,&status) == 0 )
        printf("error clearing status for %s\n",addr->ipaddr);
    memset(addr,0,sizeof(*addr));
    addr->usock = -1;
    if ( rank > 0 )
        iguana_possible_peer(coin,ipaddr);
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

int32_t pp_bind(char *hostname,uint16_t port)
{
    int32_t opt; struct sockaddr_in addr; socklen_t addrlen = sizeof(addr);
    struct hostent* hostent = gethostbyname(hostname);
    if (hostent == NULL) {
        PostMessage("gethostbyname() returned error: %d", errno);
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr.s_addr, hostent->h_addr_list[0], hostent->h_length);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("socket() failed: %s", strerror(errno));
        return -1;
    }
    opt = 1;
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(void*)&opt,sizeof(opt));
#ifdef __APPLE__
    setsockopt(sock,SOL_SOCKET,SO_NOSIGPIPE,&opt,sizeof(opt));
#endif
    //timeout.tv_sec = 0;
    //timeout.tv_usec = 1000;
    //setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout));
    int result = bind(sock, (struct sockaddr*)&addr, addrlen);
    if (result != 0) {
        printf("bind() failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return(sock);
}

int32_t pp_connect(char *hostname,uint16_t port)
{
    int32_t opt; struct sockaddr_in addr; socklen_t addrlen = sizeof(addr);
    struct hostent* hostent = gethostbyname(hostname);
    if (hostent == NULL) {
        printf("gethostbyname() returned error: %d", errno);
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr.s_addr, hostent->h_addr_list[0], hostent->h_length);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("socket() failed: %s", strerror(errno));
        return -1;
    }
    opt = 1;
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(void*)&opt,sizeof(opt));
#ifdef __APPLE__
    setsockopt(sock,SOL_SOCKET,SO_NOSIGPIPE,&opt,sizeof(opt));
#endif
    int result = connect(sock, (struct sockaddr*)&addr, addrlen);
    if (result != 0) {
        printf("connect() failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    //send(sock, "hello", 6, 0);
    return(sock);
}

int32_t iguana_send(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *serialized,int32_t len)
{
    int32_t numsent,remains,usock;
    if ( addr == 0 )
        return(-1);
    usock = addr->usock;
    if ( usock < 0 || addr->dead != 0 )
        return(-1);
    remains = len;
    //printf(" send.(%s) %d bytes to %s\n",(char *)&serialized[4],len,addr->ipaddr);// getchar();
    if ( strcmp((char *)&serialized[4],"ping") == 0 )
        addr->sendmillis = milliseconds();
    if ( len > IGUANA_MAXPACKETSIZE )
        printf("sending too big! %d\n",len);
    while ( remains > 0 )
    {
        if ( coin->peers.shuttingdown != 0 )
            return(-1);
        if ( (numsent= (int32_t)send(usock,serialized,remains,MSG_NOSIGNAL)) < 0 )
        {
            if ( errno != EAGAIN && errno != EWOULDBLOCK )
            {
                printf("%s: %s numsent.%d vs remains.%d len.%d errno.%d (%s) usock.%d\n",serialized+4,addr->ipaddr,numsent,remains,len,errno,strerror(errno),addr->usock);
                printf("bad errno.%d %s zombify.%p\n",errno,strerror(errno),&addr->dead);
                addr->dead = (uint32_t)time(NULL);
                return(-errno);
            } //else usleep(*sleeptimep), *sleeptimep *= 1.1;
        }
        else if ( remains > 0 )
        {
            remains -= numsent;
            serialized += numsent;
            if ( remains > 0 )
                printf("iguana sent.%d remains.%d of len.%d\n",numsent,remains,len);
        }
    }
    addr->totalsent += len;
    //printf(" sent.%d bytes to %s\n",len,addr->ipaddr);// getchar();
    return(len);
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
    memcpy(packet->serialized,serialized,datalen);
    //printf("%p queue send.(%s) %d to (%s) %x\n",packet,serialized+4,datalen,addr->ipaddr,addr->ipbits);
    queue_enqueue("sendQ",&addr->sendQ,&packet->DL,0);
    return(datalen);
}

int32_t iguana_recv(int32_t usock,uint8_t *recvbuf,int32_t len)
{
    int32_t recvlen,remains = len;
    while ( remains > 0 )
    {
        if ( (recvlen= (int32_t)recv(usock,recvbuf,remains,0)) < 0 )
        {
            if ( errno == EAGAIN )
            {
#ifdef IGUANA_DEDICATED_THREADS
                //printf("EAGAIN for len %d, remains.%d\n",len,remains);
#endif
                usleep(10000);
            }
            else return(-errno);
        }
        else
        {
            if ( recvlen > 0 )
            {
                remains -= recvlen;
                recvbuf = &recvbuf[recvlen];
            } else usleep(10000);
            //if ( remains > 0 )
                //printf("got %d remains.%d of total.%d\n",recvlen,remains,len);
        }
    }
    return(len);
}

void _iguana_processmsg(struct iguana_info *coin,int32_t usock,struct iguana_peer *addr,uint8_t *_buf,int32_t maxlen)
{
    int32_t len,recvlen; void *buf = _buf; struct iguana_msghdr H,checkH;
    if ( coin->peers.shuttingdown != 0 || addr->dead != 0 )
        return;
    //printf("%p got.(%s) from %s | usock.%d ready.%u dead.%u\n",addr,H.command,addr->ipaddr,addr->usock,addr->ready,addr->dead);
    memset(&H,0,sizeof(H));
    if ( (recvlen= (int32_t)iguana_recv(usock,(uint8_t *)&H,sizeof(H))) == sizeof(H) )
    {
        //printf("%p got.(%s) recvlen.%d from %s | usock.%d ready.%u dead.%u\n",addr,H.command,recvlen,addr->ipaddr,addr->usock,addr->ready,addr->dead);
        if ( coin->peers.shuttingdown != 0 || addr->dead != 0 )
            return;
        if ( (len= iguana_validatehdr(coin,&H)) >= 0 )
        {
            if ( len > 0 )
            {
                if ( len > IGUANA_MAXPACKETSIZE )
                {
                    printf("buffer %d too small for %d\n",IGUANA_MAXPACKETSIZE,len);
                    return;
                }
                if ( len > maxlen )
                    buf = mycalloc('p',1,len);
                if ( (recvlen= iguana_recv(usock,buf,len)) < 0 )
                {
                    printf("recv error on (%s) len.%d errno.%d (%s)\n",H.command,len,-recvlen,strerror(-recvlen));
                    if ( buf != _buf )
                        myfree(buf,len);
                    addr->dead = (uint32_t)time(NULL);
                    return;
                }
            }
            memset(&checkH,0,sizeof(checkH));
            iguana_sethdr(&checkH,coin->chain->netmagic,H.command,buf,len);
            if ( memcmp(&checkH,&H,sizeof(checkH)) == 0 )
            {
                //if ( strcmp(addr->ipaddr,"127.0.0.1") == 0 )
                //printf("%s parse.(%s) len.%d\n",addr->ipaddr,H.command,len);
                //printf("addr->dead.%u\n",addr->dead);
                if ( strcmp(H.command,"block") == 0 || strcmp(H.command,"tx") == 0 )
                {
                    //printf("Init %s memory %p %p %p\n",addr->ipaddr,addr->RAWMEM.ptr,addr->TXDATA.ptr,addr->HASHMEM.ptr);
                    if ( addr->RAWMEM.ptr == 0 )
                        iguana_meminit(&addr->RAWMEM,addr->ipaddr,0,IGUANA_MAXPACKETSIZE,0);
                    if ( addr->TXDATA.ptr == 0 )
                        iguana_meminit(&addr->TXDATA,"txdata",0,IGUANA_MAXPACKETSIZE,0);
                    if ( addr->HASHMEM.ptr == 0 )
                        iguana_meminit(&addr->HASHMEM,"HASHPTRS",0,IGUANA_MAXPACKETSIZE*13,0);
                }
                if ( iguana_parser(coin,addr,&addr->RAWMEM,&addr->TXDATA,&addr->HASHMEM,&H,buf,len) < 0 || addr->dead != 0 )
                {
                    printf("%p addr->dead.%d or parser break at %u\n",&addr->dead,addr->dead,(uint32_t)time(NULL));
                    addr->dead = (uint32_t)time(NULL);
                }
                else
                {
                    addr->numpackets++;
                    addr->totalrecv += len;
                    coin->totalrecv += len, coin->totalpackets++;
                    //printf("next iter.(%s) numreferrals.%d numpings.%d\n",addr->ipaddr,addr->numreferrals,addr->numpings);
                }
            } else printf("header error from %s\n",addr->ipaddr);
            if ( buf != _buf )
                myfree(buf,len);
            return;
        }
        printf("invalid header received from (%s)\n",addr->ipaddr);
    }
    printf("%s recv error on hdr errno.%d (%s)\n",addr->ipaddr,-recvlen,strerror(-recvlen));
#ifndef IGUANA_DEDICATED_THREADS
    addr->dead = 1;
#endif
}

void iguana_startconnection(void *arg)
{
    void iguana_dedicatedloop(struct iguana_info *coin,struct iguana_peer *addr);
    int32_t status,i,n; char ipaddr[64]; struct iguana_peer *addr = arg; struct iguana_info *coin = 0;
    if ( addr == 0 || (coin= iguana_coin(addr->symbol)) == 0 )
    {
        printf("iguana_startconnection nullptrs addr.%p coin.%p\n",addr,coin);
        return;
    }
    printf("startconnection.(%s)\n",addr->ipaddr);
    if ( strcmp(coin->name,addr->coinstr) != 0 )
    {
        printf("iguana_startconnection.%s mismatched coin.%p (%s) vs (%s)\n",addr->ipaddr,coin,coin->symbol,addr->coinstr);
        return;
    }
    addr->usock = pp_connect(addr->ipaddr,coin->chain->portp2p);
    //addr->usock = iguana_connect(coin,addrs,sizeof(addrs)/sizeof(*addrs),addr->ipaddr,coin->chain->portp2p,2);
    if ( addr->usock < 0 || coin->peers.shuttingdown != 0 )
    {
        status = IGUANA_PEER_KILLED;
        strcpy(ipaddr,addr->ipaddr);
        printf("refused PEER STATUS.%d for %s usock.%d\n",status,addr->ipaddr,addr->usock);
        iguana_iAkill(coin,addr,1);
        if ( iguana_rwipbits_status(coin,1,addr->ipbits,&status) == 0 )
            printf("error updating status.%d for %s\n",status,ipaddr);
        addr->pending = 0;
        addr->ipbits = 0;
        addr->dead = 1;
    }
    else
    {
        addr->ready = (uint32_t)time(NULL);
        addr->ipbits = (uint32_t)calc_ipbits(addr->ipaddr);
        addr->dead = 0;
        addr->pending = 0;
        addr->height = iguana_set_iAddrheight(coin,addr->ipbits,0);
        strcpy(addr->symbol,coin->symbol);
        strcpy(addr->coinstr,coin->name);
        coin->peers.lastpeer = (uint32_t)time(NULL);
        status = IGUANA_PEER_READY;
        for (i=n=0; i<coin->MAXPEERS; i++)
            if ( coin->peers.active[i].usock > 0 )
                n++;
        printf("CONNECTED.%d of max.%d! PEER STATUS.%d for %s usock.%d\n",n,coin->MAXPEERS,status,addr->ipaddr,addr->usock);
        iguana_iAconnected(coin,addr);
        coin->peers.numconnected++;
        if ( iguana_rwipbits_status(coin,1,addr->ipbits,&status) == 0 )
            printf("error updating status.%d for %s\n",status,addr->ipaddr);
        if ( strcmp("127.0.0.1",addr->ipaddr) == 0 )
            coin->peers.localaddr = addr;
#ifdef IGUANA_DEDICATED_THREADS
        //iguana_launch("recv",iguana_dedicatedrecv,addr,IGUANA_RECVTHREAD);
        iguana_dedicatedloop(coin,addr);
#endif
    }
    //printf("%s ready.%u dead.%d numthreads.%d\n",addr->ipaddr,addr->ready,addr->dead,coin->numthreads);
    //queue_enqueue("retryQ",&coin->peers.retryQ,&addr->DL);
}

void *iguana_kvconnectiterator(struct iguana_info *coin,struct iguanakv *kv,struct iguana_kvitem *item,uint64_t args,void *key,void *value,int32_t valuesize)
{
    struct iguana_iAddr *iA = value; char ipaddr[64]; int32_t i; struct iguana_peer *addr = 0;
    if ( iA != 0 && iA->ipbits != 0 && iguana_numthreads(coin,1 << IGUANA_CONNTHREAD) < IGUANA_MAXCONNTHREADS )//&& iA->status != IGUANA_PEER_READY && iA->status != IGUANA_PEER_CONNECTING )
    {
        //printf("%x\n",iA->ipbits);
        expand_ipbits(ipaddr,iA->ipbits);
        //portable_mutex_lock(&coin->peers_mutex);
        for (i=0; i<coin->MAXPEERS; i++)
        {
            addr = &coin->peers.active[i];
            if ( addr->usock >= 0 || addr->pending != 0 || addr->ipbits == iA->ipbits || strcmp(ipaddr,addr->ipaddr) == 0 )
            {
                printf("skip.(%s) usock.%d pending.%d ipbits.%x vs %x\n",addr->ipaddr,addr->usock,addr->pending,addr->ipbits,iA->ipbits);
                //portable_mutex_unlock(&coin->peers_mutex);
                return(0);
            }
            if ( addr->ipbits == 0 )
            {
                iguana_initpeer(coin,addr,iA->ipbits);
                break;
            }
        }
        //portable_mutex_unlock(&coin->peers_mutex);
        if ( addr != 0 )
        {
            printf("status.%d addr.%p possible peer.(%s) (%s).%x %u threads %d %d %d %d\n",iA->status,addr,ipaddr,addr->ipaddr,addr->ipbits,addr->pending,iguana_numthreads(coin,0),iguana_numthreads(coin,1),iguana_numthreads(coin,2),iguana_numthreads(coin,3));
            iA->status = IGUANA_PEER_CONNECTING;
            if ( iguana_rwiAddrind(coin,1,iA,item->hh.itemind) > 0 )
            {
                //printf("iguana_startconnection.(%s) status.%d\n",ipaddr,IGUANA_PEER_CONNECTING);
                iguana_launch(coin,"connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
            }
        } else printf("no open peer slots left\n");
    }
    else if ( iA != 0 )
        printf("iA->ipbits %d, %d iguana_numthreads(coin,1 << IGUANA_CONNTHREAD)\n",iA->ipbits,iguana_numthreads(coin,1 << IGUANA_CONNTHREAD));
    else printf("connector null iA\n");
    return(0);
}
 
uint32_t iguana_possible_peer(struct iguana_info *coin,char *ipaddr)
{
    char checkaddr[64]; uint32_t ipbits,ind,now = (uint32_t)time(NULL); int32_t i;
    struct iguana_iAddr iA; struct iguana_kvitem item;
    if ( ipaddr != 0 )
    {
        printf("%p Q possible peer.(%s)\n",coin,ipaddr);
        queue_enqueue("possibleQ",&coin->possibleQ,queueitem(ipaddr),1);
        return((uint32_t)time(NULL));
    }
    else if ( (ipaddr= queue_dequeue(&coin->possibleQ,1)) == 0 )
        return((uint32_t)time(NULL));
#ifdef IGUANA_DISABLEPEERS
    if ( strcmp(ipaddr,"127.0.0.1") != 0 )
    {
        free_queueitem(ipaddr);
        return((uint32_t)time(NULL));
    }
#endif
    printf("check possible peer.(%s)\n",ipaddr);
    for (i=0; i<coin->MAXPEERS; i++)
        if ( strcmp(ipaddr,coin->peers.active[i].ipaddr) == 0 )
        {
            printf("(%s) already active\n",ipaddr);
            free_queueitem(ipaddr);
            return((uint32_t)time(NULL));
        }
    if ( strncmp("0.0.0",ipaddr,5) != 0 && strcmp("0.0.255.255",ipaddr) != 0 && strcmp("1.0.0.0",ipaddr) != 0 )
    {
        if ( (ipbits= (uint32_t)calc_ipbits(ipaddr)) != 0 )
        {
            expand_ipbits(checkaddr,ipbits);
            if ( strcmp(checkaddr,ipaddr) == 0 )
            {
                if ( (ind= iguana_ipbits2ind(coin,&iA,ipbits,1)) > 0 && iA.status != IGUANA_PEER_CONNECTING && iA.status != IGUANA_PEER_READY )
                {
                    printf("valid ipaddr.(%s) MAXPEERS.%d\n",ipaddr,coin->MAXPEERS);
                    if ( (iA.lastconnect == 0 || iA.lastkilled == 0) || (iA.numconnects > 0 && iA.lastconnect > (now - IGUANA_RECENTPEER)) || iA.lastkilled < now-600 )
                    {
                        iA.status = IGUANA_PEER_ELIGIBLE;
                        if ( iguana_rwiAddrind(coin,1,&iA,ind) == 0 )
                            printf("error updating status for (%s)\n",ipaddr);
                        if ( coin->peers.numconnected < coin->MAXPEERS )
                        {
                            memset(&item,0,sizeof(item));
                            item.hh.itemind = ind;
                            iguana_kvconnectiterator(coin,coin->iAddrs,&item,0,&iA.ipbits,&iA,sizeof(iA));
                        } else printf("numconnected.%d >= MAXPEERS.%d\n",coin->peers.numconnected,coin->MAXPEERS);
                    } else printf("ignore.(%s) lastconnect.%u lastkilled.%u numconnects.%d\n",ipaddr,iA.lastconnect,iA.lastkilled,iA.numconnects);
                } else printf("skip.(%s) ind.%d status.%d\n",ipaddr,ind,iA.status);
            } else printf("reject ipaddr.(%s)\n",ipaddr);
        }
    }
    free_queueitem(ipaddr);
    return((uint32_t)time(NULL));
}

void iguana_processmsg(void *ptr)
{
    struct iguana_info *coin; uint8_t buf[32768]; struct iguana_peer *addr = ptr;
    if ( addr == 0 || (coin= iguana_coin(addr->symbol)) == 0 || addr->dead != 0 )
    {
        printf("iguana_processmsg cant find addr.%p symbol.%s\n",addr,addr!=0?addr->symbol:0);
        return;
    }
    _iguana_processmsg(coin,addr->usock,addr,buf,sizeof(buf));
    addr->startrecv = 0;
}

int32_t iguana_pollsendQ(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct iguana_packet *packet;
    if ( (packet= queue_dequeue(&addr->sendQ,0)) != 0 )
    {
        //printf("%s: send.(%s) usock.%d dead.%u ready.%u\n",addr->ipaddr,packet->serialized+4,addr->usock,addr->dead,addr->ready);
        if ( strcmp((char *)&packet->serialized[4],"getdata") == 0 )
        {
            printf("unexpected getdata for %s\n",addr->ipaddr);
            myfree(packet,sizeof(*packet) + packet->datalen);
        }
        else
        {
//#ifdef IGUANA_DEDICATED_THREADS
            iguana_send(coin,addr,packet->serialized,packet->datalen);
            //if ( packet->getdatablock > 0 )
            //    iguana_setwaitstart(coin,packet->getdatablock);
            myfree(packet,sizeof(*packet) + packet->datalen);
/*#else
            addr->startsend = (uint32_t)time(NULL);
            strcpy(addr->symbol,coin->symbol);
            strcpy(addr->coinstr,coin->name);
            iguana_launch("send_data",iguana_issue,packet,IGUANA_SENDTHREAD);
#endif*/
            return(1);
        }
    }
    return(0);
}

int32_t iguana_pollrecv(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *buf,int32_t bufsize)
{
#ifndef IGUANA_DEDICATED_THREADS
    strcpy(addr->symbol,coin->symbol);
    if ( addr != coin->peers.localaddr )
    {
        addr->startrecv = (uint32_t)time(NULL);
        iguana_launch("processmsg",iguana_processmsg,addr,IGUANA_RECVTHREAD);
    }
    else
#endif
        _iguana_processmsg(coin,addr->usock,addr,buf,bufsize);
    return(1);
}

void iguana_acceptloop(void *args)
{
    socklen_t clilen; struct sockaddr_in cli_addr; struct iguana_peer *addr; struct iguana_info *coin = args;
    addr = &coin->bindaddr;
    memset(addr,0,sizeof(*addr));
    iguana_initpeer(coin,addr,(uint32_t)calc_ipbits("127.0.0.1"));
    addr->usock = pp_bind("127.0.0.1",coin->chain->portp2p);
    printf("iguana_bindloop 127.0.0.1 bind sock.%d\n",addr->usock);
    memset(coin->fds,0,sizeof(coin->fds));
    while ( 1 )
    {
        printf("LISTEN on sock.%d\n",addr->usock);
        listen(addr->usock,64);
        clilen = sizeof(cli_addr);
        printf("ACCEPT on sock.%d\n",addr->usock);
        coin->fds[coin->numsocks].fd = accept(addr->usock,(struct sockaddr *)&cli_addr,&clilen);
        printf("NEWSOCK.%d\n",coin->fds[coin->numsocks].fd);
        if ( coin->fds[coin->numsocks].fd < 0 )
        {
            printf("ERROR on accept\n");
            continue;
        }
        coin->numsocks++;
    }
}

void iguana_recvloop(void *arg)
{
    int32_t i; uint8_t buf[32768]; struct iguana_info *coin = arg;
    while ( 1 )
    {
        if ( coin->numsocks == 0 )
        {
            sleep(1);
            continue;
        }
        for (i=0; i<coin->numsocks; i++)
            coin->fds[i].revents = POLLIN, coin->fds[i].events = 0;
        if ( poll(coin->fds,coin->numsocks,10000) > 0 )
        {
            for (i=0; i<coin->numsocks; i++)
            {
                if ( (coin->fds[i].events & POLLIN) != 0 )
                {
                    printf("process message from [%d]\n",i);
                    _iguana_processmsg(coin,coin->fds[i].fd,&coin->bindaddr,buf,sizeof(buf));
                    printf("iguana_bindloop processed.(%s)\n",buf+4);
                }
            }
        } else printf("numsocks.%d nothing to receive\n",coin->numsocks);
    }
}

#ifdef IGUANA_PEERALLOC
void *iguana_peeralloc(struct iguana_info *coin,struct iguana_peer *addr,int32_t datalen)
{
    struct iguana_memspace *mem; long i,iter; int32_t j,diff,size,bestfit; void *ptr;
    //printf("iguana_peeralloc.%s\n",addr->ipaddr);
    while ( 1 )
    {
        bestfit = -1;
        for (iter=0; iter<3; iter++)
        {
            for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
            {
                mem = addr->SEROUT[i];
                if ( mem->threadsafe != 0 )
                    portable_mutex_lock(&mem->mutex);
                if ( iter < 2 && mem->availptrs > 0 )
                {
                    for (j=0; j<mem->numptrs; j++)
                    {
                        if ( mem->allocsizes[j] == 0 )
                        {
                            size = mem->maxsizes[j];
                            if ( size >= datalen )
                            {
                                diff = (size - datalen);
                                if ( diff == 0 || (iter == 1 && diff == bestfit) )
                                {
                                    mem->allocsizes[j] = datalen;
                                    mem->availptrs--;
                                    //printf("%s availptrs.%d size.%d j.%d diff.%d bestfit.%d %p.%d max.%d\n",mem->name,mem->availptrs,size,j,diff,bestfit,mem->ptrs[j],size,mem->maxsizes[j]);
                                    if ( mem->threadsafe != 0 )
                                        portable_mutex_unlock(&mem->mutex);
                                    return(mem->ptrs[j]);
                                }
                                else if ( iter == 0 && diff < (datalen >> 3) && diff < 4096 )
                                    bestfit = diff;
                            }
                        }
                    }
                }
                else if ( iter == 2 && (ptr= iguana_memalloc(mem,datalen,0)) != 0 )
                {
                    if ( mem->threadsafe != 0 )
                        portable_mutex_unlock(&mem->mutex);
                    ///printf("alloc iter.2\n");
                    return(ptr);
                }
                if ( mem->threadsafe != 0 )
                    portable_mutex_unlock(&mem->mutex);
                //printf("iter.%ld bestfit.%d\n",iter,bestfit);
            }
        }
        printf("iguana_peeralloc: cant find memory. wait and hope...\n");
        sleep(5);
    }
    return(0);
}

int64_t iguana_peerallocated(struct iguana_info *coin,struct iguana_peer *addr)
{
    int32_t i; int64_t total = 0;
    for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
        if ( addr->SEROUT[i] != 0 )
            total += iguana_memallocated(addr->SEROUT[i]);
    return(total);
}

int64_t iguana_peerfree(struct iguana_info *coin,struct iguana_peer *addr,void *ptr,int32_t datalen)
{
    struct iguana_memspace *mem; long offset,i; int64_t avail = -1;
    //printf("iguana_peerfree.%p %d\n",ptr,datalen);
    for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
    {
        mem = addr->SEROUT[i];
        offset = ((long)ptr - (long)mem->ptr);
        if ( offset >= 0 && offset+datalen < mem->totalsize )
        {
            if ( iguana_memfree(mem,ptr,datalen) < 0 || (avail= iguana_peerallocated(coin,addr)) < 0 )
            {
                printf("iguana_peerfree: corrupted mem avail.%lld ptr.%p %d\n",(long long)avail,ptr,datalen);
                getchar();
            }
            return(avail);
        }
    }
    printf("iguana_peerfree: cant find ptr.%p %d\n",ptr,datalen);
    return(-1);
}
#else
void *iguana_peeralloc(struct iguana_info *coin,struct iguana_peer *addr,int32_t datalen)
{
    addr->allocated += datalen;
    return(calloc(1,datalen));
}

int64_t iguana_peerfree(struct iguana_info *coin,struct iguana_peer *addr,void *ptr,int32_t datalen)
{
    addr->freed += datalen;
    free(ptr);
    return(1);
}

int64_t iguana_peerallocated(struct iguana_info *coin,struct iguana_peer *addr)
{
    return(addr->allocated - addr->freed);
}
#endif

void iguana_dedicatedloop(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct pollfd fds; uint8_t *buf,serialized[64];
    int32_t bufsize,flag,timeout = coin->MAXPEERS/64+1;
#ifdef IGUANA_PEERALLOC
    int32_t i;  int64_t remaining; struct iguana_memspace *mem[sizeof(addr->SEROUT)/sizeof(*addr->SEROUT)];
    for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
    {
        mem[i] = mycalloc('s',1,sizeof(*mem[i]));
        addr->SEROUT[i] = mem[i];
        mem[i]->totalsize = IGUANA_MAXPACKETSIZE;
        mem[i]->ptr = mycalloc('P',1,mem[i]->totalsize);
        mem[i]->used = 0;
        strcpy(mem[i]->name,addr->ipaddr);
        //mem[i]->threadsafe = 1;
        iguana_memreset(mem[i]);
    }
#endif
    addr->addrind = (int32_t)(((long)addr - (long)&coin->peers.active[0]) / sizeof(*addr));
    printf("start dedicatedloop.%s addrind.%d\n",addr->ipaddr,addr->addrind);
    //sprintf(fname,"tmp/%s/peer%d.%d",coin->symbol,addr->addrind,addr->filecount++);
    //addr->fp = fopen(fname,"wb");
    addr->maxfilehash2 = IGUANA_MAXFILEITEMS;
    bufsize = IGUANA_MAXPACKETSIZE;
    buf = mycalloc('r',1,bufsize);
    //printf("send version myservices.%llu\n",(long long)coin->myservices);
    iguana_send_version(coin,addr,coin->myservices);
    iguana_queue_send(coin,addr,serialized,"getaddr",0,0,0);
    //printf("after send version\n");
    while ( addr->usock >= 0 && addr->dead == 0 && coin->peers.shuttingdown == 0 )
    {
        flag = 0;
        memset(&fds,0,sizeof(fds));
        fds.fd = addr->usock;
        fds.events |= POLLOUT;
        if (  poll(&fds,1,timeout) > 0 )
            flag += iguana_pollsendQ(coin,addr);
        if ( flag == 0 )
        {
            memset(&fds,0,sizeof(fds));
            fds.fd = addr->usock;
            fds.events |= POLLIN;
            if ( poll(&fds,1,timeout) > 0 )
                flag += iguana_pollrecv(coin,addr,buf,bufsize);
            if ( flag == 0 )
            {
                if ( time(NULL) > addr->pendtime+30 )
                {
                    if ( addr->pendblocks > 0 )
                        addr->pendblocks--;
                    if ( addr->pendhdrs > 0 )
                        addr->pendhdrs--;
                    addr->pendtime = 0;
                }
                memset(&fds,0,sizeof(fds));
                fds.fd = addr->usock;
                fds.events |= POLLOUT;
                if ( poll(&fds,1,timeout) > 0 )
                    flag += iguana_pollQs(coin,addr);
            }
            if ( flag == 0 )//&& iguana_processjsonQ(coin) == 0 )
                usleep(10000);//+ 100000*(coin->blocks.hwmheight > (long)coin->longestchain-coin->minconfirms*2));
        }
    }
    if ( addr->fp != 0 )
        fflush(addr->fp);
    iguana_iAkill(coin,addr,addr->dead != 0);
    printf("finish dedicatedloop.%s\n",addr->ipaddr);
    myfree(buf,bufsize);
    if ( addr->filehash2 != 0 )
        myfree(addr->filehash2,addr->maxfilehash2*sizeof(*addr->filehash2));
    iguana_mempurge(&addr->RAWMEM);
    iguana_mempurge(&addr->TXDATA);
    iguana_mempurge(&addr->HASHMEM);
#ifdef IGUANA_PEERALLOC
    while ( (remaining= iguana_peerallocated(coin,addr)) > 0 )
    {
        char str[65];
        printf("waiting for helperQ to flush peer mem %s\n",mbstr(str,remaining));
        sleep(5);
    }
    for (i=0; i<sizeof(addr->SEROUT)/sizeof(*addr->SEROUT); i++)
    {
        if ( addr->SEROUT[i] != 0 )
        {
            if ( addr->SEROUT[i]->ptr != 0 )
                myfree(addr->SEROUT[i]->ptr,IGUANA_MAXPACKETSIZE);
            myfree(addr->SEROUT[i],sizeof(*addr->SEROUT[i]));
        }
    }
#endif
    coin->peers.numconnected--;
}

void iguana_peersloop(void *ptr)
{
#ifndef IGUANA_DEDICATED_THREADS
    struct pollfd fds[IGUANA_MAXPEERS]; struct iguana_info *coin = ptr;
    struct iguana_peer *addr; uint8_t *bufs[IGUANA_MAXPEERS];
    int32_t i,j,n,r,nonz,flag,bufsizes[IGUANA_MAXPEERS],timeout=1;
    memset(fds,0,sizeof(fds));
    memset(bufs,0,sizeof(bufs));
    memset(bufsizes,0,sizeof(bufsizes));
    while ( 1 )
    {
        while ( coin->peers.shuttingdown != 0 )
        {
            printf("peers shuttingdown\n");
            sleep(3);
        }
        flag = 0;
        r = (rand() % coin->MAXPEERS);
        for (j=n=nonz=0; j<coin->MAXPEERS; j++)
        {
            i = (j + r) % coin->MAXPEERS;
            addr = &coin->peers.active[i];
            fds[i].fd = -1;
            if ( addr->usock >= 0 && addr->dead == 0 && addr->ready != 0 && (addr->startrecv+addr->startsend) != 0 )
            {
                fds[i].fd = addr->usock;
                fds[i].events = (addr->startrecv != 0) * POLLIN |  (addr->startsend != 0) * POLLOUT;
                nonz++;
            }
        }
        if ( nonz != 0 && poll(fds,coin->MAXPEERS,timeout) > 0 )
        {
            for (j=0; j<coin->MAXPEERS; j++)
            {
                i = (j + r) % coin->MAXPEERS;
                addr = &coin->peers.active[i];
                if ( addr->usock < 0 || addr->dead != 0 || addr->ready == 0 )
                    continue;
                if ( addr->startrecv == 0 && (fds[i].revents & POLLIN) != 0 && iguana_numthreads(1 << IGUANA_RECVTHREAD) < IGUANA_MAXRECVTHREADS )
                {
                    if ( bufs[i] == 0 )
                        bufsizes[i] = IGUANA_MAXPACKETSIZE, bufs[i] = mycalloc('r',1,bufsizes[i]);
                    flag += iguana_pollrecv(coin,addr,bufs[i],bufsizes[i]);
                }
                if ( addr->startsend == 0 && (fds[i].revents & POLLOUT) != 0 && iguana_numthreads(1 << IGUANA_SENDTHREAD) < IGUANA_MAXSENDTHREADS )
                {
                    if ( iguana_pollsendQ(coin,addr) == 0 )
                        flag += iguana_poll(coin,addr);
                    else flag++;
                }
            }
        }
        if ( flag == 0 )
            usleep(1000);
    }
#endif
}
