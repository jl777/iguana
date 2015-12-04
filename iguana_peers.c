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
        for (i=0; i<IGUANA_MAXPEERS; i++)
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

static int _decreasing_double(const void *a,const void *b)
{
#define double_a (*(double *)a)
#define double_b (*(double *)b)
	if ( double_b > double_a )
		return(1);
	else if ( double_b < double_a )
		return(-1);
	return(0);
#undef double_a
#undef double_b
}

static int32_t revsortds(double *buf,uint32_t num,int32_t size)
{
	qsort(buf,num,size,_decreasing_double);
	return(0);
}

double iguana_metric(struct iguana_peer *addr,uint32_t now,double decay)
{
    int32_t duration; double metric = addr->recvblocks * addr->recvtotal;
    addr->recvblocks *= decay;
    addr->recvtotal *= decay;
    if ( now >= addr->ready && addr->ready != 0 )
        duration = (now - addr->ready + 1);
    else duration = 1;
    if ( metric < SMALLVAL && duration > 300 )
        metric = 0.001;
    else metric /= duration;
    return(metric);
}

int32_t iguana_peermetrics(struct iguana_info *coin)
{
    int32_t i,ind,n; double *sortbuf,sum; uint32_t now; struct iguana_peer *addr,*slowest = 0;
    //printf("peermetrics\n");
    sortbuf = mycalloc('M',IGUANA_MAXPEERS,sizeof(double)*2);
    coin->peers.mostreceived = 0;
    now = (uint32_t)time(NULL);
    for (i=n=0; i<IGUANA_MAXPEERS; i++)
    {
        addr = &coin->peers.active[i];
        if ( addr->usock < 0 || addr->dead != 0 || addr->ready == 0 )
            continue;
        if ( addr->recvblocks > coin->peers.mostreceived )
            coin->peers.mostreceived = addr->recvblocks;
        //printf("[%.0f %.0f] ",addr->recvblocks,addr->recvtotal);
        sortbuf[n*2 + 0] = iguana_metric(addr,now,1.);
        sortbuf[n*2 + 1] = i;
        n++;
    }
    if ( n > 0 )
    {
        revsortds(sortbuf,n,sizeof(double)*2);
        portable_mutex_lock(&coin->peers.rankedmutex);
        for (sum=i=0; i<n; i++)
        {
            if ( i < IGUANA_MAXPEERS )
            {
                coin->peers.topmetrics[i] = sortbuf[i*2];
                ind = (int32_t)sortbuf[i*2 +1];
                coin->peers.ranked[i] = &coin->peers.active[ind];
                if ( sortbuf[i*2] > SMALLVAL && (double)i/n > .8 )
                    slowest = coin->peers.ranked[i];
                //printf("(%.5f %s) ",sortbuf[i*2],coin->peers.ranked[i]->ipaddr);
                coin->peers.ranked[i]->rank = i + 1;
                sum += coin->peers.topmetrics[i];
            }
        }
        coin->peers.numranked = n;
        portable_mutex_unlock(&coin->peers.rankedmutex);
        //printf("NUMRANKED.%d\n",n);
        if ( i > 0 )
        {
            coin->peers.avemetric = (sum / i);
            if ( i >= IGUANA_MAXPEERS-3 && slowest != 0 )
            {
                printf("prune slowest peer.(%s) numranked.%d\n",slowest->ipaddr,n);
                slowest->dead = 1;
            }
        }
    }
    myfree(sortbuf,IGUANA_MAXPEERS * sizeof(double)*2);
    return(coin->peers.mostreceived);
}

int32_t iguana_connectsocket(int32_t blockflag,struct iguana_peer *A,struct sockaddr *addr,socklen_t addr_len)
{
    int32_t flags,val = 65536*2; struct timeval timeout;
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
        setsockopt(A->usock,SOL_SOCKET,SO_SNDBUF,&val,sizeof(val));
        setsockopt(A->usock,SOL_SOCKET,SO_RCVBUF,&val,sizeof(val));
        timeout.tv_sec = 0;
        timeout.tv_usec = 1000;
        setsockopt(A->usock,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout));
        setsockopt(A->usock,SOL_SOCKET,SO_SNDTIMEO,(char *)&timeout,sizeof(timeout));
        //opt = 1;
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

int32_t iguana_send(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *serialized,int32_t len,int32_t *sleeptimep)
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
        if ( *sleeptimep < 10 )
            *sleeptimep = 10;
        else if ( *sleeptimep > 1000000 )
            *sleeptimep = 1000000;
        if ( coin->peers.shuttingdown != 0 )
            return(-1);
        if ( (numsent= (int32_t)send(usock,serialized,remains,MSG_NOSIGNAL)) < 0 )
        {
            if ( errno != EAGAIN && errno != EWOULDBLOCK )
            {
                printf("%s: sleeptime.%d %s numsent.%d vs remains.%d len.%d errno.%d (%s) usock.%d\n",serialized+4,*sleeptimep,addr->ipaddr,numsent,remains,len,errno,strerror(errno),addr->usock);
                printf("bad errno.%d %s zombify.%p\n",errno,strerror(errno),&addr->dead);
                addr->dead = (uint32_t)time(NULL);
                return(-errno);
            } //else usleep(*sleeptimep), *sleeptimep *= 1.1;
        }
        else if ( remains > 0 )
        {
            *sleeptimep *= .9;
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
        return(iguana_send(coin,addr,serialized,datalen,&addr->sleeptime));
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

void _iguana_processmsg(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *_buf,int32_t maxlen)
{
    int32_t len,recvlen,usock = addr->usock; void *buf = _buf;
    struct iguana_msghdr H,checkH;
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
                if ( iguana_parser(coin,addr,&H,buf,len) < 0 || addr->dead != 0 )
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
    struct iguana_peer addrs[8],*addr = arg; struct iguana_info *coin = 0;
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
    addr->usock = iguana_connect(coin,addrs,sizeof(addrs)/sizeof(*addrs),addr->ipaddr,coin->chain->default_port,2);
    if ( addr->usock < 0 || coin->peers.shuttingdown != 0 )
    {
        addr->pending = 0;
        addr->ipbits = 0;
        addr->dead = 1;
    }
    else
    {
        addr->ready = (uint32_t)time(NULL);
        addr->dead = 0;
        addr->pending = 0;
        addr->height = iguana_set_iAddrheight(coin,addr->ipbits,0);
        strcpy(addr->symbol,coin->symbol);
        strcpy(addr->coinstr,coin->name);
        coin->peers.lastpeer = (uint32_t)time(NULL);
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
    if ( iA->ipbits != 0 && iguana_numthreads(1 << IGUANA_CONNTHREAD) < IGUANA_MAXCONNTHREADS && iA->status != IGUANA_PEER_READY && iA->status != IGUANA_PEER_CONNECTING )
    {
        //printf("%x\n",iA->ipbits);
        expand_ipbits(ipaddr,iA->ipbits);
        portable_mutex_lock(&coin->peers.rankedmutex);
        for (i=0; i<sizeof(coin->peers.active)/sizeof(*coin->peers.active); i++)
        {
            addr = &coin->peers.active[i];
            if ( addr->pending != 0 || addr->ipbits == iA->ipbits || strcmp(ipaddr,addr->ipaddr) == 0 )
            {
                portable_mutex_unlock(&coin->peers.rankedmutex);
                return(0);
            }
            if ( addr->ipbits == 0 )
            {
                iguana_initpeer(coin,addr,iA->ipbits);
                break;
            }
        }
        portable_mutex_unlock(&coin->peers.rankedmutex);
        if ( addr != 0 )
        {
            printf("status.%d addr.%p possible peer.(%s) (%s).%x %u threads %d %d %d %d\n",iA->status,addr,ipaddr,addr->ipaddr,addr->ipbits,addr->pending,iguana_numthreads(0),iguana_numthreads(1),iguana_numthreads(2),iguana_numthreads(3));
            iA->status = IGUANA_PEER_CONNECTING;
            if ( iguana_rwiAddrind(coin,1,iA,item->hh.itemind) > 0 )
            {
                //printf("iguana_startconnection.(%s) status.%d\n",ipaddr,IGUANA_PEER_CONNECTING);
                iguana_launch("connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
            }
        } else printf("no open peer slots left\n");
    }
    return(0);
}
 
int32_t iguana_possible_peer(struct iguana_info *coin,char *ipaddr)
{
    char checkaddr[64]; uint32_t ipbits,ind,now = (uint32_t)time(NULL); int32_t i;
    struct iguana_iAddr iA; struct iguana_kvitem item;
    if ( ipaddr != 0 )
    {
        queue_enqueue("possibleQ",&coin->possibleQ,queueitem(ipaddr),1);
        return(0);
    }
    else if ( (ipaddr= queue_dequeue(&coin->possibleQ,1)) == 0 )
        return(0);
#ifdef IGUANA_DISABLEPEERS
    if ( strcmp(ipaddr,"127.0.0.1") != 0 )
    {
        free_queueitem(ipaddr);
        return(0);
    }
#endif
    //printf("possible peer.(%s)\n",ipaddr);
    for (i=0; i<IGUANA_MAXPEERS; i++)
        if ( strcmp(ipaddr,coin->peers.active[i].ipaddr) == 0 )
        {
            free_queueitem(ipaddr);
            return(0);
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
                    if ( (iA.lastconnect == 0 || iA.lastkilled == 0) || (iA.numconnects > 0 && iA.lastconnect > (now - IGUANA_RECENTPEER)) || iA.lastkilled < now-600 )
                    {
                        iA.status = IGUANA_PEER_ELIGIBLE;
                        if ( iguana_rwiAddrind(coin,1,&iA,ind) == 0 )
                            printf("error updating status for (%s)\n",ipaddr);
                        else if ( coin->peers.numranked < IGUANA_MAXPEERS-IGUANA_MAXPEERS/8 )
                        {
                            memset(&item,0,sizeof(item));
                            item.hh.itemind = ind;
                            iguana_kvconnectiterator(coin,coin->iAddrs,&item,0,&iA.ipbits,&iA,sizeof(iA));
                        }
                    }
                }
            } else printf("reject ipaddr.(%s)\n",ipaddr);
        }
    }
    free_queueitem(ipaddr);
    return(-1);
}

void iguana_processmsg(void *ptr)
{
    struct iguana_info *coin; uint8_t buf[32768]; struct iguana_peer *addr = ptr;
    if ( addr == 0 || (coin= iguana_coin(addr->symbol)) == 0 || addr->dead != 0 )
    {
        printf("iguana_processmsg cant find addr.%p symbol.%s\n",addr,addr!=0?addr->symbol:0);
        return;
    }
    _iguana_processmsg(coin,addr,buf,sizeof(buf));
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
            iguana_send(coin,addr,packet->serialized,packet->datalen,&addr->sleeptime);
            if ( packet->getdatablock > 0 )
                iguana_setwaitstart(coin,packet->getdatablock);
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
        _iguana_processmsg(coin,addr,buf,bufsize);
    return(1);
}

int32_t iguana_poll(struct iguana_info *coin,struct iguana_peer *addr)
{
    uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(uint32_t)*32 + sizeof(bits256)];
    char *hashstr = 0; bits256 hash2; int32_t threshold,height,datalen,flag = 0;
    if ( iguana_needhdrs(coin) != 0 && addr->pendhdrs == 0 && (hashstr= queue_dequeue(&coin->R.hdrsQ,1)) != 0 )
    {
        if ( (datalen= iguana_gethdrs(coin,serialized,strcmp(coin->name,"bitcoin") != 0 ? "getblocks" : "getheaders",hashstr)) > 0 )
        {
            iguana_send(coin,addr,serialized,datalen,&addr->sleeptime);
            addr->pendhdrs++;
            flag++;
        }
        free_queueitem(hashstr);
        hashstr = 0;
    }
    else //if ( iguana_needhdrs(coin) == 0 )
    {
        if ( (hashstr= queue_dequeue(&coin->priorityQ,1)) != 0 )
        {
            threshold = coin->blocks.parsedblocks + IGUANA_HDRSCOUNT;
            //decode_hex(hash2.bytes,sizeof(hash2),hashstr);
            //height = iguana_height(coin,hash2);
            //printf("dequeued priorityQ.(%s) height.%d width %d/%d\n",hashstr,height,coin->widthready,coin->width);
        }
        else if ( (hashstr= queue_dequeue(&coin->blocksQ,1)) != 0 )
        {
            threshold = coin->blocks.parsedblocks + 100*IGUANA_HDRSCOUNT;
            //decode_hex(hash2.bytes,sizeof(hash2),hashstr);
            //height = iguana_height(coin,hash2);
            //printf("ht.%d dequeued.(%s) for %s\n",height,hashstr,addr->ipaddr);
        }
        else threshold = 0;
    }
    if ( hashstr != 0 )
    {
        decode_hex(hash2.bytes,sizeof(hash2),hashstr);
        height = iguana_height(coin,hash2);
        if ( height < coin->blocks.parsedblocks )
        {
            //if ( height > coin->firstblock )
            //printf("discard %d when parsed.%d\n",height,coin->blocks.parsedblocks);
            free_queueitem(hashstr);
        }
        else if ( height > threshold )
        {
            queue_enqueue("resubmit",&coin->blocksQ,(void *)((long)hashstr - sizeof(struct queueitem)),0);
        }
        else
        {
            if ( (datalen= iguana_getdata(coin,serialized,MSG_BLOCK,hashstr)) > 0 )
                iguana_send(coin,addr,serialized,datalen,&addr->sleeptime), addr->pendblocks++, flag++;
            free_queueitem(hashstr);
        }
    }
    return(flag);
}

void iguana_dedicatedloop(struct iguana_info *coin,struct iguana_peer *addr)
{
    struct pollfd fds; uint8_t *buf; int32_t bufsize,flag,timeout = IGUANA_MAXPEERS/64 + 1;
    printf("start dedicatedloop.%s\n",addr->ipaddr);
    bufsize = IGUANA_MAXPACKETSIZE;
    buf = mycalloc('r',1,bufsize);
    //printf("send version\n");
    iguana_send_version(coin,addr,coin->myservices);
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
            if ( flag == 0 && addr->pendblocks < IGUANA_MAXPENDING )
            {
                memset(&fds,0,sizeof(fds));
                fds.fd = addr->usock;
                fds.events |= POLLOUT;
                if ( poll(&fds,1,timeout) > 0 )
                    flag += iguana_poll(coin,addr);
            }
            if ( flag == 0 )
                usleep(1000 + 100000*(coin->blocks.hwmheight > (long)coin->longestchain-1000));
        }
    }
    myfree(buf,bufsize);
    iguana_iAkill(coin,addr,addr->dead != 0);
    printf("finish dedicatedloop.%s\n",addr->ipaddr);
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
        r = (rand() % IGUANA_MAXPEERS);
        for (j=n=nonz=0; j<sizeof(coin->peers.active)/sizeof(*coin->peers.active); j++)
        {
            i = (j + r) % IGUANA_MAXPEERS;
            addr = &coin->peers.active[i];
            fds[i].fd = -1;
            if ( addr->usock >= 0 && addr->dead == 0 && addr->ready != 0 && (addr->startrecv+addr->startsend) != 0 )
            {
                fds[i].fd = addr->usock;
                fds[i].events = (addr->startrecv != 0) * POLLIN |  (addr->startsend != 0) * POLLOUT;
                nonz++;
            }
        }
        if ( nonz != 0 && poll(fds,sizeof(coin->peers.active)/sizeof(*coin->peers.active),timeout) > 0 )
        {
            for (j=0; j<sizeof(coin->peers.active)/sizeof(*coin->peers.active); j++)
            {
                i = (j + r) % IGUANA_MAXPEERS;
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
