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
//static const bits256 bits256_zero;

void iguana_recvalloc(struct iguana_info *coin,int32_t numitems)
{
    //coin->emitbits = myrealloc('W',coin->emitbits,coin->emitbits==0?0:coin->blocks.maxbits/coin->chain->bundlesize+1,numitems/coin->chain->bundlesize+1);
    //coin->bundleready = myrealloc('W',coin->bundleready,coin->bundleready==0?0:coin->blocks.maxbits/coin->chain->bundlesize+1,numitems/coin->chain->bundlesize+1);
    //coin->havehash = myrealloc('W',coin->havehash,coin->havehash==0?0:coin->blocks.maxbits/8+1,numitems/8+1);
    coin->blocks.ptrs = myrealloc('W',coin->blocks.ptrs,coin->blocks.ptrs==0?0:coin->blocks.maxbits * sizeof(*coin->blocks.ptrs),numitems * sizeof(*coin->blocks.ptrs));
    printf("realloc waitingbits.%d -> %d\n",coin->blocks.maxbits,numitems);
    coin->blocks.maxbits = numitems;
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
    sortbuf = mycalloc('s',coin->MAXPEERS,sizeof(double)*2);
    coin->peers.mostreceived = 0;
    now = (uint32_t)time(NULL);
    for (i=n=0; i<coin->MAXPEERS; i++)
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
        portable_mutex_lock(&coin->peers_mutex);
        for (sum=i=0; i<n; i++)
        {
            if ( i < coin->MAXPEERS )
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
        portable_mutex_unlock(&coin->peers_mutex);
        //printf("NUMRANKED.%d\n",n);
        if ( i > 0 )
        {
            coin->peers.avemetric = (sum / i);
            if ( i >= (coin->MAXPEERS - 1) && slowest != 0 )
            {
                printf("prune slowest peer.(%s) numranked.%d\n",slowest->ipaddr,n);
                slowest->dead = 1;
            }
        }
    }
    myfree(sortbuf,coin->MAXPEERS * sizeof(double) * 2);
    return(coin->peers.mostreceived);
}

void *iguana_kviAddriterator(struct iguana_info *coin,struct iguanakv *kv,struct iguana_kvitem *item,uint64_t args,void *key,void *value,int32_t valuesize)
{
    char ipaddr[64]; int32_t i; FILE *fp = (FILE *)args; struct iguana_peer *addr; struct iguana_iAddr *iA = value;
    if ( fp != 0 && iA != 0 && iA->numconnects > 0 && iA->lastconnect > time(NULL)-IGUANA_RECENTPEER )
    {
        for (i=0; i<coin->peers.numranked; i++)
            if ( (addr= coin->peers.ranked[i]) != 0 && addr->ipbits == iA->ipbits )
                break;
        if ( i == coin->peers.numranked )
        {
            expand_ipbits(ipaddr,iA->ipbits);
            fprintf(fp,"%s\n",ipaddr);
        }
    }
    return(0);
}

uint32_t iguana_updatemetrics(struct iguana_info *coin)
{
    char fname[512],tmpfname[512],oldfname[512]; int32_t i; struct iguana_peer *addr; FILE *fp;
    iguana_peermetrics(coin);
    sprintf(fname,"%s_peers.txt",coin->symbol);
    sprintf(oldfname,"%s_oldpeers.txt",coin->symbol);
    sprintf(tmpfname,"tmp/%s/peers.txt",coin->symbol);
    if ( (fp= fopen(tmpfname,"w")) != 0 )
    {
        for (i=0; i<coin->peers.numranked; i++)
            if ( (addr= coin->peers.ranked[i]) != 0 )
                fprintf(fp,"%s\n",addr->ipaddr);
        if ( ftell(fp) > iguana_filesize(fname) )
        {
            printf("new peers.txt %ld vs (%s) %ld\n",ftell(fp),fname,(long)iguana_filesize(fname));
            fclose(fp);
            iguana_renamefile(fname,oldfname);
            iguana_copyfile(tmpfname,fname,1);
        } else fclose(fp);
    }
    return((uint32_t)time(NULL));
}

int32_t iguana_needhdrs(struct iguana_info *coin)
{
    if ( coin->longestchain == 0 || coin->blocks.hashblocks < coin->longestchain-coin->chain->bundlesize )
        return(1);
    else return(0);
}

int32_t iguana_reqhdrs(struct iguana_info *coin)
{
    int32_t i,n = 0; struct iguana_bundle *bp; char hashstr[65];
    if ( iguana_needhdrs(coin) > 0 && queue_size(&coin->hdrsQ) == 0 )
    {
        if ( coin->zcount++ > 10 )
        {
            for (i=0; i<coin->bundlescount; i++)
            {
                if ( (bp= coin->bundles[i]) != 0 )
                {
                    if ( bp->numhashes < bp->n && bp->ramchain.bundleheight+bp->numhashes < coin->longestchain && time(NULL) > bp->issuetime+30 )//&& coin->numpendings < coin->MAXBUNDLES )
                    {
                        printf("hdrsi.%d numhashes.%d:%d needhdrs.%d qsize.%d zcount.%d\n",i,bp->numhashes,bp->n,iguana_needhdrs(coin),queue_size(&coin->hdrsQ),coin->zcount);
                        if ( bp->issuetime == 0 )
                            coin->numpendings++;
                        char str[65];
                        bits256_str(str,bp->hashes[0]);
                        printf("(%s %d).%d ",str,bp->ramchain.bundleheight,i);
                        init_hexbytes_noT(hashstr,bp->hashes[0].bytes,sizeof(bits256));
                        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
                        n++;
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

int32_t iguana_processrecv(struct iguana_info *coin) // single threaded
{
    int32_t newhwm = 0,h,lflag,flag = 0; struct iguana_block *next,*block;
    //printf("process bundlesQ\n");
    flag += iguana_processbundlesQ(coin,&newhwm);
    flag += iguana_reqhdrs(coin);
    lflag = 1;
    while ( lflag != 0 )
    {
        lflag = 0;
        h = coin->blocks.hwmchain.height / coin->chain->bundlesize;
        if ( (next= iguana_blockfind(coin,iguana_blockhash(coin,coin->blocks.hwmchain.height+1))) == 0 )
        {
            if ( (block= iguana_blockfind(coin,coin->blocks.hwmchain.hash2)) != 0 )
                next = block->hh.next, block->mainchain = 1;
        }
        if ( next != 0 )
        {
            //printf("have next\n");
            if ( memcmp(next->prev_block.bytes,coin->blocks.hwmchain.hash2.bytes,sizeof(bits256)) == 0 )
            {
                if ( _iguana_chainlink(coin,next) != 0 )
                    lflag++;
                else printf("chainlink error for %d\n",coin->blocks.hwmchain.height+1);
            }
            else if ( 0 )
            {
                double lag = milliseconds() - coin->backstopmillis;
                if ( (coin->backstop != coin->blocks.hwmchain.height+1 || lag > 3*coin->avetime) && next->recvlen == 0 )
                {
                    coin->backstop = coin->blocks.hwmchain.height+1;
                    coin->backstopmillis = milliseconds();
                    iguana_blockQ(coin,0,coin->blocks.hwmchain.height+1,next->hash2,1);
                    // clear recvlens
                    //if ( ((coin->blocks.hwmchain.height+1) % 100) == 0 )
                        printf("BACKSTOP.%d avetime %.3f %.3f lag %.3f\n",coin->blocks.hwmchain.height+1,coin->avetime,coin->backstopmillis,lag);
                 }
                else if ( bits256_nonz(next->prev_block) > 0 )
                    printf("next prev cmp error nonz.%d\n",bits256_nonz(next->prev_block));
            }
        }
        if ( h != coin->blocks.hwmchain.height / coin->chain->bundlesize )
            iguana_savehdrs(coin);
    }
    return(flag);
}

void iguana_coinloop(void *arg)
{
    struct iguana_info *coin,**coins = arg;
    struct iguana_bundle *bp; int32_t flag,i,n,bundlei; bits256 zero; char str[1024];
    uint32_t now,lastdisp = 0;
    n = (int32_t)(long)coins[0];
    coins++;
    printf("begin coinloop[%d]\n",n);
    for (i=0; i<n; i++)
    {
        if ( (coin= coins[i]) != 0 && coin->started == 0 )
        {
            iguana_startcoin(coin,coin->initialheight,coin->mapflags);
            coin->started = coin;
            coin->chain->minconfirms = coin->minconfirms;
        }
    }
    coin = coins[0];
    iguana_rwiAddrind(coin,0,0,0);
    iguana_possible_peer(coin,"127.0.0.1");
    memset(zero.bytes,0,sizeof(zero));
    if ( (bp= iguana_bundlecreate(coin,&bundlei,0,*(bits256 *)coin->chain->genesis_hashdata)) != 0 )
        bp->ramchain.bundleheight = 0;
    while ( 1 )
    {
        flag = 0;
        for (i=0; i<n; i++)
        {
            if ( (coin= coins[i]) != 0 )
            {
                now = (uint32_t)time(NULL);
                if ( now > coin->lastpossible )
                    coin->lastpossible = iguana_possible_peer(coin,0); // tries to connect to new peers
                if ( coin->active != 0 )
                {
                    if ( now > coin->peers.lastmetrics+6 )
                        coin->peers.lastmetrics = iguana_updatemetrics(coin); // ranks peers
                    flag += iguana_processrecv(coin);
                    if ( 0 && coin->blocks.parsedblocks < coin->blocks.hwmchain.height-coin->chain->minconfirms )
                    {
                        if ( iguana_updateramchain(coin) != 0 )
                            iguana_syncs(coin), flag++; // merge ramchain fragments into full ramchain
                    }
                    if ( now > lastdisp )
                    {
                        lastdisp = (uint32_t)now;
                        //for (j=m=0; j<coin->longestchain; j++)
                        //    if ( GETBIT(coin->havehash,j) != 0 )
                        //        m++;
                        iguana_bundlestats(coin,str);
                        printf("%s.%-2d %s time %.2f files.%d Q.%d %d\n",coin->symbol,flag,str,(double)(time(NULL)-coin->starttime)/60.,coin->peers.numfiles,queue_size(&coin->priorityQ),queue_size(&coin->blocksQ));
                        if ( (rand() % 100) == 0 )
                            myallocated(0,0);
                    }
                }
            }// bp block needs mutex
        }
        if ( flag == 0 )
        {
            //printf("IDLE\n");
            usleep(1000);
        }
    }
}

void iguana_coinargs(char *symbol,int64_t *maxrecvcachep,int32_t *minconfirmsp,int32_t *maxpeersp,int32_t *initialheightp,uint64_t *servicesp,int32_t *maxpendingp,int32_t *maxbundlesp,cJSON *json)
{
    if ( (*maxrecvcachep= j64bits(json,"maxrecvcache")) != 0 )
        *maxrecvcachep *= 1024 * 1024 * 1024L;
    *minconfirmsp = juint(json,"minconfirms");
    *maxpeersp = juint(json,"maxpeers");
    *maxpendingp = juint(json,"maxpending");
    *maxbundlesp = juint(json,"maxbundles");
    if ( (*initialheightp= juint(json,"initialheight")) == 0 )
        *initialheightp = (strcmp(symbol,"BTC") == 0) ? 400000 : 100000;
    *servicesp = j64bits(json,"services");
}

struct iguana_info *iguana_setcoin(char *symbol,void *launched,int32_t maxpeers,int64_t maxrecvcache,uint64_t services,int32_t initialheight,int32_t maphash,int32_t minconfirms,int32_t maxpending,int32_t maxbundles,cJSON *json)
{
    struct iguana_chain *iguana_createchain(cJSON *json);
    struct iguana_info *coin; int32_t j,m,mapflags; char dirname[512]; cJSON *peers;
    mapflags = IGUANA_MAPRECVDATA | maphash*IGUANA_MAPTXIDITEMS | maphash*IGUANA_MAPPKITEMS | maphash*IGUANA_MAPBLOCKITEMS | maphash*IGUANA_MAPPEERITEMS;
    coin = iguana_coin(symbol);
    coin->launched = launched;
    if ( (coin->MAXPEERS= maxpeers) <= 0 )
        coin->MAXPEERS = (strcmp(symbol,"BTC") == 0) ? 128 : 32;
    if ( (coin->MAXRECVCACHE= maxrecvcache) == 0 )
        coin->MAXRECVCACHE = IGUANA_MAXRECVCACHE;
    if ( (coin->MAXPENDING= maxpending) <= 0 )
        coin->MAXPENDING = _IGUANA_MAXPENDING;//(strcmp(symbol,"BTC") == 0) ? _IGUANA_MAXPENDING : _IGUANA_MAXPENDING*128;
    if ( (coin->MAXBUNDLES= maxbundles) <= 0 )
        coin->MAXBUNDLES = (strcmp(symbol,"BTC") == 0) ? _IGUANA_MAXBUNDLES : _IGUANA_MAXBUNDLES*64;
    coin->myservices = services;
    sprintf(dirname,"DB/%s",symbol);
    ensure_directory(dirname);
    sprintf(dirname,"tmp/%s",symbol);
    ensure_directory(dirname);
    coin->initialheight = initialheight;
    coin->mapflags = mapflags;
    coin->active = juint(json,"active");
    if ( (coin->minconfirms = minconfirms) == 0 )
        coin->minconfirms = (strcmp(symbol,"BTC") == 0) ? 3 : 10;
    if ( coin->chain == 0 && (coin->chain= iguana_createchain(json)) == 0 )
    {
        printf("cant initialize chain.(%s)\n",jstr(json,0));
        return(0);
    }
    if ( (peers= jarray(&m,json,"peers")) != 0 )
    {
        for (j=0; j<m; j++)
        {
            printf("%s ",jstr(jitem(peers,j),0));
            iguana_possible_peer(coin,jstr(jitem(peers,j),0));
        }
        printf("addnodes.%d\n",m);
    }
    return(coin);
}

int32_t iguana_launchcoin(char *symbol,cJSON *json)
{
    int32_t maxpeers,maphash,initialheight,minconfirms,maxpending,maxbundles;
    int64_t maxrecvcache; uint64_t services; struct iguana_info **coins,*coin;
    if ( symbol == 0 )
        return(-1);
    if ( (coin= iguana_coin(symbol)) == 0 )
        return(-1);
    if ( coin->launched == 0 )
    {
        if ( juint(json,"GBavail") < 8 )
            maphash = IGUANA_MAPHASHTABLES;
        else maphash = 0;
        iguana_coinargs(symbol,&maxrecvcache,&minconfirms,&maxpeers,&initialheight,&services,&maxpending,&maxbundles,json);
        coins = mycalloc('A',1+1,sizeof(*coins));
        if ( (coin= iguana_setcoin(coin->symbol,coins,maxpeers,maxrecvcache,services,initialheight,maphash,minconfirms,maxpending,maxbundles,json)) != 0 )
        {
            coins[0] = (void *)((long)1);
            coins[1] = coin;
            printf("launch coinloop for.%s\n",coin->symbol);
            iguana_launch(coin,"iguana_coinloop",iguana_coinloop,coins,IGUANA_PERMTHREAD);
            return(1);
        }
        else
        {
            myfree(coins,sizeof(*coins) * 2);
            return(-1);
        }
    }
    return(0);
}

void iguana_coins(void *arg)
{
    struct iguana_info **coins,*coin; char *jsonstr,*symbol; cJSON *array,*item,*json;
    int32_t i,n,maxpeers,maphash,initialheight,minconfirms,maxpending,maxbundles;
    int64_t maxrecvcache; uint64_t services;
    if ( (jsonstr= arg) != 0 && (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (array= jarray(&n,json,"coins")) == 0 )
        {
            if ( (symbol= jstr(json,"coin")) != 0 && strncmp(symbol,"BTC",3) == 0 )
            {
                coins = mycalloc('A',1+1,sizeof(*coins));
                coins[1] = iguana_setcoin(symbol,coins,0,0,0,0,0,0,0,0,json);
                coins[0] = (void *)((long)1);
                iguana_coinloop(coins);
            } else printf("no coins[] array in JSON.(%s) only BTCD and BTC can be quicklaunched\n",jsonstr);
            free_json(json);
            return;
        }
        coins = mycalloc('A',n+1,sizeof(*coins));
        if ( juint(json,"GBavail") < 8 )
            maphash = IGUANA_MAPHASHTABLES;
        else maphash = 0;
        printf("MAPHASH.%d\n",maphash);
        for (i=0; i<n; i++)
        {
            item = jitem(array,i);
            if ( (symbol= jstr(item,"name")) == 0 || strlen(symbol) > 8 )
            {
                printf("skip strange coin.(%s)\n",symbol);
                continue;
            }
            iguana_coinargs(symbol,&maxrecvcache,&minconfirms,&maxpeers,&initialheight,&services,&maxpending,&maxbundles,item);
            char str[65];
            printf("init.(%s) maxpeers.%d maxrecvcache.%s maphash.%x services.%llx\n",symbol,maxpeers,mbstr(str,maxrecvcache),maphash,(long long)services);
            coins[1 + i] = coin = iguana_setcoin(symbol,coins,maxpeers,maxrecvcache,services,initialheight,maphash,minconfirms,maxpending,maxbundles,item);
            printf("MAXRECVCACHE.%s\n",mbstr(str,coin->MAXRECVCACHE));
        }
        coins[0] = (void *)((long)n);
        iguana_coinloop(coins);
    }
}
