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

int32_t iguana_needhdrs(struct iguana_info *coin)
{
    if ( coin->longestchain == 0 || coin->blocks.hashblocks < coin->longestchain-coin->chain->bundlesize )
        return(1);
    else return(0);
}

void iguana_recvalloc(struct iguana_info *coin,int32_t numitems)
{
    coin->emitbits = myrealloc('W',coin->emitbits,coin->emitbits==0?0:coin->blocks.maxbits/coin->chain->bundlesize+1,numitems/coin->chain->bundlesize+1);
    coin->bundleready = myrealloc('W',coin->bundleready,coin->bundleready==0?0:coin->blocks.maxbits/coin->chain->bundlesize+1,numitems/coin->chain->bundlesize+1);
    coin->blocks.ptrs = myrealloc('W',coin->blocks.ptrs,coin->blocks.ptrs==0?0:coin->blocks.maxbits * sizeof(*coin->blocks.ptrs),numitems * sizeof(*coin->blocks.ptrs));
    printf("realloc waitingbits.%d -> %d\n",coin->blocks.maxbits,numitems);
    coin->blocks.maxbits = numitems;
}

int32_t iguana_savehdrs(struct iguana_info *coin)
{
    int32_t height,iter,valid,retval = 0; char fname[512],tmpfname[512],oldfname[512]; bits256 hash2; FILE *fp;
    sprintf(oldfname,"%s_oldhdrs.txt",coin->symbol);
    sprintf(tmpfname,"tmp/%s/hdrs.txt",coin->symbol);
    sprintf(fname,"%s_hdrs.txt",coin->symbol);
    if ( (fp= fopen(tmpfname,"w")) != 0 )
    {
        fprintf(fp,"%d\n",coin->blocks.hashblocks);
        for (height=0; height<=coin->blocks.hashblocks; height+=coin->chain->bundlesize)
        {
            for (iter=0; iter<2; iter++)
            {
                hash2 = iguana_blockhash(coin,&valid,height+iter);
                if ( bits256_nonz(hash2) > 0 )
                {
                    fprintf(fp,"%d %s\n",height+iter,bits256_str(hash2));
                    retval = height+iter;
                }
                if ( coin->chain->hasheaders != 0 )
                    break;
            }
        }
        //printf("new hdrs.txt %ld vs (%s) %ld\n",ftell(fp),fname,(long)iguana_filesize(fname));
        if ( ftell(fp) > iguana_filesize(fname) )
        {
            printf("new hdrs.txt %ld vs (%s) %ld\n",ftell(fp),fname,(long)iguana_filesize(fname));
            fclose(fp);
            iguana_renamefile(fname,oldfname);
            iguana_copyfile(tmpfname,fname,1);
        } else fclose(fp);
    }
    return(retval);
}

void iguana_parseline(struct iguana_info *coin,int32_t iter,FILE *fp)
{
    int32_t j,k,m,c,height; bits256 hash2; char checkstr[1024],line[1024]; struct iguana_peer *addr;
    m = 0;
    while ( fgets(line,sizeof(line),fp) > 0 )
    {
        j = (int32_t)strlen(line) - 1;
        line[j] = 0;
        //printf("parse line.(%s) maxpeers.%d\n",line,coin->MAXPEERS);
        if ( iter == 0 )
        {
            if ( m < coin->MAXPEERS )
            {
                addr = &coin->peers.active[m++];
                iguana_initpeer(coin,addr,(uint32_t)calc_ipbits(line));
                printf("call initpeer.(%s)\n",addr->ipaddr);
                iguana_launch("connection",iguana_startconnection,addr,IGUANA_CONNTHREAD);
            }
        }
        else
        {
            for (k=height=0; k<j-1; k++)
            {
                if ( (c= line[k]) == ' ' )
                    break;
                else if ( c >= '0' && c <= '9' )
                    height = (height * 10) + (line[k] - '0');
                else break;
            }
            //printf("parseline: k.%d %d keight.%d m.%d \n",k,line[k],height,m);
            if ( line[k] == ' ' )
            {
                decode_hex(hash2.bytes,sizeof(hash2),line+k+1);
                init_hexbytes_noT(checkstr,hash2.bytes,sizeof(hash2));
                if ( strcmp(checkstr,line+k+1) == 0 )
                {
                    printf("add bundle.%d (%s)\n",height,bits256_str(hash2));
                    if ( (height % coin->chain->bundlesize) == 0 )
                    {
                        if ( height > coin->blocks.maxbits-coin->chain->bundlesize*10 )
                            iguana_recvalloc(coin,height + coin->chain->bundlesize*100);
                        if ( height <= coin->chain->bundlesize*coin->bundleswidth )
                            queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(checkstr),1);
                        queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(checkstr),1);
                    }
                    iguana_blockhashset(coin,height,hash2,100);
                }
            }
        }
    }
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
    sortbuf = mycalloc('M',coin->MAXPEERS,sizeof(double)*2);
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
            if ( i >= (coin->MAXPEERS - (coin->MAXPEERS<<3)) && slowest != 0 )
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
        portable_mutex_lock(&coin->peers_mutex);
        iguana_kviterate(coin,coin->iAddrs,(uint64_t)(long)fp,iguana_kviAddriterator);
        portable_mutex_unlock(&coin->peers_mutex);
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

int32_t iguana_heightwt(struct iguana_info *coin,int32_t *wtp,bits256 hash2)
{
    int32_t heightwts[3][2],height,i,n = 0; struct iguana_block *block,*next,*prev;
    *wtp = 0;
    height = -1;
    memset(heightwts,0,sizeof(heightwts));
    if ( (block= iguana_blockfind(coin,hash2)) != 0 )
    {
        if ( (heightwts[1][0]= iguana_blockmetric(coin,&heightwts[1][1],block)) >= 0 )
            n++;
        if ( (prev= block->hh.prev) != 0 )
        {
            if ( (heightwts[0][0]= iguana_blockmetric(coin,&heightwts[0][1],block)) >= 0 )
            {
                if ( heightwts[0][0]+1 == heightwts[1][0] )
                    n++;
                else n--, heightwts[0][0] = -1;
            }
        }
        if ( (next= block->hh.prev) != 0 )
        {
            if ( (heightwts[2][0]= iguana_blockmetric(coin,&heightwts[2][1],block)) >= 0 )
            {
                if ( heightwts[2][0]-1 == heightwts[1][0] )
                    n++;
                else n--, heightwts[2][0] = -1;
            }
        }
        if ( n > 0 )
        {
            for (i=0; i<3; i++)
                if ( heightwts[i][0] >= 0 )
                    (*wtp) += heightwts[i][1];
            (*wtp) *= n;
            height = heightwts[1][0];
        }
    }
    return(height);
}

struct iguana_bundlereq *iguana_recvblockhashes(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *blockhashes,int32_t num)
{
    int32_t i,j,height,wt,m,run,height0 = -1; struct iguana_block *block; int32_t heightwts[_IGUANA_HDRSCOUNT][2];
    for (i=m=run=0; i<num&&i<_IGUANA_HDRSCOUNT; i++)
    {
        if ( (height= iguana_heightwt(coin,&wt,blockhashes[i])) >= 0 )
        {
            if ( run == i && (i == 0 || height == height0+i) )
                run++;
            if ( (block= iguana_blockfind(coin,blockhashes[i])) != 0 && block->mainchain == 0 )
            {
                printf("%p[%d] <- %d matches.%d wt.%d vs matches.%d\n",block,block->hh.itemind,height,block->matches,wt,block->matches);
                if ( block->hh.itemind != height && wt > block->matches )
                {
                    if ( block->matches < 100 )
                    {
                        block->matches = 1;
                        block->hh.itemind = height;
                    }
                    else printf("height conflict for %s\n",bits256_str(blockhashes[i]));
                }
            }
            if ( i == 0 )
                height0 = height;
            height -= i;
            if ( m > 0 )
            {
                for (j=0; j<m; i++)
                {
                    if ( heightwts[j][0] == height )
                    {
                        heightwts[j][1] += wt;
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
    }
    if ( m > 0 )
    {
        for (i=0; i<m; i++)
            printf("(h%d %d) ",heightwts[i][0],heightwts[i][1]);
        printf("m.%d run.%d height0.%d\n",m,run,height0);
    } else printf("m.%d height0.%d %s[%d]\n",m,height0,bits256_str(blockhashes[0]),num);
    return(req);
}

void iguana_gotdata(struct iguana_info *coin,struct iguana_peer *addr,int32_t height,bits256 hash2)
{
    int32_t h,flag = 0;
    if ( height >= 0 && bits256_nonz(hash2) > 0 )
    {
        if ( (height % coin->chain->bundlesize) == 0 )
        {
            h = height - coin->chain->bundlesize;
            while ( iguana_bundleready(coin,h) > 0 )
            {
                h += coin->chain->bundlesize;
                flag++;
            }
            if ( flag != 0 )
                iguana_savehdrs(coin);
        }
        if ( coin->chain->hasheaders == 0 && (height % coin->chain->bundlesize) == 1 && iguana_havetxdata(coin,height) == 0 )
            iguana_queueblock(coin,height,hash2,1);
    }
    if ( addr != 0 && height > addr->height && height < coin->longestchain )
    {
        iguana_set_iAddrheight(coin,addr->ipbits,height);
        addr->height = height;
    }
}

struct iguana_bundlereq *iguana_recvblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundlereq *req,struct iguana_block *block,int32_t numtx,uint8_t *data,int32_t datalen,int32_t *newhwmp)
{
    int32_t height,bundlei; struct iguana_block *permblock = 0;
    //printf("got block.%s data.%p\n",addr!=0?addr->ipaddr:"local",data);
    if ( (height= iguana_blockheight(coin,block)) >= 0 && (permblock= iguana_block(coin,height)) != 0 )
    {
        //permblock->H = block->H;
        if ( iguana_blockptr(coin,height) == 0 )
            coin->blocks.ptrs[height] = permblock;
        if ( height <= coin->blocks.hwmheight )
        {
            if ( height < coin->blocks.hwmheight )
                coin->blocks.dirty = height;
            (*newhwmp)++;
        }
        //printf("iguana_recvblock (%s) height.%d %p[%d]\n",bits256_str(permblock->hash2),height,data,datalen);
        if ( permblock->txn_count == 0 )
            permblock->txn_count = numtx;
        iguana_gotdata(coin,addr,height,permblock->hash2);
        if ( data != 0 && permblock->txdata == 0 )
        {
            permblock->txdata = req;
            bundlei = (height / coin->chain->bundlesize);
            if ( GETBIT(coin->emitbits,bundlei) == 0 && iguana_bundleready(coin,height) > 0 )
            {
                req->bundleheight = bundlei * coin->chain->bundlesize;
                SETBIT(coin->emitbits,bundlei);
                req->type = 'E';
                queue_enqueue("emitQ",&coin->emitQ,&req->DL,0);
            }
            req = 0;
        }
    } else if ( (rand() % 100) == 0 )
        printf("cant find (%s) height.%d permblock.%p\n",bits256_str(block->hash2),height,permblock);
    return(req);
}

struct iguana_bundlereq *iguana_recvblockhdrs(struct iguana_info *coin,struct iguana_bundlereq *req,struct iguana_block *blocks,int32_t n,int32_t *newhwmp)
{
    int32_t i;
    if ( blocks == 0 )
        return(req);
    printf("recvblockhrs.%p[%d]\n",blocks,n);
    for (i=0; i<n; i++)
        iguana_recvblock(coin,req->addr,0,&blocks[i],req->numtx,0,0,newhwmp);
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
    while ( (req= queue_dequeue(&coin->bundlesQ,0)) != 0 )
    {
        //printf("%s bundlesQ.%p type.%c n.%d\n",req->addr != 0 ? req->addr->ipaddr : "0",req,req->type,req->n);
        if ( req->type == 'B' ) // one block with all txdata
            req = iguana_recvblock(coin,req->addr,req,&req->block,req->numtx,req->serialized,req->n,newhwmp);
        else if ( req->type == 'H' ) // blockhdrs (doesnt have txn_count!)
        {
            if ( (req= iguana_recvblockhdrs(coin,req,req->blocks,req->n,newhwmp)) != 0 )
                myfree(req->blocks,sizeof(*req->blocks) * req->n);
        }
        else if ( req->type == 'S' ) // blockhashes
        {
            if ( (req= iguana_recvblockhashes(coin,req,req->hashes,req->n)) != 0 )
                myfree(req->hashes,sizeof(*req->hashes) * req->n);
        }
        else if ( req->type == 'U' ) // unconfirmed tx
            req = iguana_recvunconfirmed(coin,req,req->serialized,req->n);
        else if ( req->type == 'T' ) // txids from inv
        {
            if ( (req= iguana_recvtxids(coin,req,req->hashes,req->n)) != 0 )
                myfree(req->hashes,req->n * sizeof(*req->hashes));
        }
        else printf("iguana_updatebundles unknown type.%c\n",req->type);
        flag++;
        if ( req != 0 )
            myfree(req,req->allocsize), req = 0;
    }
    return(flag);
}

int32_t iguana_processrecv(struct iguana_info *coin) // single threaded
{
    int32_t height,valid,n,newhwm=0,flag = 0; bits256 hash2; char hashstr[65]; struct iguana_block *block;
    //printf("processrecv\n");
    flag = iguana_processbundlesQ(coin,&newhwm);
    while ( iguana_havetxdata(coin,coin->blocks.recvblocks) != 0 )
        coin->blocks.recvblocks++;
    while ( iguana_blockptr(coin,coin->blocks.hashblocks) > 0 )
        coin->blocks.hashblocks++;
    while ( coin->blocks.issuedblocks < coin->blocks.hashblocks ) //coin->blocks.issuedblocks < coin->blocks.recvblocks+coin->chain->bundlesize*coin->bundleswidth &&
    {
        iguana_queueblock(coin,coin->blocks.issuedblocks,iguana_blockhash(coin,&valid,coin->blocks.issuedblocks),0);
        coin->blocks.issuedblocks++;
    }
    if ( iguana_needhdrs(coin) > 0 )
    {
        if ( queue_size(&coin->hdrsQ) == 0 )
        {
            if ( coin->zcount++ > 50 )//&& time(NULL) > coin->recvtime+3 )
            {
                n = 0;
                coin->recvtime = (uint32_t)time(NULL);
                height = (coin->blocks.hashblocks / coin->chain->bundlesize) * coin->chain->bundlesize;
                while ( height < (coin->longestchain - coin->chain->bundlesize) && n < coin->peers.numranked+1 )
                {
                    if ( iguana_bundleready(coin,height) <= 0 )
                    {
                        if ( iguana_havehash(coin,height) > 0 && (block= iguana_blockptr(coin,height)) != 0 )
                        {
                            flag++;
                            //printf("REQ HDR.(%s) %d\n",bits256_str(block->hash2),height);
                            printf("%d ",height);
                            n++;
                            init_hexbytes_noT(hashstr,block->hash2.bytes,sizeof(block->hash2));
                            queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(hashstr),1);
                        }
                    }
                    height += coin->chain->bundlesize;
                }
                printf("REQ HDRS\n");
                coin->zcount = 0;
            }
        } else coin->zcount = 0;
    }
    if ( queue_size(&coin->priorityQ) == 0 )
    {
        coin->pcount++;
        if ( (coin->bcount > 10 || time(NULL) > coin->recvtime) && iguana_blockptr(coin,coin->blocks.recvblocks) == 0 && coin->blocks.recvblocks < coin->blocks.hashblocks )
        {
            hash2 = iguana_blockhash(coin,&valid,coin->blocks.recvblocks);
            flag += (iguana_queueblock(coin,coin->blocks.recvblocks,hash2,1) > 0);
            coin->recvtime = (uint32_t)time(NULL);
        }
    } else coin->pcount = 0;
    if ( queue_size(&coin->blocksQ) == 0 )
    {
        coin->bcount++;
        if ( coin->bcount > 100 || time(NULL) > coin->recvtime+3 )
        {
            for (height=coin->blocks.recvblocks+1; height<coin->blocks.issuedblocks; height++)
            {
                if ( iguana_blockptr(coin,coin->blocks.recvblocks) == 0 )
                {
                    //if ( (height % 100) == 0 )
                        printf("RETRY BLOCK.%d\n",height);
                    flag += (iguana_queueblock(coin,height,iguana_blockhash(coin,&valid,height),0) > 0);
                }
            }
            coin->recvtime = (uint32_t)time(NULL);
        }
    } else coin->bcount = 0;
    //if ( newhwm != 0 )
    //    flag += iguana_lookahead(coin,&hash2,coin->blocks.hwmheight);
    return(flag);
}

void iguana_coinloop(void *arg)
{
    int32_t flag,i,j,n,m; uint32_t now,lastdisp = 0; struct iguana_info *coin,**coins = arg;
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
    iguana_possible_peer(coin,"127.0.0.1");
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
                    if ( now > coin->peers.lastmetrics+60 )
                        coin->peers.lastmetrics = iguana_updatemetrics(coin); // ranks peers
                    flag += iguana_processrecv(coin);
                    if ( 0 && coin->blocks.parsedblocks < coin->blocks.hwmheight-coin->chain->minconfirms )
                    {
                        if ( iguana_updateramchain(coin) != 0 )
                            iguana_syncs(coin), flag++; // merge ramchain fragments into full ramchain
                    }
                    if ( now > lastdisp+1 )
                    {
                        lastdisp = (uint32_t)now;
                        for (j=m=0; j<coin->longestchain; j++)
                            if ( iguana_blockptr(coin,j) != 0 )
                                m++;
                        printf("%s.%d: pend.%d/%d hash.%d/%d I.%d recv.%d/%d emit.%d HWM.%d parsed.%d |long.%d %.2f min\n",coin->symbol,flag,coin->numpendings,coin->hdrscount,coin->blocks.hashblocks,m,coin->blocks.issuedblocks,coin->blocks.recvblocks,coin->recvcount,coin->blocks.emitblocks,coin->blocks.hwmheight,coin->blocks.parsedblocks,coin->longestchain,(double)(time(NULL)-coin->starttime)/60.);
                        if ( (rand() % 60) == 0 )
                            myallocated();
                    }
                }
            }
        }
        if ( flag == 0 )
            usleep(5000);
    }
}

void iguana_coinargs(char *symbol,int64_t *maxrecvcachep,int32_t *minconfirmsp,int32_t *maxpeersp,int32_t *initialheightp,uint64_t *servicesp,cJSON *json)
{
    if ( (*maxrecvcachep= j64bits(json,"maxrecvcache")) != 0 )
        *maxrecvcachep *= 1024 * 1024 * 1024L;
    *minconfirmsp = juint(json,"minconfirms");
    *maxpeersp= juint(json,"maxpeers");
    if ( (*initialheightp= juint(json,"initialheight")) == 0 )
        *initialheightp = (strcmp(symbol,"BTC") == 0) ? 400000 : 100000;
    *servicesp = j64bits(json,"services");
}

struct iguana_info *iguana_setcoin(char *symbol,void *launched,int32_t maxpeers,int64_t maxrecvcache,uint64_t services,int32_t initialheight,int32_t maphash,int32_t minconfirms,cJSON *json)
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
    int32_t maxpeers,maphash,initialheight,minconfirms; int64_t maxrecvcache; uint64_t services;
    struct iguana_info **coins,*coin;
    if ( symbol == 0 )
        return(-1);
    if ( (coin= iguana_coin(symbol)) == 0 )
        return(-1);
    if ( coin->launched == 0 )
    {
        if ( juint(json,"GBavail") < 8 )
            maphash = IGUANA_MAPHASHTABLES;
        else maphash = 0;
        iguana_coinargs(symbol,&maxrecvcache,&minconfirms,&maxpeers,&initialheight,&services,json);
        coins = mycalloc('A',1+1,sizeof(*coins));
        if ( (coin= iguana_setcoin(coin->symbol,coins,maxpeers,maxrecvcache,services,initialheight,maphash,minconfirms,json)) != 0 )
        {
            coins[0] = (void *)((long)1);
            coins[1] = coin;
            printf("launch coinloop for.%s\n",coin->symbol);
            iguana_launch("iguana_coinloop",iguana_coinloop,coins,IGUANA_PERMTHREAD);
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
    int32_t i,n,maxpeers,maphash,initialheight,minconfirms; int64_t maxrecvcache; uint64_t services;
    if ( (jsonstr= arg) != 0 && (json= cJSON_Parse(jsonstr)) != 0 )
    {
        if ( (array= jarray(&n,json,"coins")) == 0 )
        {
            if ( (symbol= jstr(json,"coin")) != 0 && strncmp(symbol,"BTC",3) == 0 )
            {
                coins = mycalloc('A',1+1,sizeof(*coins));
                coins[1] = iguana_setcoin(symbol,coins,0,0,0,0,0,0,json);
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
            iguana_coinargs(symbol,&maxrecvcache,&minconfirms,&maxpeers,&initialheight,&services,item);
            printf("init.(%s) maxpeers.%d maxrecvcache.%s maphash.%x services.%llx\n",symbol,maxpeers,mbstr(maxrecvcache),maphash,(long long)services);
            coins[1 + i] = coin = iguana_setcoin(symbol,coins,maxpeers,maxrecvcache,services,initialheight,maphash,minconfirms,item);
            printf("MAXRECVCACHE.%s\n",mbstr(coin->MAXRECVCACHE));
        }
        coins[0] = (void *)((long)n);
        iguana_coinloop(coins);
    }
}
