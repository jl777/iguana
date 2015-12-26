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

void iguana_gotblockM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *origtxdata,struct iguana_msgtx *txarray,uint8_t *data,int32_t recvlen)
{
    struct iguana_bundlereq *req; struct iguana_txblock *txdata = 0; int32_t i; char fname[1024];
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
    txdata = origtxdata;
    if ( addr != 0 )
    {
        if ( addr->pendblocks > 0 )
            addr->pendblocks--;
        addr->lastblockrecv = (uint32_t)time(NULL);
        addr->recvblocks += 1.;
        addr->recvtotal += recvlen;
        origtxdata->block.ipbits = addr->ipbits;
        iguana_ramchain_data(coin,addr,origtxdata,txarray,origtxdata->block.txn_count,data,recvlen);
        {
            txdata->block.ipbits = addr->ipbits;
            if ( 0 )
            {
                struct iguana_txblock *checktxdata; struct iguana_memspace checkmem; int32_t checkbundlei;
                memset(&checkmem,0,sizeof(checkmem));
                iguana_meminit(&checkmem,"checkmem",0,txdata->datalen + 4096,0);
                if ( (checktxdata= iguana_peertxdata(coin,&checkbundlei,fname,&checkmem,addr->ipbits,txdata->block.hash2)) != 0 )
                {
                    printf("check datalen.%d bundlei.%d T.%d U.%d S.%d P.%d X.%d\n",checktxdata->datalen,checkbundlei,checktxdata->numtxids,checktxdata->numunspents,checktxdata->numspends,checktxdata->numpkinds,checktxdata->numexternaltxids);
                }
                iguana_mempurge(&checkmem);
            }
         }
        req->datalen = txdata->datalen;
    }
    //printf("datalen.%d\n",req->datalen);
    if ( req->datalen == 0 )
        req->datalen = recvlen;
    req->block = txdata->block;
    req->ipbits = txdata->block.ipbits;
    req->block.txn_count = req->numtx = txdata->block.txn_count;
    coin->recvcount++;
    coin->recvtime = (uint32_t)time(NULL);
    req->addr = addr;
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
struct iguana_bundlereq *iguana_recvblockhashes(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *blockhashes,int32_t num)
{
    int32_t i,bundlei; struct iguana_block *block,*prev = 0; struct iguana_bundle *bp;
    bp = 0, bundlei = -2, iguana_bundlefind(coin,&bp,&bundlei,blockhashes[1]);
    if ( bp == 0 || bundlei != 1 || num <= 2 )
    {
        if ( num > 2 )
            iguana_blockQ(coin,0,-1,blockhashes[1],1);
        //char str[65]; printf("got %d hashes %d:%d %s\n",num,bp==0?-1:bp->bundleheight,bundlei,bits256_str(str,blockhashes[0]));
        return(req);
    }
    if ( num > coin->chain->bundlesize+1 )
        num = coin->chain->bundlesize+1;
    //char str[65]; printf("got %d iguana_recvblockhashes %d:%d %s\n",num,bp==0?-1:bp->bundleheight,bundlei,bits256_str(str,blockhashes[1]));
    //return(req);
    for (i=0; i<num; i++)
    {
        block = 0;
        if ( bits256_nonz(blockhashes[i]) > 0 )
        {
            if ( (block= iguana_blockhashset(coin,-1,blockhashes[i],1)) != 0 && prev != 0 )
            {
                if ( prev->hh.next == 0 && block->hh.prev == 0 )
                    prev->hh.next = block, block->hh.prev = prev;
            }
            if ( i == coin->chain->bundlesize )
            {
                //char str[65]; printf("ACREATE.%d new bundle.%s\n",bp->bundleheight + coin->chain->bundlesize,bits256_str(str,blockhashes[i]));
                //iguana_bundlecreate(coin,&bundlei,bp->bundleheight + coin->chain->bundlesize,blockhashes[i]);
                iguana_blockQ(coin,0,-1,blockhashes[i],1);
            }
            else if ( i < coin->chain->bundlesize )
            {
                if ( i == 1  )
                    iguana_blockQ(coin,0,-1,blockhashes[i],1);
                iguana_bundlehash2add(coin,0,bp,i,blockhashes[i]);
            }
        }
        prev = block;
    }
    return(req);
}

struct iguana_bundle *iguana_bundleset(struct iguana_info *coin,struct iguana_block **blockp,int32_t *bundleip,struct iguana_block *origblock)
{
    struct iguana_block *block,*prev; struct iguana_bundle *bp = 0; int32_t bundlei = -2;
    if ( origblock == 0 )
        return(0);
    block = iguana_blockhashset(coin,-1,origblock->hash2,1);
    *blockp = block;
    if ( block != 0 )
    {
        if ( bits256_nonz(origblock->prev_block) > 0 )
        {
            prev = iguana_blockhashset(coin,-1,origblock->prev_block,1);
            if ( prev != 0 )
            {
                prev->hh.next = block, block->hh.prev = prev;
                //printf("link block\n");
            }
        }
        if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,origblock->hash2)) != 0 )
        {
            if ( bundlei < coin->chain->bundlesize )
            {
                block->bundlei = bundlei;
                block->hdrsi = bp->hdrsi;
                block->havebundle = 1;
                iguana_hash2set(coin,"blockadd",bp,block->bundlei,block->hash2);
            }
        }
        else if ( (bp= iguana_bundlefind(coin,&bp,&bundlei,origblock->prev_block)) != 0 )
        {
            if ( bundlei < coin->chain->bundlesize-1 )
            {
                block->bundlei = ++bundlei;
                block->hdrsi = bp->hdrsi;
                block->havebundle = 1;
                iguana_hash2set(coin,"blockadd",bp,block->bundlei,block->hash2);
            }
            else if ( bundlei == coin->chain->bundlesize-1 )
            {
                char str[65]; printf("CREATE.%d new bundle.%s\n",bp->bundleheight + coin->chain->bundlesize,bits256_str(str,origblock->hash2));
                iguana_blockQ(coin,0,-1,origblock->hash2,1);
                iguana_bundlecreate(coin,&bundlei,bp->bundleheight + coin->chain->bundlesize,origblock->hash2);
            }
        } else { char str[65]; printf("can find.(%s)\n",bits256_str(str,origblock->hash2)); }
        if ( block->havebundle != 0 && block->hdrsi < coin->bundlescount )
        {
            bundlei = block->bundlei;
            bp = coin->bundles[block->hdrsi];
        }
        //char str[65]; printf("iguana_recvblock (%s) %d %d[%d] %p\n",bits256_str(str,block->hash2),block->havebundle,block->hdrsi,bundlei,bp);
    }
    *bundleip = bundlei;
    return(bp);
}

struct iguana_bundlereq *iguana_recvblockhdrs(struct iguana_info *coin,struct iguana_bundlereq *req,struct iguana_block *blocks,int32_t n,int32_t *newhwmp)
{
    int32_t i,bundlei; struct iguana_block *block;
    if ( blocks == 0 )
    {
        printf("iguana_recvblockhdrs null blocks?\n");
        return(req);
    }
    if ( blocks != 0 && n > 0 )
    {
        for (i=0; i<n; i++)
        {
            //fprintf(stderr,"i.%d of %d bundleset\n",i,n);
            iguana_bundleset(coin,&block,&bundlei,&blocks[i]);
            //fprintf(stderr,"i.%d of %d iguana_chainextend\n",i,n);
            //iguana_chainextend(coin,&blocks[i]);
        }
    }
    return(req);
}

struct iguana_bundlereq *iguana_recvblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundlereq *req,struct iguana_block *origblock,int32_t numtx,int32_t datalen,int32_t *newhwmp)
{
    struct iguana_bundle *bp=0; char str[65]; int32_t bundlei = -2; struct iguana_block *block; double duration;
    bp = iguana_bundleset(coin,&block,&bundlei,origblock);
    if ( block != origblock )
        iguana_blockcopy(coin,block,origblock);
    if ( bp != 0 && bundlei >= 0 )
    {
        if ( bp->requests[bundlei] > 2 )
        printf("recv bundlei.%d hdrs.%d reqs.[%d]\n",bundlei,bp->hdrsi,bp->requests[bundlei]);
        if ( bundlei == 1 && bp->numhashes < bp->n )
        {
            bits256_str(str,block->prev_block);
            queue_enqueue("hdrsQ",&coin->hdrsQ,queueitem(str),1);
        }
        if ( bp->hdrtime == 0 )
            bp->hdrtime = (uint32_t)time(NULL);
        if ( datalen > 0 )
        {
            SETBIT(bp->recv,bundlei);
            if ( bp->issued[bundlei] > 0 )
            {
                duration = 1000. * ((int32_t)time(NULL) - bp->issued[bundlei]);
                if ( duration < bp->avetime/10. )
                    duration = bp->avetime/10.;
                else if ( duration > bp->avetime*10. )
                    duration = bp->avetime * 10.;
                dxblend(&bp->avetime,duration,.9);
                dxblend(&coin->avetime,bp->avetime,.9);
            }
            if ( bundlei >= 0 && bundlei < bp->n )
            {
                //bp->blocks[bundlei] = block;
                //bp->numrecv++;
            }
        }
    }
    if ( block != 0 )
    {
        block->recvlen = datalen;
        block->ipbits = req->ipbits;
        //printf("datalen.%d ipbits.%x\n",datalen,req->ipbits);
    } else printf("cant create block.%llx block.%p bp.%p bundlei.%d\n",(long long)origblock->hash2.txid,block,bp,bundlei);
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
    while ( flag < IGUANA_BUNDLELOOP && (req= queue_dequeue(&coin->bundlesQ,0)) != 0 )
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
        //printf("done %s bundlesQ.%p type.%c n.%d\n",req->addr != 0 ? req->addr->ipaddr : "0",req,req->type,req->n);
        if ( req != 0 )
            myfree(req,req->allocsize), req = 0;
    }
    return(flag);
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
        if ( coin->zcount++ > 1 )
        {
            for (i=0; i<coin->bundlescount; i++)
            {
                if ( (bp= coin->bundles[i]) != 0 )
                {
                    if ( bp->numhashes < bp->n && bp->bundleheight+bp->numhashes < coin->longestchain && time(NULL) > bp->issuetime+sqrt(coin->bundlescount) )//&& coin->numpendings < coin->MAXBUNDLES )
                    {
                        printf("hdrsi.%d numhashes.%d:%d needhdrs.%d qsize.%d zcount.%d\n",i,bp->numhashes,bp->n,iguana_needhdrs(coin),queue_size(&coin->hdrsQ),coin->zcount);
                        if ( bp->issuetime == 0 )
                            coin->numpendings++;
                        char str[65];
                        bits256_str(str,bp->hashes[0]);
                        printf("(%s %d).%d ",str,bp->bundleheight,i);
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

struct iguana_blockreq { struct queueitem DL; bits256 hash2,*blockhashes; struct iguana_bundle *bp; int32_t n,height,bundlei; };
int32_t iguana_blockQ(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t priority)
{
    queue_t *Q; char *str; struct iguana_blockreq *req; struct iguana_block *block;
    if ( bits256_nonz(hash2) == 0 )
    {
        printf("cant queue zerohash bundlei.%d\n",bundlei);
        return(-1);
    }
    if ( priority != 0 || bp == 0 || (block= iguana_blockfind(coin,bp->hashes[bundlei])) == 0 || block->ipbits == 0 )
    {
        if ( priority != 0 )
            str = "priorityQ", Q = &coin->priorityQ;
        else str = "blocksQ", Q = &coin->blocksQ;
        if ( Q != 0 )
        {
            req = mycalloc('r',1,sizeof(*req));
            req->hash2 = hash2;
            req->bp = bp;
            req->bundlei = bundlei;
            if ( bp != 0 && bundlei >= 0 && bundlei < bp->n )
            {
                bp->issued[bundlei] = milliseconds();
                if ( bp->bundleheight >= 0 )
                    req->height = (bp->bundleheight + bundlei);
            }
            char str[65];
            bits256_str(str,hash2);
            if ( 0 && (bundlei % 250) == 0 )
                printf("%s %d %s recv.%d numranked.%d qsize.%d\n",str,req->height,str,coin->blocks.recvblocks,coin->peers.numranked,queue_size(Q));
            queue_enqueue(str,Q,&req->DL,0);
            return(1);
        } else printf("null Q\n");
    } //else printf("queueblock skip priority.%d bundlei.%d\n",bundlei,priority);
    return(0);
}

int32_t iguana_pollQsPT(struct iguana_info *coin,struct iguana_peer *addr)
{
    uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(uint32_t)*32 + sizeof(bits256)];
    char *hashstr=0,hexstr[65]; bits256 hash2; uint32_t now; struct iguana_blockreq *req=0;
    int32_t limit,refbundlei,height=-1,datalen,flag = 0;
    now = (uint32_t)time(NULL);
    if ( iguana_needhdrs(coin) != 0 && addr->pendhdrs < IGUANA_MAXPENDHDRS )
    {
        //printf("%s check hdrsQ\n",addr->ipaddr);
        if ( (hashstr= queue_dequeue(&coin->hdrsQ,1)) != 0 )
        {
            if ( (datalen= iguana_gethdrs(coin,serialized,coin->chain->gethdrsmsg,hashstr)) > 0 )
            {
                decode_hex(hash2.bytes,sizeof(hash2),hashstr);
                if ( bits256_nonz(hash2) > 0 )
                {
                    //printf("%s request hdr.(%s)\n",addr!=0?addr->ipaddr:"local",hashstr);
                    iguana_send(coin,addr,serialized,datalen);
                    addr->pendhdrs++;
                    flag++;
                }
                free_queueitem(hashstr);
                return(flag);
            } else printf("datalen.%d from gethdrs\n",datalen);
            free_queueitem(hashstr);
            hashstr = 0;
        }
    }
    if ( (limit= addr->recvblocks) > coin->MAXPENDING )
        limit = coin->MAXPENDING;
    if ( limit < 1 )
        limit = 1;
    if ( coin->bundlescount > 0  && (req= queue_dequeue(&coin->priorityQ,0)) == 0 && addr->pendblocks < limit )
    {
        struct iguana_bundle *bp,*bestbp = 0; int32_t i,r,diff,j,k,n; double metric,bestmetric = -1.;
        if ( (addr->ipbits % 10) < 6 )
            refbundlei = (addr->ipbits % coin->bundlescount);
        else
        {
            for (i=n=0; i<coin->bundlescount; i++)
                if ( coin->bundles[i] != 0 && coin->bundles[i]->emitfinish == 0 )
                    n++;
            if ( n*2 < coin->bundlescount )
            {
                for (i=refbundlei=0; i<IGUANA_MAXPEERS; i++)
                {
                    if ( addr->usock == coin->peers.active[i].usock )
                        break;
                    if ( coin->peers.active[i].usock >= 0 )
                        refbundlei++;
                }
                //printf("half done\n");
            } else refbundlei = ((addr->addrind*100) % coin->bundlescount);
        }
        for (i=0; i<coin->bundlescount; i++)
        {
            if ( (diff= (i - refbundlei)) < 0 )
                diff = -diff;
            if ( (bp= coin->bundles[i]) != 0 && bp->emitfinish == 0 )
            {
                metric = (1 + diff * ((addr->addrind&1) == 0 ? 1 : diff) * (1. + bp->metric)) / (i + 1);
                //printf("%f ",bp->metric);
                if ( bestmetric < 0. || metric < bestmetric )
                    bestmetric = metric, bestbp = bp;
            }
        }
        if ( bestbp != 0 && bp->emitfinish == 0 )
        {
            for (k=0; k<coin->bundlescount; k++)
            {
                i = (bestbp->hdrsi + k) % coin->bundlescount;
                if ( (bp= coin->bundles[i]) == 0 || bp->emitfinish != 0 )
                    continue;
                //printf("%.15f ref.%d addrind.%d bestbp.%d\n",bestmetric,refbundlei,addr->addrind,bp->hdrsi);
                for (r=0; r<coin->chain->bundlesize && r<bp->n; r++)
                {
                    j = (addr->addrind*3 + r) % bp->n;
                    hash2 = bp->hashes[j];
                    if ( bp->requests[j] <= bp->minrequests && bp->recvlens[j] == 0 && bits256_nonz(hash2) > 0 && (bp->issued[j] == 0 || now > bp->issued[j]+bp->threshold) )
                    {
                        init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
                        if ( (datalen= iguana_getdata(coin,serialized,MSG_BLOCK,hexstr)) > 0 )
                        {
                            iguana_send(coin,addr,serialized,datalen);
                            coin->numemitted++;
                            addr->pendblocks++;
                            addr->pendtime = (uint32_t)time(NULL);
                            if ( 0 && (rand() % 1000) == 0 )
                            {
                                char str[65];
                                printf(" %s %s issue.%d %d lag.%d\n",addr->ipaddr,bits256_str(str,hash2),bp->hdrsi,j,now-bp->issued[j]);
                            }
                            bp->issued[j] = (uint32_t)time(NULL);
                            if ( bp->requests[j] < 100 )
                                bp->requests[j]++;
                            return(1);
                        } else printf("MSG_BLOCK null datalen.%d\n",datalen);
                    } //else printf("null hash\n");
                }
            }
        }
    }
    if ( req != 0 )
    {
        hash2 = req->hash2;
        height = req->height;
        if ( 0 && req->bp != 0 && req->bundlei >= 0 && req->bundlei < req->bp->n && req->bundlei < coin->chain->bundlesize && req->bp->recvlens[req->bundlei] != 0 )
        {
            //printf("%p[%d] %d\n",req->bp,req->bp!=0?req->bp->bundleheight:-1,req->bundlei);
            myfree(req,sizeof(*req));
        }
        else if ( req->bp == 0 || (req->bp != 0 && req->bundlei >= 0) )//&& GETBIT(req->bp->recv,req->bundlei) == 0) )
        {
            init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
            if ( (datalen= iguana_getdata(coin,serialized,MSG_BLOCK,hexstr)) > 0 )
            {
                if ( 0 && queue_size(&coin->priorityQ) > 0 )
                    printf("%s %s BLOCK.%d:%d bit.%d Q.(%d %d)\n",addr->ipaddr,hexstr,req->bp!=0?req->bp->hdrsi:-1,req->bundlei,req->bp!=0?GETBIT(req->bp->recv,req->bundlei):-1,queue_size(&coin->priorityQ),queue_size(&coin->blocksQ));
                iguana_send(coin,addr,serialized,datalen);
                coin->numemitted++;
                addr->pendblocks++;
                addr->pendtime = (uint32_t)time(NULL);
                if ( req->bp != 0 && req->bundlei >= 0 && req->bundlei < req->bp->n )
                    req->bp->issued[req->bundlei] = milliseconds();
                flag++;
                myfree(req,sizeof(*req));
                return(flag);
            } else printf("error constructing request %s.%d\n",hexstr,height);
        }
    }
    return(flag);
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
            else if ( 1 )
            {
                double lag = milliseconds() - coin->backstopmillis;
                if ( coin->blocks.hwmchain.height+1 < coin->longestchain && (coin->backstop != coin->blocks.hwmchain.height+1 || lag > 2*coin->avetime) )//&& next->recvlen == 0 )
                {
                    coin->backstop = coin->blocks.hwmchain.height+1;
                    coin->backstopmillis = milliseconds();
                    iguana_blockQ(coin,0,coin->blocks.hwmchain.height+1,next->hash2,1);
                    // clear recvlens
                    //if ( ((coin->blocks.hwmchain.height+1) % 100) == 0 )
                    if ( (rand() % 100) == 0 )
                        printf("BACKSTOP.%d avetime %.3f %.3f lag %.3f\n",coin->blocks.hwmchain.height+1,coin->avetime,coin->backstopmillis,lag);
                }
                else if ( 0 && bits256_nonz(next->prev_block) > 0 )
                    printf("next prev cmp error nonz.%d\n",bits256_nonz(next->prev_block));
            }
        }
        if ( h != coin->blocks.hwmchain.height / coin->chain->bundlesize )
            iguana_savehdrs(coin);
    }
    return(flag);
}

