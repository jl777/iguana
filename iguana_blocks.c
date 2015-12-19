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

#define iguana_block(coin,height) (height >= 0 ? coin->blocks.ptrs[height] : 0) // invariant ptr
#define iguana_blockfind(coin,hash2) iguana_blockhashset(coin,-1,hash2,0)

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

struct iguana_block *iguana_blockhashset(struct iguana_info *coin,int32_t height,bits256 hash2,int32_t createflag)
{
    struct iguana_block *block; 
    if ( height > coin->blocks.maxbits )
    {
        printf("illegal height.%d when max.%d\n",height,coin->blocks.maxbits);
        return(0);
    }
    //portable_mutex_lock(&coin->blocks_mutex);
    HASH_FIND(hh,coin->blocks.hash,&hash2,sizeof(hash2),block);
    if ( block != 0 )
    {
        /*if ( block->matches < createflag && height >= 0 )
        {
            char str[65];
            bits256_str(str,hash2);
            printf("OVERRIDE.%s itemind.%d with height.%d\n",str,block->hh.itemind,height);
            block->hh.itemind = height;
        }*/
        //portable_mutex_unlock(&coin->blocks_mutex);
        return(block);
    }
    if ( createflag > 0 )
    {
        block = mycalloc('y',1,sizeof(*block));
        block->hash2 = hash2;
        block->hh.itemind = height, block->height = -1;
        block->hh.next = block->hh.prev = block;
        /*block->matches = createflag;
        if ( height >= 0 && createflag == 100 )
        {
            //printf("blocks.ptrs.(%s) height.%d %p\n",bits256_str(hash2),height,block);
            coin->blocks.ptrs[height] = block;
        }*/
        HASH_ADD(hh,coin->blocks.hash,hash2,sizeof(hash2),block);
        {
            struct iguana_block *tmp;
            HASH_FIND(hh,coin->blocks.hash,&hash2,sizeof(hash2),tmp);
            char str[65];
            bits256_str(str,hash2);
            if ( tmp != block )
                printf("%s height.%d search error %p != %p\n",str,height,block,tmp);
            // else printf("added.(%s) height.%d %p\n",bits256_str(hash2),height,block);
        }
    }
    //portable_mutex_unlock(&coin->blocks_mutex);
    return(block);
}

bits256 iguana_blockhash(struct iguana_info *coin,int32_t *validp,int32_t height)
{
    struct iguana_block *block; bits256 hash2; uint8_t serialized[sizeof(struct iguana_msgblock)];
    *validp = 0; memset(hash2.bytes,0,sizeof(hash2));
    if ( (block= iguana_block(coin,height)) != 0 )
    {
        hash2 = block->hash2;
        if ( block->hh.itemind == height )
        {
            if ( block->height == height )
            {
                if ( (*validp= block->valid) == 0 )
                {
                    iguana_serialize_block(&hash2,serialized,block);
                    *validp = (memcmp(hash2.bytes,block->hash2.bytes,sizeof(hash2)) == 0);
                    block->valid = 1;
                    char str[65]; char str2[65];
                    bits256_str(str,hash2), bits256_str(str2,block->hash2);
                    if ( *validp == 0 )
                        printf("iguana_blockhash: miscompare.%d (%s) vs (%s)\n",height,str,str2);
                }
            }
        }
        else printf("iguana_blockhash: height mismatch %d != %d\n",height,block->hh.itemind);
    }
    return(hash2);
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
void iguana_mergeprevdep(struct iguana_prevdep *destlp,struct iguana_prevdep *srclp)
{
    if ( srclp->numpkinds > destlp->numpkinds )
        destlp->numpkinds = srclp->numpkinds;
    if ( srclp->numtxids > destlp->numtxids )
        destlp->numtxids = srclp->numtxids;
    if ( srclp->numunspents > destlp->numunspents )
        destlp->numunspents = srclp->numunspents;
    if ( srclp->numspends > destlp->numspends )
        destlp->numspends = srclp->numspends;
    if ( srclp->PoW > destlp->PoW )
        destlp->PoW = srclp->PoW;
}

void iguana_mergeblock(struct iguana_block *dest,struct iguana_prevdep *destlp,struct iguana_block *block,struct iguana_prevdep *srclp)
{
    if ( block->numvins > dest->numvins )
        dest->numvins = block->numvins;
    if ( block->numvouts > dest->numvouts )
        dest->numvouts = block->numvouts;
    if ( block->txn_count > dest->txn_count )
        dest->txn_count = block->txn_count;
    if ( dest->height == 0 )
        dest->height = block->height;
    iguana_mergeprevdep(destlp,srclp);
}

void iguana_convblock(struct iguana_block *dest,struct iguana_msgblock *msg,bits256 hash2,int32_t height) //uint32_t numtxids,uint32_t numunspents,uint32_t numspends,double PoW)
{
    memset(dest,0,sizeof(*dest));
    dest->version = msg->H.version;
    dest->prev_block = msg->H.prev_block;
    dest->merkle_root = msg->H.merkle_root;
    dest->timestamp = msg->H.timestamp;
    dest->bits = msg->H.bits;
    dest->nonce = msg->H.nonce;
    dest->txn_count = msg->txn_count;
    dest->height = height;
    dest->hash2 = hash2;
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
    if ( priority != 0 || bp == 0 || (block= bp->blocks[bundlei]) == 0 )
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

int32_t iguana_pollQs(struct iguana_info *coin,struct iguana_peer *addr)
{
    uint8_t serialized[sizeof(struct iguana_msghdr) + sizeof(uint32_t)*32 + sizeof(bits256)];
    char *hashstr=0,hexstr[65]; bits256 hash2; int32_t limit,height=-1,datalen,flag = 0;
    struct iguana_blockreq *req=0;
    if ( iguana_needhdrs(coin) != 0 && addr->pendhdrs < IGUANA_MAXPENDHDRS )
    {
        //printf("%s check hdrsQ\n",addr->ipaddr);
        if ( (hashstr= queue_dequeue(&coin->hdrsQ,1)) != 0 )
        {
            //printf("%s request hdr.(%s)\n",addr!=0?addr->ipaddr:"local",hashstr);
            if ( (datalen= iguana_gethdrs(coin,serialized,coin->chain->gethdrsmsg,hashstr)) > 0 )
            {
                decode_hex(hash2.bytes,sizeof(hash2),hashstr);
                iguana_send(coin,addr,serialized,datalen);
                addr->pendhdrs++;
                flag++;
                free_queueitem(hashstr);
                return(flag);
            } else printf("datalen.%d from gethdrs\n",datalen);
            free_queueitem(hashstr);
            hashstr = 0;
        }
    }
    if ( (limit= addr->recvblocks) > coin->MAXPENDING )
        limit = coin->MAXPENDING;
    if ( (req= queue_dequeue(&coin->priorityQ,0)) == 0 && addr->pendblocks < limit )
    {
        //char str[65];
        struct iguana_bundle *bp; int32_t i,r,j,incr; struct iguana_block *block; double millis = milliseconds();
        //|| ( && (req= queue_dequeue(&coin->blocksQ,0)) != 0) )
        incr = (coin->bundlescount / (coin->peers.numranked + 1)) + 1;
        for (r=0; r<coin->bundlescount; r++)
        {
            i = (r + incr*addr->addrind) % coin->bundlescount;
            if ( (bp= coin->bundles[i]) != 0 && bp->emitfinish == 0 && bp->blockhashes != 0 )
            {
                for (j=0; j<coin->chain->bundlesize && j<bp->n; j++)
                {
                    if ( (block= bp->blocks[j]) == 0 && (bp->issued[j] == 0 || millis > bp->issued[j]+1000) )
                    {
                        if ( j == 0 )
                            hash2 = bp->bundlehash2;
                        else if ( j == 1 )
                            hash2 = bp->firstblockhash2;
                        else hash2 = bp->blockhashes[j];
                        if ( bits256_nonz(hash2) > 0 )
                        {
                            init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
                            if ( (datalen= iguana_getdata(coin,serialized,MSG_BLOCK,hexstr)) > 0 )
                            {
                                iguana_send(coin,addr,serialized,datalen);
                                addr->pendblocks++;
                                addr->pendtime = (uint32_t)time(NULL);
                                if ( j < 2 )
                                {
                                    char str[65];
                                    printf("%p %s %s issue.%d %d lag.%.3f\n",block,addr->ipaddr,bits256_str(str,hash2),bp->hdrsi,j,milliseconds()-millis);
                                }
                                bp->issued[j] = milliseconds();
                                SETBIT(bp->recv,j);
                                return(1);
                            }
                        }
                    }
                }
            }
        }
    }
    if ( req != 0 )
    {
        hash2 = req->hash2;
        height = req->height;
        if ( req->bp != 0 && req->bundlei >= 0 && req->bundlei < req->bp->n && req->bundlei < coin->chain->bundlesize && req->bp->blocks[req->bundlei] != 0 )
        {
            //printf("%p[%d] %d\n",req->bp,req->bp!=0?req->bp->bundleheight:-1,req->bundlei);
            myfree(req,sizeof(*req));
        }
        else if ( req->bp == 0 || (req->bp != 0 && req->bundlei >= 0 && GETBIT(req->bp->recv,req->bundlei) == 0) )
        {
            init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
            if ( (datalen= iguana_getdata(coin,serialized,MSG_BLOCK,hexstr)) > 0 )
            {
                if ( 0 && queue_size(&coin->priorityQ) > 0 )
                    printf("%s %s BLOCK.%d:%d bit.%d Q.(%d %d)\n",addr->ipaddr,hexstr,req->bp!=0?req->bp->hdrsi:-1,req->bundlei,req->bp!=0?GETBIT(req->bp->recv,req->bundlei):-1,queue_size(&coin->priorityQ),queue_size(&coin->blocksQ));
                iguana_send(coin,addr,serialized,datalen);
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

void iguana_copyblock(struct iguana_info *coin,struct iguana_block *block,struct iguana_block *origblock)
{
    block->hash2 = origblock->hash2;
    block->prev_block = origblock->prev_block;
    block->merkle_root = origblock->merkle_root;
    if ( block->timestamp == 0 )
        block->timestamp = origblock->timestamp;
    if ( block->nonce == 0 )
        block->nonce = origblock->nonce;
    if ( block->bits == 0 )
        block->bits = origblock->bits;
    if ( block->txn_count == 0 )
        block->txn_count = origblock->txn_count;
    if ( block->version == 0 )
        block->version = origblock->version;
}
