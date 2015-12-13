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

#define iguana_block(coin,height) (height >= 0 ? coin->blocks.ptrs[height] : 0) // invariant ptr
#define iguana_blockfind(coin,hash2) iguana_blockhashset(coin,-1,hash2,0)

static int32_t _sort_by_itemind(struct iguana_block *a, struct iguana_block *b)
{
    if (a->hh.itemind == b->hh.itemind) return 0;
    return (a->hh.itemind < b->hh.itemind) ? -1 : 1;
}

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
    printf("_iguana_verifysort: n.%d topheight.%d run.%d\n",i,height,run);
    return(run);
}

int32_t iguana_blocksort(struct iguana_info *coin)
{
    int32_t hashblocks;
    portable_mutex_lock(&coin->blocks_mutex);
    HASH_SORT(coin->blocks.hash,_sort_by_itemind);
    hashblocks = _iguana_verifysort(coin);
    portable_mutex_unlock(&coin->blocks_mutex);
    return(hashblocks);
}

int32_t _iguana_blocklink(struct iguana_info *coin,struct iguana_block *block)
{
    int32_t height,n = 0; struct iguana_block *prev,*next;
    if ( block == 0 )
        printf("iguana_blockslink: illegal null block %p\n",block), getchar();
    block->hh.next = block->hh.prev = 0;
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
    portable_mutex_lock(&coin->blocks_mutex);
    HASH_FIND(hh,coin->blocks.hash,&hash2,sizeof(hash2),block);
    if ( block != 0 )
    {
        if ( block->matches < createflag && height >= 0 )
        {
            printf("OVERRIDE.%s itemind.%d with height.%d\n",bits256_str(hash2),block->hh.itemind,height);
            block->hh.itemind = height;
        }
        portable_mutex_unlock(&coin->blocks_mutex);
        return(block);
    }
    if ( createflag > 0 )
    {
        block = mycalloc('y',1,sizeof(*block));
        block->hash2 = hash2;
        block->hh.itemind = height, block->height = -1;
        block->hh.next = block->hh.prev = 0;
        block->matches = createflag;
        if ( height >= 0 && createflag == 100 )
        {
            //printf("blocks.ptrs.(%s) height.%d %p\n",bits256_str(hash2),height,block);
            coin->blocks.ptrs[height] = block;
        }
        HASH_ADD(hh,coin->blocks.hash,hash2,sizeof(hash2),block);
        {
            struct iguana_block *tmp;
            HASH_FIND(hh,coin->blocks.hash,&hash2,sizeof(hash2),tmp);
            if ( tmp != block )
                printf("%s height.%d search error %p != %p\n",bits256_str(hash2),height,block,tmp);
            // else printf("added.(%s) height.%d %p\n",bits256_str(hash2),height,block);
        }
    }
    portable_mutex_unlock(&coin->blocks_mutex);
    return(block);
}

bits256 iguana_blockhash(struct iguana_info *coin,int32_t *validp,int32_t height)
{
    struct iguana_block *block; bits256 hash2; uint8_t serialized[sizeof(struct iguana_msgblock)];
    *validp = 0; hash2 = bits256_zero;
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
                    if ( *validp == 0 )
                        printf("iguana_blockhash: miscompare.%d (%s) vs (%s)\n",height,bits256_str(hash2),bits256_str2(block->hash2));
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

void *iguana_bundletxdata(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei)
{
    struct iguana_block *block; void *txdata = 0;
    if ( bp != 0 && bundlei >= 0 && bundlei < coin->chain->bundlesize && GETBIT(bp->recv,bundlei) != 0 && (block= bp->blocks[bundlei]) != 0 )
        txdata = block->txdata;
    //printf("txdata.%p\n",txdata);
    return(txdata);
}

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

void iguana_mergeblock(struct iguana_block *dest,struct iguana_block *block)
{
    if ( block->L.numpkinds > dest->L.numpkinds )
        dest->L.numpkinds = block->L.numpkinds;
    if ( block->L.numtxids > dest->L.numtxids )
        dest->L.numtxids = block->L.numtxids;
    if ( block->L.numunspents > dest->L.numunspents )
        dest->L.numunspents = block->L.numunspents;
    if ( block->L.numspends > dest->L.numspends )
        dest->L.numspends = block->L.numspends;
    if ( block->L.PoW > dest->L.PoW )
        dest->L.PoW = block->L.PoW;
    if ( block->numvins > dest->numvins )
        dest->numvins = block->numvins;
    if ( block->numvouts > dest->numvouts )
        dest->numvouts = block->numvouts;
    if ( block->txn_count > dest->txn_count )
        dest->txn_count = block->txn_count;
    dest->height = block->height;
}

void iguana_convblock(struct iguana_block *dest,struct iguana_msgblock *msg,bits256 hash2,int32_t height,uint32_t numtxids,uint32_t numunspents,uint32_t numspends,double PoW)
{
    memset(dest,0,sizeof(*dest));
    dest->version = msg->H.version;
    dest->prev_block = msg->H.prev_block;
    dest->merkle_root = msg->H.merkle_root;
    dest->timestamp = msg->H.timestamp;
    dest->bits = msg->H.bits;
    dest->nonce = msg->H.nonce;
    dest->txn_count = msg->txn_count;
    dest->L.numtxids = numtxids;
    dest->L.numunspents = numunspents;
    dest->L.numspends = numspends;
    dest->height = height;
    dest->L.PoW = PoW;
    dest->hash2 = hash2;
    dest->txn_count = msg->txn_count;
}

struct iguana_blockreq { struct queueitem DL; bits256 hash2,*blockhashes; struct iguana_bundle *bp; int32_t n,height,bundlei; };
int32_t iguana_blockQ(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2,int32_t priority)
{
    queue_t *Q; char *str; struct iguana_blockreq *req;
    if ( bits256_nonz(hash2) == 0 )
    {
        printf("cant queue zerohash bundlei.%d\n",bundlei);
        getchar();
        return(-1);
    }
    if ( priority != 0 || iguana_bundletxdata(coin,bp,bundlei) == 0 )
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
            if ( 0 && (bundlei % 250) == 0 )
                printf("%s %d %s recv.%d numranked.%d qsize.%d\n",str,req->height,bits256_str(hash2),coin->blocks.recvblocks,coin->peers.numranked,queue_size(Q));
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
    if ( (limit= addr->recvblocks) < 1 )
        limit = 1;
    else if ( limit > coin->MAXPENDING )
        limit = coin->MAXPENDING;
    while ( (req= queue_dequeue(&coin->priorityQ,0)) != 0 || (addr->pendblocks < limit && (req= queue_dequeue(&coin->blocksQ,0)) != 0) )
    {
        hash2 = req->hash2;
        height = req->height;
        if ( iguana_bundletxdata(coin,req->bp,req->bundlei) != 0 )
        {
            //printf("%p[%d] %d\n",req->bp,req->bp!=0?req->bp->bundleheight:-1,req->bundlei);
            myfree(req,sizeof(*req));
        }
        else if ( req->bp != 0 && req->bundlei >= 0 && GETBIT(req->bp->recv,req->bundlei) == 0 )
        {
            init_hexbytes_noT(hexstr,hash2.bytes,sizeof(hash2));
            if ( (datalen= iguana_getdata(coin,serialized,MSG_BLOCK,hexstr)) > 0 )
            {
                if ( 0 && queue_size(&coin->priorityQ) > 0 )
                    printf("%s %s BLOCK.%d:%d bit.%d qsizes.(p%d %d)\n",addr->ipaddr,hexstr,req->bp!=0?req->bp->hdrsi:-1,req->bundlei,req->bp!=0?GETBIT(req->bp->recv,req->bundlei):-1,queue_size(&coin->priorityQ),queue_size(&coin->blocksQ));
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

bits256 iguana_bundleihash2(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei)
{
    struct iguana_block *block;
    if ( bp->hdrsi == 0 && bp->bundleheight == 0 && bundlei == 0 )
        return(*(bits256 *)coin->chain->genesis_hashdata);
    if ( bundlei < -1 )
        return(bits256_zero);
    else if ( bundlei == -1 )
        return(bp->prevbundlehash2);
    else if ( bundlei == 0 )
        return(bp->bundlehash2);
    else if ( bundlei == 1 )
        return(bp->firstblockhash2);
    else if ( bundlei >= bp->n )
        return(bp->nextbundlehash2);
    else if ( bp->blockhashes != 0 && (block= bp->blocks[bundlei]) != 0 )
    {
        if ( memcmp(bp->blockhashes[bundlei].bytes,block->hash2.bytes,sizeof(bits256)) != 0 )
        {
            printf("bundleihash2 error at bundlei.%d %s != %s\n",bundlei,bits256_str(bp->blockhashes[bundlei]),bits256_str2(block->hash2));
            return(bits256_zero);
        }
        return(bp->blockhashes[bundlei]);
    }
    else if ( (block= bp->blocks[bundlei]) != 0 )
        return(block->hash2);
    else if ( bp->blockhashes != 0 )
        return(bp->blockhashes[bundlei]);
    else return(bits256_zero);
}

int32_t iguana_hash2set(struct iguana_info *coin,char *str,bits256 *orighash2,bits256 newhash2)
{
    if ( bits256_nonz(newhash2) == 0 )
    {
        printf("iguana_hash2set warning: newhash2 is zero\n"), getchar();
        return(-1);
    }
    if ( bits256_nonz(*orighash2) > 0 )
    {
        if ( memcmp(newhash2.bytes,orighash2,sizeof(bits256)) != 0 )
        {
            printf("iguana_hash2set overwrite [%s] %s with %s\n",str,bits256_str(*orighash2),bits256_str2(newhash2));
            if ( strcmp(str,"firstblockhash2") == 0 )
                getchar();
            *orighash2 = newhash2;
            return(-1);
        }
    }
    *orighash2 = newhash2;
    return(0);
}

struct iguana_bundle *iguana_bundlescan(struct iguana_info *coin,int32_t *bundleip,struct iguana_bundle *bp,bits256 hash2,int32_t searchmask)
{
    int32_t i;
    *bundleip = -2;
    if ( (searchmask & IGUANA_SEARCHBUNDLE) != 0 )
    {
        //printf("%s vs %s: %d\n",bits256_str(hash2),bits256_str2(bp->bundlehash2),memcmp(hash2.bytes,bp->bundlehash2.bytes,sizeof(hash2)));
        if ( memcmp(hash2.bytes,bp->bundlehash2.bytes,sizeof(hash2)) == 0 )
        {
            if ( bp->blockhashes != 0 )
                iguana_hash2set(coin,"blockhashes[0]",&bp->blockhashes[0],bp->bundlehash2);
            *bundleip = 0;
            return(bp);
        }
        if ( memcmp(hash2.bytes,bp->firstblockhash2.bytes,sizeof(hash2)) == 0 )
        {
            if ( bp->blockhashes != 0 )
                iguana_hash2set(coin,"blockhashes[1]",&bp->blockhashes[1],bp->firstblockhash2);
            *bundleip = 1;
            return(bp);
        }
        if ( bp->blockhashes != 0 )
        {
            /*if ( bits256_nonz(bp->lastblockhash2) > 0 )
                iguana_hash2set(coin,"blockhashes[n-1]",&bp->blockhashes[bp->n-1],bp->lastblockhash2);
            else if ( bits256_nonz(bp->blockhashes[bp->n-1]) > 0 )
                iguana_hash2set(coin,"b blockhashes[n-1]",&bp->lastblockhash2,bp->blockhashes[bp->n-1]);
            
            if ( (searchmask & IGUANA_SEARCHNOLAST) == 0 )
            {
                if ( memcmp(hash2.bytes,bp->lastblockhash2.bytes,sizeof(hash2)) == 0 )
                {
                    *bundleip = bp->n - 1;
                    return(bp);
                }
            }*/
  //printf("blockhashes.%p n.%d\n",bp->blockhashes,bp->n);
            for (i=1; i<bp->n && i<coin->chain->bundlesize; i++)
            {
                if ( memcmp(hash2.bytes,bp->blockhashes[i].bytes,sizeof(hash2)) == 0 )
                {
                    *bundleip = i;
                    return(bp);
                }
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
    int32_t i,searchmask; struct iguana_block *block; struct iguana_bundle *bp = 0;
    *bundleip = -2;
    if ( bits256_nonz(hash2) > 0 )
    {
        if ( adjust == 0 )
            searchmask = IGUANA_SEARCHBUNDLE;
        else searchmask = IGUANA_SEARCHNOLAST;
        if ( (block= iguana_blockfind(coin,hash2)) != 0 && (bp= block->bp) != 0 && (bp= iguana_bundlescan(coin,bundleip,bp,hash2,searchmask)) != 0 )
            return(bp);
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

struct iguana_block *iguana_bundleblockadd(struct iguana_info *coin,struct iguana_bundle *bp,int32_t bundlei,bits256 hash2)
{
    struct iguana_block *block =0; struct iguana_bundle *prevbp,*nextbp; int32_t i,nextbundlei; bits256 cmphash2;
    if ( bits256_nonz(hash2) > 0 && (block= iguana_blockhashset(coin,-1,hash2,1)) != 0 )
    {
        if ( bundlei >= coin->chain->bundlesize )
            return(block);
        //printf("iguana_bundleblockadd[%d] %d <- %s\n",bp->hdrsi,bundlei,bits256_str(hash2));
        /*if ( bundlei < bp->n-1 )
        {
            iguana_hash2set(coin,"block bundlehash2",&block->bundlehash2,bp->bundlehash2);
            if ( block->bp != 0 && block->bp != bp )
                printf("bundleblockadd: REPLACE %s.bp %p <- %p\n",bits256_str(block->hash2),block->bp,bp);
            block->bp = bp;
        }*/
        if ( (block->bundlei= bundlei) == 0 )
        {
            iguana_hash2set(coin,"bundlehash2",&bp->bundlehash2,block->hash2);
            //iguana_blockQ(coin,bp,0,bp->bundlehash2,1);
            if ( bp->blockhashes != 0 )
                iguana_hash2set(coin,"blockhashes[0]",&bp->blockhashes[0],bp->bundlehash2);
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
                            iguana_hash2set(coin,"bp setprev",&bp->prevbundlehash2,prevbp->bundlehash2);
                            iguana_hash2set(coin,"prevbp setnext",&prevbp->nextbundlehash2,bp->bundlehash2);
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
            iguana_hash2set(coin,"firstblockhash2",&bp->firstblockhash2,block->hash2);
            if ( bp->blockhashes != 0 )
            {
                if ( bits256_nonz(block->prev_block) > 0 )
                    iguana_hash2set(coin,"b blockhashes[0]",&bp->blockhashes[0],block->prev_block);
                iguana_hash2set(coin,"b blockhashes[1]",&bp->blockhashes[1],block->hash2);
            }
        }
        else if ( bundlei == bp->n-1 )
        {
            if ( (nextbp= iguana_bundlefind(coin,&nextbundlei,hash2,-1)) != 0 )
            {
                if ( nextbundlei == 0 )
                {
                    iguana_hash2set(coin,"bp setnext",&bp->nextbundlehash2,nextbp->bundlehash2);
                    iguana_hash2set(coin,"next setprev",&bp->prevbundlehash2,bp->bundlehash2);
                    printf("next BUNDLES LINKED! (%d <-> %d) (%s <-> %s)\n",bp->bundleheight,nextbp->bundleheight,bits256_str(bp->bundlehash2),bits256_str2(nextbp->bundlehash2));
                    if ( nextbp->bundleheight != bp->bundleheight+coin->chain->bundlesize )
                        printf("WARNING gap in bundleheight %d != %d bundlesize\n",nextbp->bundleheight,bp->bundleheight+coin->chain->bundlesize);
                } else printf("nextbundlei.%d != 0 nextbp->n %d\n",nextbundlei,nextbp->n);
            }
            //iguana_hash2set(coin,"lastblockhash2",&bp->lastblockhash2,block->hash2);
        }
    }
    return(block);
}

struct iguana_bundle *iguana_bundlecreate(struct iguana_info *coin,bits256 bundlehash2,bits256 firstblockhash2)
{
    struct iguana_bundle *bp = 0; int32_t bundlei = -2;
    if ( (bp= iguana_bundlefind(coin,&bundlei,bundlehash2,-1)) != 0 )
    {
        //printf("found bundlehash.%s bundlei.%d bp.%p %d\n",bits256_str(bundlehash2),*bundleip,bp,bp->hdrsi);
        return(bp);
    }
    if ( (bp= iguana_bundlefind(coin,&bundlei,firstblockhash2,-1)) != 0 )
    {
        //printf("found firstblockhash2.%s bundlei.%d bp.%p %d\n",bits256_str(firstblockhash2),*bundleip,hdrs,hdrs->hdrsi);
        return(bp);
    }
    // printf("search miss\n");
    if ( bits256_nonz(bundlehash2) > 0 )
    {
        //coin->bundles = myrealloc('W',coin->bundles,coin->bundles==0?0:coin->numhdrs*sizeof(*coin->bundles),(coin->numhdrs+1)*sizeof(*coin->bundles));
        bp = mycalloc('b',1,sizeof(*bp) + (1+coin->chain->bundlesize)*sizeof(*bp->issued)); //&coin->bundles[coin->numhdrs];
        bp->blocks = mycalloc('b',sizeof(*bp->blocks),(1+coin->chain->bundlesize));
        bp->hdrsi = coin->bundlescount;
        bp->bundlehash2 = bundlehash2;
        bp->coin = coin;
        bp->avetime = coin->avetime * 2.;
        bp->firstblockhash2 = firstblockhash2;
        bp->bundleheight = -1;
        coin->bundles[coin->bundlescount++] = bp;
        printf("alloc.[%d] new hdrs.%s first.%s %p\n",coin->bundlescount,bits256_str(bundlehash2),bits256_str2(firstblockhash2),bp);
        if ( bits256_nonz(bundlehash2) > 0 )
            iguana_blockQ(coin,bp,0,bundlehash2,1);
        if ( bits256_nonz(firstblockhash2) > 0 )
            iguana_blockQ(coin,bp,1,firstblockhash2,1);
        return(bp);
    }
    //else printf("iguana_hdrscreate cant find hdr with %s or %s\n",bits256_str(bundlehash2),bits256_str2(firstblockhash2));
    return(0);
}

struct iguana_block *iguana_recvblockhdr(struct iguana_info *coin,struct iguana_bundle **bpp,int32_t *bundleip,struct iguana_block *block,int32_t *newhwmp)
{
    struct iguana_bundle *prevbp,*bp = 0; int32_t j,prevbundlei; bits256 orighash2 = block->hash2;
    (*bpp) = 0;
    *bundleip = -2;
    if ( (block= iguana_blockhashset(coin,-1,block->hash2,1)) == 0 )
    {
        printf("error getting block for %s\n",bits256_str(orighash2));
        return(0);
    }
    if ( (bp= iguana_bundlefind(coin,bundleip,block->hash2,-1)) == 0 )
    {
        if ( (prevbp= iguana_bundlefind(coin,&prevbundlei,block->prev_block,-1)) == 0 )
        {
            for (j=0; j<coin->bundlescount; j++)
            {
                if ( (bp= coin->bundles[j]) != 0 )
                {
                    if ( (bp= iguana_bundlescan(coin,bundleip,bp,block->hash2,IGUANA_SEARCHNOLAST)) != 0 )
                    {
                        (*bpp) = bp;
                        printf("FOUND.%s in bundle.[%d:%d] %d\n",bits256_str(block->hash2),bp->hdrsi,*bundleip,bp->bundleheight + *bundleip);
                        iguana_bundleblockadd(coin,bp,*bundleip,block->hash2);
                        return(block);
                    }
                }
            }
            printf("CANTFIND.%s\n",bits256_str(block->hash2));
            return(block);
        }
        else
        {
            (*bpp) = bp;
            if ( prevbundlei >= 0 && prevbundlei < bp->n-1 )
            {
                *bundleip = prevbundlei + 1;
                printf("prev FOUND.%s in bundle.[%d:%d] %d\n",bits256_str(block->hash2),bp->hdrsi,*bundleip,bp->bundleheight + *bundleip);
                iguana_bundleblockadd(coin,bp,*bundleip,block->hash2);
            }
            if ( prevbundlei == coin->chain->bundlesize-1 )
            {
                printf("prev AUTOCREATE.%s\n",bits256_str(block->hash2));
                iguana_bundlecreate(coin,block->hash2,bits256_zero);
            }
            return(block);
        }
    }
    else
    {
        (*bpp) = bp;
        //printf("blockadd.%s %s %d\n",bits256_str(block->hash2),bits256_str2(orighash2),*bundleip);
        iguana_bundleblockadd(coin,bp,*bundleip,block->hash2);
        if ( *bundleip > 0 && bits256_nonz(block->prev_block) > 0 )
            iguana_bundleblockadd(coin,bp,(*bundleip) - 1,block->prev_block);
    }
    return(block);
}

struct iguana_bundlereq *iguana_recvblockhashes(struct iguana_info *coin,struct iguana_bundlereq *req,bits256 *blockhashes,int32_t num)
{
    struct iguana_bundle *bp; int32_t i,j,missing,bundlei = -2,bundleheight = -1;
    if ( (bp= iguana_bundlefind(coin,&bundlei,blockhashes[1],-1)) != 0 )
    {
        if ( bp->blockhashes == 0 )
        {
            bundleheight = bp->bundleheight;
            if ( num > coin->chain->bundlesize+1 )
            {
                bp->blockhashes = mycalloc('h',coin->chain->bundlesize+1,sizeof(*blockhashes));
                memcpy(bp->blockhashes,blockhashes,(coin->chain->bundlesize+1) * sizeof(*blockhashes));
                num = coin->chain->bundlesize+1;
            } else bp->blockhashes = req->hashes, req->hashes = 0;
            //printf("GOT blockhashes.%s[%d] %d %p hdrsi.%d\n",bits256_str(blockhashes[1]),num,bundleheight,bp->blockhashes,bp->hdrsi);
            bp->n = num;
            bp->bundleheight = bundleheight;
            if ( bundlei >= 0 && bundlei < bp->n )
            {
                j = 1;
                if ( bundlei != 1 )
                    printf(">>>>>>>>> %s bundlei.%d j.%d\n",bits256_str(blockhashes[1]),bundlei,j);
                for (i=bundlei; i<bp->n&&j<bp->n&&i<coin->chain->bundlesize; i++,j++)
                    iguana_bundleblockadd(coin,bp,i,blockhashes[j]);
            }
            iguana_blockQ(coin,bp,1,blockhashes[1],0);
            if ( bp->n < coin->chain->bundlesize )
                iguana_blockQ(coin,bp,bp->n-1,blockhashes[bp->n-1],0);
            else iguana_blockQ(coin,bp,coin->chain->bundlesize-1,blockhashes[coin->chain->bundlesize-1],0);
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
                    //printf("GOT MISMATCHED %d blockhashes.%s[%d] missing.%d of %d\n",bp->bundleheight,bits256_str(blockhashes[1]),num,missing,bp->n);
                    return(req);
                }
                if ( num > bp->n && bp->n <= coin->chain->bundlesize )
                {
                    /*myfree(bp->blockhashes,sizeof(*bp->blockhashes) * bp->n);
                     bp->blockhashes = mycalloc('h',num,sizeof(*blockhashes));
                     printf("replace blockhashes.%s[%d] %d %p\n",bits256_str(blockhashes[0]),num,bp->bundleheight,bp->blockhashes);
                     memcpy(bp->blockhashes,blockhashes,num * sizeof(*blockhashes));
                     i = bp->n, bp->n = num;
                     for (; i<num; i++)
                     iguana_bundleblockadd(coin,bp,i,blockhashes[i]);*/
                    return(req);
                }
                if ( bp->bundleheight >= 0 && (rand() % 1000) == 0 )
                    printf("GOT duplicate.%s[%d] bheight.%d\n",bits256_str(blockhashes[1]),num,bp->bundleheight);
            }
        }
        if ( (num= bp->n) > coin->chain->bundlesize )
            num = coin->chain->bundlesize;
    }
    else
    {
        if ( num > coin->chain->bundlesize+1 )
            num = coin->chain->bundlesize+1;
        for (i=1; i<num; i++)
            iguana_blockhashset(coin,-1,blockhashes[i],1);
        if ( num > 2 )
        {
            printf("recvblockhashes cant find %s num.%d\n",bits256_str(blockhashes[1]),num);
            iguana_bundlecreate(coin,blockhashes[1],blockhashes[2]);
            if ( 0 && num == coin->chain->bundlesize+1 && iguana_bundlefind(coin,&bundlei,blockhashes[num - 1],0) == 0 )
            {
                printf("AUTO EXTEND2.%s[%d]\n",bits256_str(blockhashes[num - 1]),num);
                iguana_bundlecreate(coin,blockhashes[num - 1],bits256_zero);
            }
        }
    }
    return(req);
}

void iguana_copyblock(struct iguana_info *coin,struct iguana_block *block,struct iguana_block *origblock)
{
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

struct iguana_bundlereq *iguana_recvblockhdrs(struct iguana_info *coin,struct iguana_bundlereq *req,struct iguana_block *blocks,int32_t n,int32_t *newhwmp)
{
    int32_t i,j; struct iguana_block *block; struct iguana_bundle *bp; bits256 *blockhashes;
    if ( blocks == 0 )
        return(req);
    if ( n > coin->chain->bundlesize+1 )
        n = coin->chain->bundlesize+1;
    blockhashes = mycalloc('h',n+1,sizeof(*blockhashes));
    blockhashes[0] = blocks->prev_block;
    for (i=0; i<n; i++)
        blockhashes[i+1] = blocks[i].hash2;
    n++;
    for (j=0; j<coin->bundlescount; j++)
    {
        if ( (bp= coin->bundles[j]) != 0 )
        {
            if ( memcmp(blocks[0].prev_block.bytes,bp->bundlehash2.bytes,sizeof(bits256)) == 0 )
            {
                iguana_hash2set(coin,"blockhdrs[1]",&bp->firstblockhash2,blocks[0].hash2);
                if ( bp->blockhashes == 0 )
                {
                    bp->blockhashes = blockhashes;
                    bp->n = n;
                    for (i=1; i<n; i++)
                        if ( (block= iguana_blockfind(coin,blockhashes[i])) != 0 )
                            iguana_copyblock(coin,block,&blocks[i-1]);
                    iguana_blockQ(coin,bp,0,bp->bundlehash2,0);
                    iguana_blockQ(coin,bp,1,blockhashes[1],0);
                    if ( bp->n < coin->chain->bundlesize )
                        iguana_blockQ(coin,bp,n-1,blockhashes[n-1],0);
                    else iguana_blockQ(coin,bp,coin->chain->bundlesize-1,blockhashes[coin->chain->bundlesize-1],0);
                    break;
                }
                else
                {
                    //printf("free duplicate blockhashes\n");
                    myfree(blockhashes,n*sizeof(*blockhashes));
                }
            }
        }
    }
    return(req);
}

void iguana_gotdata(struct iguana_info *coin,struct iguana_peer *addr,int32_t height,bits256 hash2)
{
    if ( addr != 0 && height > addr->height && height < coin->longestchain )
    {
        iguana_set_iAddrheight(coin,addr->ipbits,height);
        addr->height = height;
    }
}

struct iguana_bundlereq *iguana_recvblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_bundlereq *req,struct iguana_block *origblock,int32_t numtx,uint8_t *data,int32_t datalen,int32_t *newhwmp)
{
    struct iguana_bundle *bp; struct iguana_bundlereq *txdata; int32_t bundlei; struct iguana_block *block; double duration = 0.;
    if ( (block= iguana_recvblockhdr(coin,&bp,&bundlei,origblock,newhwmp)) != 0 )
    {
        iguana_copyblock(coin,block,origblock);
        //printf("iguana_recvblock (%s) %d[%d] bit.%d recv.%d %02x %02x\n",bits256_str(block->hash2),bp->hdrsi,bundlei,GETBIT(bp->recv,bundlei),bp->numrecv,bp->recv[0],bp->recv[bp->n/8]);
        if ( bp != 0 && data != 0 && datalen > 0 )
        {
            //printf("iguana_recvblock (%s) %d[%d] bit.%d recv.%d %02x %02x\n",bits256_str(block->hash2),bp->hdrsi,bundlei,GETBIT(bp->recv,bundlei),bp->numrecv,bp->recv[0],bp->recv[bp->n/8]);
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
            if ( bundlei == 1 )
                iguana_blockQ(coin,bp,0,block->prev_block,0);
            if ( (txdata= block->txdata) == 0 )
            {
                if ( bundlei >= 0 && bundlei < bp->n && bundlei < coin->chain->bundlesize )
                {
                    bp->blocks[bundlei] = block;
                    block->datalen = req->datalen;
                    bp->numrecv++;
                }
                req->datalen = datalen;
                req->argbp = bp, req->argbundlei = bundlei;
                req->type = 'Q';
                iguana_txdataQ(coin,req);
                block->txdata = (void *)"submitted to helperQ";
                req = 0;
            }
            else
            {
                if ( (req->datalen != txdata->datalen || memcmp(txdata->serialized,req->serialized,txdata->datalen) != 0) && (rand() % 1000) == 0 )
                    printf("data compare error.(%d %d)\n",req->datalen,txdata->datalen);
                if ( (rand() % 1000) == 0 )
                    printf("got duplicate block %s\n",bits256_str(block->hash2));
            }
            //printf("%s hdrsi.%d recv[%d] dur.%.0f avetimes.(%.2f %.2f) numpendinds.%d %f\n",bits256_str(block->hash2),hdrs->hdrsi,bundlei,duration,hdrs->avetime,coin->avetime,coin->numpendings,hdrs->issued[bundlei]);
        }
    }
    else //if ( (rand() % 100) == 0 )
        printf("cant create block.%s\n",bits256_str(origblock->hash2));
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
    while ( (req= queue_dequeue(&coin->bundlesQ,0)) != 0 && flag < 100 )
    {
        //printf("%s bundlesQ.%p type.%c n.%d\n",req->addr != 0 ? req->addr->ipaddr : "0",req,req->type,req->n);
        if ( req->type == 'B' ) // one block with all txdata
        {
            if ( (req= iguana_recvblock(coin,req->addr,req,req->blocks,req->numtx,req->serialized,req->n,newhwmp)) != 0 && req->blocks != 0 )
                myfree(req->blocks,sizeof(*req->blocks));
        }
        else if ( req->type == 'H' ) // blockhdrs (doesnt have txn_count!)
        {
            if ( (req= iguana_recvblockhdrs(coin,req,req->blocks,req->n,newhwmp)) != 0 )
                myfree(req->blocks,sizeof(*req->blocks) * req->n);
        }
        else if ( req->type == 'S' ) // blockhashes
        {
            if ( (req= iguana_recvblockhashes(coin,req,req->hashes,req->n)) != 0 && req->hashes != 0 )
                myfree(req->hashes,sizeof(*req->hashes) * req->n);
        }
        else if ( req->type == 'U' ) // unconfirmed tx
            req = iguana_recvunconfirmed(coin,req,req->serialized,req->n);
        else if ( req->type == 'T' ) // txids from inv
        {
            if ( (req= iguana_recvtxids(coin,req,req->hashes,req->n)) != 0 )
                myfree(req->hashes,(req->n+1) * sizeof(*req->hashes));
        }
        else printf("iguana_updatebundles unknown type.%c\n",req->type);
        flag++;
        if ( req != 0 )
            myfree(req,req->allocsize), req = 0;
    }
    return(flag);
}

char *iguana_bundledisp(struct iguana_info *coin,struct iguana_bundle *prevbp,struct iguana_bundle *bp,struct iguana_bundle *nextbp,int32_t m)
{
    static char line[1024];
    line[0] = 0;
    if ( bp == 0 )
        return(line);
    if ( prevbp != 0 )
    {
        if ( memcmp(prevbp->bundlehash2.bytes,bp->prevbundlehash2.bytes,sizeof(bits256)) == 0 )
        {
            if ( memcmp(prevbp->nextbundlehash2.bytes,bp->bundlehash2.bytes,sizeof(bits256)) == 0 )
                sprintf(line+strlen(line),"<->");
            else sprintf(line+strlen(line),"<-");
        }
        else if ( memcmp(prevbp->nextbundlehash2.bytes,bp->bundlehash2.bytes,sizeof(bits256)) == 0 )
            sprintf(line+strlen(line),"->");
    }
    sprintf(line+strlen(line),"(%d:%d)",bp->hdrsi,m);
    if ( nextbp != 0 )
    {
        if ( memcmp(nextbp->bundlehash2.bytes,bp->nextbundlehash2.bytes,sizeof(bits256)) == 0 )
        {
            if ( memcmp(nextbp->prevbundlehash2.bytes,bp->bundlehash2.bytes,sizeof(bits256)) == 0 )
                sprintf(line+strlen(line),"<->");
            else sprintf(line+strlen(line),"->");
        }
        else if ( memcmp(nextbp->prevbundlehash2.bytes,bp->bundlehash2.bytes,sizeof(bits256)) == 0 )
            sprintf(line+strlen(line),"<-");
    }
    return(line);
}

int32_t iguana_bundlecheck(struct iguana_info *coin,struct iguana_bundle *bp,int32_t priorityflag)
{
    int32_t i,qsize,n = 0; struct iguana_block *block; bits256 hash2; double threshold; uint64_t datasize =0;
    //printf("bp.%p bundlecheck.%d emit.%d\n",bp,bp->hdrsi,bp->emitfinish);
    if ( bp != 0 && bp->emitfinish == 0 )
    {
        qsize = queue_size(&coin->priorityQ);
        if ( bp->numrecv > coin->chain->bundlesize*.98 )
        {
            priorityflag = 1;
            if ( bp->numrecv > coin->chain->bundlesize-3 )
                threshold = bp->avetime;
            else threshold = bp->avetime * 2;
        } else threshold = bp->avetime * 5;
        for (i=0; i<coin->chain->bundlesize; i++)
        {
            hash2 = iguana_bundleihash2(coin,bp,i);
            if ( bits256_nonz(hash2) == 0 )
                continue;
            if ( (block= bp->blocks[i]) == 0 )
                block = bp->blocks[i] = iguana_blockfind(coin,hash2);
            if ( block != 0 && block->txdata != 0 )
            {
                datasize += block->datalen;
                if ( bits256_nonz(block->bundlehash2) == 0 )
                {
                    iguana_hash2set(coin,"bundlecheck",&block->bundlehash2,bp->bundlehash2);
                    block->bp = bp;
                }
                n++;
            }
            else if ( priorityflag != 0 && (bp->issued[i] == 0 || milliseconds() > (bp->issued[i] + threshold)) )
            {
                if ( (rand() % 1000) == 0 )
                    printf("priorityQ submit threshold %.3f [%d].%d\n",threshold,bp->hdrsi,i);
                CLEARBIT(bp->recv,i);
                bp->issued[i] = milliseconds();
                iguana_blockQ(coin,bp,i,hash2,1);
                bp->blocks[i] = 0;
            }
        }
        bp->numrecv = n;
        bp->datasize = datasize;
        bp->estsize = (datasize * n) / coin->chain->bundlesize;
        if ( n == coin->chain->bundlesize )
        {
            //printf("check %d blocks in hdrs.%d\n",n,bp->hdrsi);
            for (i=0; i<n-1; i++)
            {
                if ( memcmp(bp->blocks[i]->hash2.bytes,bp->blocks[i+1]->prev_block.bytes,sizeof(bits256)) != 0 )
                {
                    printf("%s -> ",bits256_str(bp->blocks[i]->hash2));
                    printf("<- %s %s ",bits256_str(bp->blocks[i+1]->prev_block),bits256_str2(bp->blocks[i+1]->hash2));
                    printf("broken chain in hdrs.%d %d %p <-> %p %d\n",bp->hdrsi,i,bp->blocks[i],bp->blocks[i+1],i+1);
                    break;
                }
            }
            if ( i == n-1 )
            {
                if ( bp->blockhashes != 0 )
                {
                    for (i=0; i<n; i++)
                        iguana_hash2set(coin,"check blocks",&bp->blockhashes[i],bp->blocks[i]->hash2);
                    iguana_hash2set(coin,"check bundlehash2",&bp->blockhashes[0],bp->bundlehash2);
                    iguana_hash2set(coin,"check firsthash2",&bp->blockhashes[1],bp->firstblockhash2);
                    //iguana_hash2set(coin,"check lastthash2",&bp->blockhashes[bp->n-1],bp->lastblockhash2);
                }
                iguana_bundleblockadd(coin,bp,0,iguana_bundleihash2(coin,bp,0));
                iguana_bundleblockadd(coin,bp,coin->chain->bundlesize-1,iguana_bundleihash2(coin,bp,coin->chain->bundlesize-1));
                if ( 0 )
                {
                    for (i=n=0; i<bp->n&&i<coin->chain->bundlesize; i++)
                    {
                        if ( bp->blocks[i] == 0 || bp->blocks[i]->txdata == 0 )
                            printf("-%d ",i), n++;
                        else printf("%d ",bp->blocks[i]->txn_count);
                    }
                    printf("missing blocks/txdata %d %d\n",n,bp->n+1);
                }
                //printf("iguana_bundlecheck.%d complete recv.%d/%d\n",bp->hdrsi,bp->numrecv,bp->n);
                iguana_emitQ(coin,bp);
                bp->emitfinish = (uint32_t)time(NULL);
                //bp = myrealloc('b',bp,sizeof(*bp) + (1+coin->chain->bundlesize)*sizeof(*bp->issued),sizeof(*bp));
                coin->numpendings--;
                return(1);
            }
        }
    }
    return(0);
}

int32_t iguana_issueloop(struct iguana_info *coin)
{
    static uint32_t lastdisp;
    int32_t i,closest,closestbundle,bundlei,qsize,m,numactive,numwaiting,maxwaiting,lastbundle,n,dispflag = 0,flag = 0;
    struct iguana_bundle *bp,*prevbp,*nextbp; bits256 hash2;
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
    if ( time(NULL) < coin->lastbundletime+15 )
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
                iguana_bundlecheck(coin,bp,numactive < coin->MAXPENDING/2 || i == coin->closestbundle || i == lastbundle);
                if ( bp->numrecv > closest && bp->numrecv < coin->chain->bundlesize )
                {
                    closest = bp->numrecv;
                    closestbundle = i;
                }
                if ( bp->numrecv > 3 )
                    numactive++;
                if ( i != lastbundle && i != coin->closestbundle && numwaiting >= maxwaiting && numactive > coin->MAXBUNDLES )
                    continue;
                    for (bundlei=0; bundlei<bp->n && bundlei<coin->chain->bundlesize; bundlei++)
                {
                    if ( iguana_bundletxdata(coin,bp,bundlei) != 0 )
                    {
                        m++;
                        //printf("hashes.%p numrecv.%d hdrs->n.%d qsize.%d\n",bp->blockhashes,bp->numrecv,bp->n,qsize);
                        continue;
                    }
                    hash2 = iguana_bundleihash2(coin,bp,bundlei);
                    if ( bits256_nonz(hash2) > 0 )
                    {
                        //printf("hdrsi.%d qsize.%d bcount.%d check bundlei.%d bit.%d %.3f lag %.3f ave %.3f\n",bp->hdrsi,qsize,coin->bcount,bundlei,GETBIT(bp->recv,bundlei),bp->issued[bundlei],milliseconds() - bp->issued[bundlei],bp->avetime);
                        if ( GETBIT(bp->recv,bundlei) == 0 )
                        {
                            if ( bp->issued[bundlei] > SMALLVAL )
                                numwaiting++;
                            if ( bp->issued[bundlei] == 0 || (qsize == 0 && coin->bcount > 100 && milliseconds() > (bp->issued[bundlei] + bp->avetime*2)) )
                            {
                                if ( i == lastbundle || i == coin->closestbundle || numwaiting < maxwaiting || numactive <= coin->MAXBUNDLES )
                                {
                                    if ( (rand() % 1000) == 0 && bp->issued[bundlei] > SMALLVAL )
                                        printf("issue.%d:%d of %d %s lag %f ave %f\n",bp->hdrsi,bundlei,bp->n,bits256_str(hash2),milliseconds() - bp->issued[bundlei],bp->avetime);
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
        if ( dispflag != 0 && bp != 0 && bp->numrecv > 3 && bp->emitfinish == 0 )
            printf("%s",iguana_bundledisp(coin,prevbp,bp,nextbp,m));
    }
    coin->closestbundle = closestbundle;
    if ( dispflag != 0 )
        printf(" PENDINGBUNDLES lastbundle.%d closest.[%d] %d\n",lastbundle,closestbundle,closest);
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
                            printf("(%s %d).%d ",bits256_str(bp->bundlehash2),bp->bundleheight,i);
                            init_hexbytes_noT(hashstr,bp->bundlehash2.bytes,sizeof(bits256));
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

void iguana_bundlestats(struct iguana_info *coin,char *str)
{
    int32_t i,j,bundlei,numbundles,numdone,numrecv,numhashes,numissued,numemit,numactive,flag;
    struct iguana_bundle *bp; bits256 hash2; int64_t estsize = 0;
    numbundles = numdone = numrecv = numhashes = numissued = numemit = numactive = 0;
    for (i=0; i<coin->bundlescount; i++)
    {
        if ( (bp= coin->bundles[i]) != 0 )
        {
            if ( bp->emitfinish != 0 )
                numemit++, numbundles++, numdone++, numhashes += (bp->n + 1), numissued += (bp->n + 1), numrecv += (bp->n + 1);
            else if ( bp->blockhashes != 0 )
            {
                numbundles++;
                if ( bp->numrecv > bp->n || bp->emitfinish != 0 )
                    numdone++, numhashes += (bp->n + 1), numissued += (bp->n + 1), numrecv += (bp->n + 1);
                else
                {
                    flag = 0;
                    for (j=0; j<bp->n&&j<coin->chain->bundlesize; j++)
                    {
                        bundlei = j;
                        hash2 = iguana_bundleihash2(coin,bp,bundlei);
                        if ( bits256_nonz(hash2) > 0 )
                        {
                            numhashes++;
                            if ( bp->issued[bundlei] > SMALLVAL )
                            {
                                numissued++;
                                if ( GETBIT(bp->recv,bundlei) != 0 )
                                {
                                    flag++;
                                    numrecv++;
                                }
                            }
                        }
                    }
                    if ( flag > 3 )
                    {
                        estsize += bp->estsize;
                        numactive++;
                    }
                }
            }
        }
    }
    sprintf(str,"N[%d] d.%d p.%d g.%d A.%d h.%d i.%d r.%d E.%d:%d long.%d est.%d %s",coin->bundlescount,numdone,coin->numpendings,numbundles,numactive,numhashes,numissued,numrecv,numemit,coin->numemitted,coin->longestchain,coin->MAXBUNDLES,mbstr(estsize));
    coin->activebundles = numactive;
    coin->estsize = estsize;
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
