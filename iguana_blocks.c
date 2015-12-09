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
    HASH_ITER(hh,coin->blockshash,block,tmp)
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
    HASH_SORT(coin->blockshash,_sort_by_itemind);
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

struct iguana_block *iguana_blockhashset(struct iguana_info *coin,int32_t height,bits256 hash2,struct iguana_bundle *bp)
{
    struct iguana_block *block; int32_t i;
    portable_mutex_lock(&coin->blocks_mutex);
    HASH_FIND(hh,coin->blockshash,hash2.bytes,sizeof(hash2),block);
    if ( block != 0 )
    {
        //printf("found.%s -> %d %p bundle.%p vs %p inputht.%d\n",bits256_str(hash2),block->hh.itemind,block,block->bundle,bp,height);
        if ( height < 0 || block->hh.itemind == height )
        {
            if ( (int32_t)block->hh.itemind < 0 )
            {
                //printf("found.%s -> %d %p bundle.%p vs %p set height.%d matches.%d\n",bits256_str(hash2),block->hh.itemind,block,block->bundle,bp,height,block->matches);
                if ( height >= 0 && block->matches == 0 )
                    block->hh.itemind = height, block->matches = 1;
                else block = 0;
            }
            else if ( block->bundle == 0 && bp != 0 )
            {
                //printf("set.%s bp <- %p\n",bits256_str(hash2),bp);
                block->bundle = bp;
            }
            else if ( block->bundle != 0 && bp != 0 && block->bundle != bp )
            {
                printf("warning: override %s bundle.%p[%d] with %p[%d]\n",bits256_str(hash2),block->bundle,block->bundle->bundlei,bp,bp->bundlei);
                block->bundle = bp;
                getchar();
            }
            if ( block != 0 )
            {
                if ( block->matches < 100 )
                    block->matches++;
                _iguana_blocklink(coin,block);
            }
        }
        else if ( block->matches == 0 && block->hh.itemind == (uint32_t)-1 )
        {
            if ( height >= 0 )
            {
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
            printf("collision with (%s) itemind.%d vs %d | matches.%d\n",bits256_str(hash2),block->hh.itemind,height,block->matches);
            if ( block->matches < 3 )
            {
                block->matches = 0;
                block->hh.itemind = -1;
                for (i=0; i<10; i++)
                    iguana_queueblock(coin,-1,block->hash2,1);
                block = 0;
                coin->blocks.recvblocks = 0;
            }
        }
        portable_mutex_unlock(&coin->blocks_mutex);
        return(block);
    }
    if ( height >= 0 )
    {
        block = mycalloc('y',1,sizeof(*block));
        block->hash2 = hash2;
        block->hh.itemind = height, block->height = -1;
        block->matches = 1;
        coin->blocks.ptrs[height] = block;
        HASH_ADD(hh,coin->blockshash,hash2,sizeof(hash2),block);
        _iguana_blocklink(coin,block);
        {
            struct iguana_block *tmp;
            HASH_FIND(hh,coin->blockshash,hash2.bytes,sizeof(hash2),tmp);
            if ( tmp != block )
                printf("%s height.%d search error %p != %p\n",bits256_str(hash2),height,block,tmp);
            //else printf("added.(%s) height.%d %p\n",bits256_str(hash2),height,block);
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
        else printf("iguana_blockhash: height mismatch %u != %u\n",height,block->height);
    }
    return(hash2);
}

bits256 iguana_prevblockhash(struct iguana_info *coin,bits256 hash2)
{
    struct iguana_block *block; bits256 tmp;
    if ( bits256_nonz(hash2) > 0 && (block= iguana_blockfind(coin,hash2)) != 0 )
        return(block->prev_block);
    else
    {
        memset(tmp.bytes,0,sizeof(tmp));
        return(tmp);
    }
}

int32_t iguana_blockheight(struct iguana_info *coin,bits256 hash2)
{
    struct iguana_block *block;
    if ( (block= iguana_blockfind(coin,hash2)) != 0 )
        return(block->hh.itemind);
    else return(-1);
}

int32_t iguana_havehash(struct iguana_info *coin,int32_t height)
{
    struct iguana_block *block;
    if ( (block= iguana_block(coin,height)) != 0 && bits256_nonz(block->hash2) > 0 )
        return(1);
    else return(0);
}

/*int32_t iguana_fixblocks(struct iguana_info *coin,int32_t startheight,int32_t endheight)
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
