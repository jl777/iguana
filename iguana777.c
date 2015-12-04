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

struct iguana_block *iguana_block(struct iguana_info *coin,struct iguana_block *space,int32_t height)
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
}

void iguana_gotdata(struct iguana_info *coin,struct iguana_peer *addr,uint32_t height,bits256 hash2)
{
    if ( height > coin->R.topheight && memcmp(bits256_zero.bytes,hash2.bytes,sizeof(bits256_zero)) != 0 )
    {
        coin->R.tophash2 = hash2;
        coin->R.topheight = height;
    }
    if ( height > coin->longestchain )
        coin->longestchain = height;
    if ( addr != 0 && height > addr->height )
    {
        iguana_set_iAddrheight(coin,addr->ipbits,height);
        addr->height = height;
    }
}

double PoW_from_compact(uint32_t nBits) // NOT consensus safe, but most of the time will be correct
{
	uint32_t nbytes,nbits,i,n; double PoW;
    nbytes = (nBits >> 24) & 0xFF;
    nbits = (8 * (nbytes - 3));
    PoW = nBits & 0xFFFFFF;
    if ( nbytes > 0x1d )
    {
        printf("illegal nBits.%x\n",nBits);
        return(0.);
    }
    if ( (n= ((8* (0x1d-3)) - nbits)) != 0 ) // 0x1d00ffff is genesis nBits so we map that to 1.
    {
        if ( n < 64 )
            PoW /= (1LL << n);
        else // very rare case efficiency not issue
        {
            for (i=0; i<n; i++)
                PoW /= 2.;
        }
    }
    PoW /=  0xffff;
    //printf("nBits.%x -> %.15f diff %.15f | n.%d\n",nBits,PoW,1./PoW,n);
    return(PoW);
}

int32_t iguana_setchainvars(struct iguana_info *coin,uint32_t *firsttxidindp,uint32_t *firstvoutp,uint32_t *firstvinp,double *PoWp,bits256 hash2,uint32_t nBits,bits256 prevhash,int32_t txn_count)
{
    int32_t height,firstvout=0,firstvin=0,firsttxidind=0; double PoW; struct iguana_block prevspace,*prev;
    *PoWp = *firsttxidindp = *firstvoutp = *firstvinp = 0;
    if ( memcmp(coin->chain->genesis_hashdata,hash2.bytes,sizeof(hash2)) == 0 )
    {
        PoW = PoW_from_compact(nBits);
        height = 0;
        firsttxidind = firstvout = firstvin = 1;
        printf("set genesis vars nBits.%x\n",nBits);
    }
    else
    {
        if ( (prev= iguana_findblock(coin,&prevspace,prevhash)) == 0 )
        {
            //if ( iguana_needhdrs(coin) == 0 )
            {
                printf("hash2.(%s) ",bits256_str(hash2));
                fprintf(stderr,"iguana_blockchain no prev block.(%s)\n",bits256_str(prevhash));
                //getchar();
            }
            return(-1);
        }
        else
        {
            height = prev->height + 1;
            PoW = (PoW_from_compact(nBits) + prev->L.PoW);
            if ( txn_count > 0 )
            {
                if ( prev->txn_count > 0 && prev->L.numtxids > 0 )
                    firsttxidind = prev->L.numtxids + prev->txn_count;
                if ( prev->numvouts > 0 && prev->L.numtxids > 0 )
                    firstvout = prev->L.numunspents + prev->numvouts;
                if ( prev->L.numspends > 0 )
                    firstvin = prev->L.numspends + prev->numvins;
                //printf("PREV.%d firsttxidind.%d firstvout.%d+%d firstvin.%d+%d (%d %d %d)\n",prev->height,prev->L.numtxids,prev->L.numunspents,prev->numvouts,prev->L.numspends,prev->numvins,firsttxidind,firstvout,firstvin);
            } //else printf("null txn_count in block.%d\n",height);
            //printf("txn.%d prev.(%d %f txn.%d) ",txn_count,prev->height,prev->PoW,prev->txn_count);
            //printf("prev.%d 1st %d + prev txn.%d %f -> %d\n",prev->height,prev->firsttxidind,prev->txn_count,prev->PoW,firsttxidind);
        }
    }
    *PoWp = PoW;
    *firsttxidindp = firsttxidind;
    *firstvoutp = firstvout;
    *firstvinp = firstvin;
    //printf("set height.%d: %d %f firstvin.%d firstvout.%d\n",height,firsttxidind,PoW,firstvin,firstvout);
    return(height);
}

int32_t iguana_setdependencies(struct iguana_info *coin,struct iguana_block *block)
{
    int32_t h,height = block->height;
    if ( (h= iguana_setchainvars(coin,&block->L.numtxids,&block->L.numunspents,&block->L.numspends,&block->L.PoW,block->hash2,block->bits,block->prev_block,block->txn_count)) == height )
    {
        // place to make sure connected to ramchain
        return(height);
    }
    if ( height == 0 )
        block->height = h;
    //printf("dependencies returned %d vs %d\n",h,height);
    return(h);
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
    tmpA.numvouts = tmpA.numvins = tmpA.tbd = tmpB.numvouts = tmpB.numvins = tmpB.tbd = 0;
    if ( memcmp(&tmpA,&tmpB,sizeof(tmpA)) != 0 )
        return(-1);
    if ( fastflag == 0 )
    {
        if ( iguana_setdependencies(coin,&tmpA) != iguana_setdependencies(coin,&tmpB) || memcmp(&tmpA,&tmpB,sizeof(tmpA)) == 0 )
            return(-1);
    }
    return(0);
}

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

bits256 iguana_blockhash(struct iguana_info *coin,int32_t height)
{
    struct iguana_block *block,space; bits256 hash2; uint8_t serialized[sizeof(struct iguana_msgblock)];
    memset(hash2.bytes,0,sizeof(hash2));
    if ( (block= iguana_block(coin,&space,height)) != 0 )
    {
        if ( block->height == height )
            iguana_serialize_block(&hash2,serialized,block);
        else printf("iguana_blockhash: height mismatch %u != %u\n",height,block->height);
    }
    return(hash2);
}

bits256 iguana_prevblockhash(struct iguana_info *coin,bits256 hash2)
{
    struct iguana_block *block,space; bits256 tmp;
    if ( (block= iguana_findblock(coin,&space,hash2)) != 0 )
        return(block->prev_block);
    else
    {
        memset(tmp.bytes,0,sizeof(tmp));
        return(tmp);
    }
}

int32_t iguana_height(struct iguana_info *coin,bits256 hash2)
{
    struct iguana_block *block,space;
    if ( bits256_nonz(hash2) > 0 && (block= iguana_findblock(coin,&space,hash2)) != 0 )
        return(block->height);
    else return(-1);
}

int32_t iguana_numblocks(struct iguana_info *coin) { return(coin->blocks.hwmheight + 1); }

int32_t iguana_checkblock(struct iguana_info *coin,int32_t dispflag,struct iguana_block *block,bits256 hash2)
{
    struct iguana_block checkspace,prevspace,*checkblock,*prev; bits256 prevhash; int32_t retval = 0;
    if ( block != 0 )
    {
        /*if ( block->txn_count == 0 )
        {
            if ( dispflag != 0 )
                printf("%s h.%d no txn_count\n",bits256_str(hash2),block->height);
            return(-1);
        }*/
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
        if ( (prev= iguana_findblock(coin,&prevspace,prevhash)) == 0 )
        {
            if ( dispflag != 0 )
                printf("cant find prevhash for (%s).%d\n",bits256_str(hash2),block->height);
            return(-5);
        } //else printf("block->height.%d prev height.%d %s\n",block->height,prev->height,bits256_str(prevhash));
        if ( fabs(block->L.PoW - (prev->L.PoW + PoW_from_compact(block->bits))) > SMALLVAL )
        {
            if ( dispflag != 0 )
                printf("PoW mismatch: %s %.15f != %.15f (%.15f %.15f)\n",bits256_str(hash2),block->L.PoW,(prev->L.PoW + PoW_from_compact(block->bits)),prev->L.PoW,PoW_from_compact(block->bits));
            block->L.PoW = (prev->L.PoW + PoW_from_compact(block->bits));
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
    while ( (block= iguana_findblock(coin,&space,hash2)) != 0 )
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
}

int32_t iguana_queueblock(struct iguana_info *coin,int32_t height,bits256 hash2)
{
    queue_t *Q; char *str,hashstr[sizeof(bits256)*32 + 1];
    if ( height != iguana_height(coin,hash2) )
    {
        printf("mismatched height.%d for %s %d\n",height,bits256_str(hash2),iguana_height(coin,hash2));
        return(0);
    }
    if ( height >= coin->blocks.parsedblocks && coin->R.recvblocks[height] == 0 && GETBIT(coin->R.waitingbits,height) == 0 )
    {
        init_hexbytes_noT(hashstr,hash2.bytes,sizeof(hash2));
        if ( height < coin->blocks.parsedblocks+10 )
            str = "priorityQ", Q = &coin->priorityQ;
        else str = "blocksQ", Q = &coin->blocksQ;
        queue_enqueue(str,Q,queueitem(hashstr),1);
        iguana_setwaitstart(coin,height);
        return(1);
    } else printf("iguana_queueblock skip.%d %s parsed.%d %p GETBIT.%d\n",height,bits256_str(hash2),coin->blocks.parsedblocks,coin->R.recvblocks[height],GETBIT(coin->R.waitingbits,height));
    return(0);
}

int32_t iguana_addblock(struct iguana_info *coin,bits256 hash2,struct iguana_block *newblock)
{
    int32_t h;
    if ( (newblock->height= iguana_setdependencies(coin,newblock)) >= 0 )
    {
        if ( newblock->L.PoW > coin->blocks.hwmPoW )
        {
            if ( newblock->height+1 > coin->blocks.maxblocks )
                coin->blocks.maxblocks = (newblock->height + 1);
            h = newblock->height;
            iguana_kvwrite(coin,coin->blocks.db,hash2.bytes,newblock,(uint32_t *)&h);
            coin->blocks.hwmheight = newblock->height;
            coin->blocks.hwmPoW = newblock->L.PoW;
            coin->blocks.hwmchain = hash2;
            coin->latest.blockhash = hash2;
            coin->latest.merkle_root = newblock->merkle_root;
            coin->latest.timestamp = newblock->timestamp;
            coin->latest.height = coin->blocks.hwmheight;
            //coin->latest.numtxids = newblock->firsttxidind + newblock->txn_count;
            iguana_gotdata(coin,0,newblock->height,hash2);
            //printf("%s height.%d PoW %f\n",bits256_str(hash2),block->height,block->PoW);
            if ( coin->blocks.initblocks != 0 && ((newblock->height % 100) == 0 || coin->blocks.hwmheight > coin->longestchain-10) )
                printf("ADD %s %d:%d:%d <- (%s) n.%u max.%u PoW %f 1st.%d numtx.%d\n",bits256_str(newblock->hash2),h,iguana_height(coin,coin->blocks.hwmchain),newblock->height,bits256_str(coin->blocks.hwmchain),coin->blocks.hwmheight+1,coin->blocks.maxblocks,newblock->L.PoW,newblock->L.numtxids,newblock->txn_count);
            iguana_queueblock(coin,newblock->height,hash2);
            coin->newhdrs++;
        }
    } else printf("error from setchain.%d\n",newblock->height);
    if ( memcmp(hash2.bytes,coin->blocks.hwmchain.bytes,sizeof(hash2)) != 0 )
    {
        if ( iguana_needhdrs(coin) == 0 )
            printf("ORPHAN.%s height.%d PoW %f vs best %f\n",bits256_str(hash2),newblock->height,newblock->L.PoW,coin->blocks.hwmPoW);
        newblock->height = -1;
    }
    //iguana_audit(coin);
    return(newblock->height);
}

int32_t iguana_lookahead(struct iguana_info *coin,bits256 *hash2p,int32_t height)
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

int32_t iguana_updatewaiting(struct iguana_info *coin,int32_t starti,int32_t max)
{
    int32_t i,height,gap,n = 0; uint32_t now;
    now = (uint32_t)time(NULL);
    height = starti;
    for (i=0; i<max; i++,height++)
    {
        gap = (height - coin->blocks.parsedblocks);
        if ( gap >= 0 )
            gap = sqrt(gap);
        if ( gap < 3 )
            gap = 3;
        if ( height < coin->R.numwaitingbits && coin->R.recvblocks[height] == 0 && coin->R.waitstart[height] != 0 && now > (coin->R.waitstart[height] + gap) )
        {
            //printf("restart height.%d width.%d widthready.%d %s\n",height,coin->width,coin->widthready,bits256_str(iguana_blockhash(coin,height)));
            iguana_waitclear(coin,height);
            iguana_waitstart(coin,height);
        }
    }
    height = starti;
    for (i=0; i<max; i++,height++)
        if ( coin->R.recvblocks[height] != 0 )
            n++;
    return(n);
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

void iguana_coinloop(void *arg)
{
    int32_t flag,i,n,w,width; struct iguana_info *coin,**coins = arg;
    n = (int32_t)(long)coins[0];
    coins++;
    printf("begin coinloop\n");
    coin = coins[0];
    iguana_possible_peer(coin,"127.0.0.1");
    iguana_possible_peer(coin,"108.58.252.82");
    iguana_possible_peer(coin,"74.207.233.193");
    iguana_possible_peer(coin,"130.211.146.81");
    while ( 1 )
    {
        flag = 0;
        for (i=0; i<n; i++)
        {
            if ( (coin= coins[i]) != 0 )
            {
                portable_mutex_lock(&coin->blocks.mutex);
                if ( time(NULL) > coin->peers.lastmetrics+60 )
                {
                    char fname[512]; FILE *fp; struct iguana_peer *addr;
                    iguana_peermetrics(coin);
                    coin->peers.lastmetrics = (uint32_t)time(NULL);
                    sprintf(fname,"%s_peers.txt",coin->symbol);
                    if ( (fp= fopen("peers.txt","w")) != 0 )
                    {
                        for (i=0; i<coin->peers.numranked; i++)
                            if ( (addr= coin->peers.ranked[i]) != 0 )
                                fprintf(fp,"%s\n",addr->ipaddr);
                        portable_mutex_lock(&coin->peers.rankedmutex);
                        iguana_kviterate(coin,coin->iAddrs,(uint64_t)(long)fp,iguana_kviAddriterator);
                        portable_mutex_unlock(&coin->peers.rankedmutex);
                        if ( ftell(fp) > iguana_filesize(fname) )
                        {
                            printf("new peers.txt %ld vs (%s) %ld\n",ftell(fp),fname,(long)iguana_filesize(fname));
                            fclose(fp);
                            iguana_renamefile(fname,"oldpeers.txt");
                            iguana_copyfile("peers.txt",fname,1);
                        } else fclose(fp);
                    }
                    iguana_possible_peer(coin,0);
                }
                if ( time(NULL) > coin->lastwaiting ) //iguana_MEMallocated(coin) < IGUANA_MAXMEMALLOCATED &&
                {
                    //printf("waiting\n"), getchar();
                    coin->width = width = sqrt(coin->longestchain-coin->blocks.parsedblocks);
                    coin->widthready = 0;
                    for (; width<(coin->longestchain-coin->blocks.parsedblocks); width<<=1)
                    {
                        w = iguana_updatewaiting(coin,coin->blocks.parsedblocks,width);
                        if ( width == coin->width )
                            coin->widthready = w;
                        if ( w != width )
                            break;
                        if ( (rand() % 100) == 0 && width > (coin->width<<2) )
                            printf("coin->width.%d higher width.%d all there\n",coin->width,width);
                    }
                    coin->lastwaiting = (uint32_t)time(NULL);
                }
                //printf("updatehdrs\n"), getchar();
                iguana_updatehdrs(coin);
                if ( coin->blocks.parsedblocks < coin->blocks.hwmheight-3 )
                {
                    //printf("processrecv\n"), getchar();
                    width = sqrt(coin->longestchain-coin->blocks.parsedblocks);
                    if ( width < 1 )
                        width = 1;
                    //if ( (w= iguana_updatewaiting(coin,coin->blocks.parsedblocks,width)) >= (width>>1) )
                    {
                        while ( iguana_processrecv(coin) == 0 && coin->blocks.parsedblocks < coin->blocks.hwmheight-3 )
                        {
                            if ( (coin->blocks.parsedblocks > coin->longestchain-1000 && (coin->blocks.parsedblocks % 100) == 1) ||
                                (coin->blocks.parsedblocks > coin->longestchain-10000 && (coin->blocks.parsedblocks % 1000) == 1) ||
                                (coin->blocks.parsedblocks > coin->longestchain-1000000 && (coin->blocks.parsedblocks % 10000) == 1) ||
                                (coin->blocks.parsedblocks > coin->firstblock+100 && (coin->blocks.parsedblocks % 100000) == 1) )
                            {
                                if ( 1 && coin->blocks.parsedblocks > coin->loadedLEDGER.snapshot.height+2 )
                                    iguana_syncs(coin);
                            }
                            flag++;
                        }
                    } // else printf("w.%d of %d: skip processrecv\n",w,width);
                }
                portable_mutex_unlock(&coin->blocks.mutex);
            }
        }
        if ( flag == 0 )
            usleep(1000);
    }
}

void iguana_main(int32_t argc,const char *symbols[])
{
    struct iguana_info *coins[32]; char dirname[512]; int32_t i,n,mapflags;
    mapflags = IGUANA_MAPRECVDATA | IGUANA_MAPHASHTABLES*IGUANA_MAPTXIDITEMS | IGUANA_MAPHASHTABLES*IGUANA_MAPPKITEMS | IGUANA_MAPHASHTABLES*IGUANA_MAPBLOCKITEMS | IGUANA_MAPHASHTABLES*IGUANA_MAPPEERITEMS;
    mycalloc(0,0,0);
    ensure_directory("DB");
    ensure_directory("tmp");
    for (i=n=0; i<sizeof(coins)/sizeof(*coins); i++)
    {
        if ( symbols[i] == 0 || symbols[i][0] == 0 )
            break;
        sprintf(dirname,"DB/%s",symbols[i]);
        ensure_directory(dirname);
        sprintf(dirname,"tmp/%s",symbols[i]);
        ensure_directory(dirname);
        coins[1 + n++] = iguana_startcoin((char *)symbols[i],400000,mapflags);
    }
    coins[0] = (void *)((long)n);
    //if ( blockflag == 0 )
    //    iguana_launch("coinloop",iguana_coinloop,coins,IGUANA_PERMTHREAD);
    //else
        iguana_coinloop(coins);
}
