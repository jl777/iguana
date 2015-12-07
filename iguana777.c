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

double PoW_from_compact(uint32_t nBits,uint8_t unitval) // NOT consensus safe, but most of the time will be correct
{
	uint32_t nbytes,nbits,i,n; double PoW;
    nbytes = (nBits >> 24) & 0xFF;
    nbits = (8 * (nbytes - 3));
    PoW = nBits & 0xFFFFFF;
    if ( nbytes > unitval )
    {
        printf("illegal nBits.%x\n",nBits);
        return(0.);
    }
    if ( (n= ((8* (unitval-3)) - nbits)) != 0 ) // 0x1d00ffff is genesis nBits so we map that to 1.
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
        PoW = PoW_from_compact(nBits,coin->chain->unitval);
        height = 0;
        firsttxidind = firstvout = firstvin = 1;
        printf("set genesis vars nBits.%x\n",nBits);
    }
    else
    {
        if ( (prev= iguana_findblock(coin,&prevspace,prevhash)) == 0 )
        {
            if ( iguana_needhdrs(coin) == 0 )
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
            PoW = (PoW_from_compact(nBits,coin->chain->unitval) + prev->L.PoW);
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
            if ( (newblock->height % coin->chain->bundlesize) == 0 )
                iguana_addcheckpoint(coin,newblock->height,hash2);
            //printf("%s height.%d PoW %f\n",bits256_str(hash2),block->height,block->PoW);
            if ( coin->blocks.initblocks != 0 && ((newblock->height % 100) == 0 || coin->blocks.hwmheight > coin->longestchain-10) )
                printf("ADD %s %d:%d:%d <- (%s) n.%u max.%u PoW %f 1st.%d numtx.%d\n",bits256_str(newblock->hash2),h,iguana_height(coin,coin->blocks.hwmchain),newblock->height,bits256_str(coin->blocks.hwmchain),coin->blocks.hwmheight+1,coin->blocks.maxblocks,newblock->L.PoW,newblock->L.numtxids,newblock->txn_count);
            //iguana_queueblock(coin,newblock->height,hash2);
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

void iguana_recvalloc(struct iguana_info *coin,int32_t numitems)
{
    int32_t numcheckpoints;
    coin->R.waitingbits = myrealloc('W',coin->R.waitingbits,coin->R.waitingbits==0?0:coin->R.numwaitingbits/8+1,numitems/8+1);
    //coin->R.recvblocks = myrealloc('W',coin->R.recvblocks,coin->R.recvblocks==0?0:coin->R.numwaitingbits * sizeof(*coin->R.recvblocks),numitems * sizeof(*coin->R.recvblocks));
    coin->R.waitstart = myrealloc('W',coin->R.waitstart,coin->R.waitstart==0?0:coin->R.numwaitingbits * sizeof(*coin->R.waitstart),numitems * sizeof(*coin->R.waitstart));
    coin->R.blockhashes = myrealloc('W',coin->R.blockhashes,coin->R.blockhashes==0?0:coin->R.numwaitingbits * sizeof(*coin->R.blockhashes),numitems * sizeof(*coin->R.blockhashes));
    numcheckpoints = (numitems / coin->chain->bundlesize) + 1;
    coin->R.checkpoints = myrealloc('h',coin->R.checkpoints,coin->R.checkpoints==0?0:coin->R.numcheckpoints * sizeof(*coin->R.checkpoints),numcheckpoints * sizeof(*coin->R.checkpoints));
    coin->R.numcheckpoints = numcheckpoints;
    printf("realloc waitingbits.%d -> %d\n",coin->R.numwaitingbits,numitems);
    coin->R.numwaitingbits = numitems;
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

void iguana_helper(void *arg)
{
    int32_t flag,i,n; struct iguana_checkpoint *checkpoint; struct iguana_info *coin,**coins = arg;
    n = (int32_t)(long)coins[0];
    coins++;
    printf("start helper\n");
    while ( 1 )
    {
        flag = 0;
        for (i=0; i<n; i++)
        {
            if ( (coin= coins[i]) != 0 && coin->firstblock != 0 )
            {
                if ( (checkpoint= queue_dequeue(&coin->emitQ,0)) != 0 )
                {
                    printf("START emittxdata.%d\n",checkpoint->height);
                    iguana_emittxdata(coin,checkpoint), flag++;
                    printf("FINISH emittxdata.%d\n",checkpoint->height);
                }
            }
        }
        if ( flag == 0 )
            usleep(10000);
    }
}

void iguana_coinloop(void *arg)
{
    int32_t flag,i,n; uint32_t now; struct iguana_info *coin,**coins = arg;
    n = (int32_t)(long)coins[0];
    for (i=0; i<IGUANA_NUMHELPERS; i++)
        iguana_launch("helpers",iguana_helper,coins,IGUANA_HELPERTHREAD);
    coins++;
    printf("begin coinloop[%d]\n",n);
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
                if ( now > coin->peers.lastmetrics+60 )
                    coin->peers.lastmetrics = iguana_updatemetrics(coin); // ranks peers
                {
                    portable_mutex_lock(&coin->recv_mutex);
                        if ( coin->R.numwaitingbits < coin->longestchain+100000 ) // assumes < 100Kblocks/iter
                            iguana_recvalloc(coin,coin->longestchain + 200000);
                    portable_mutex_unlock(&coin->recv_mutex);
                }
                if ( now > coin->lastwaiting )
                {
                    coin->lastwaiting = iguana_issuereqs(coin); // updates waiting Q's and issues reqs
                    coin->lastwaiting = now;
                }
                {
                    portable_mutex_lock(&coin->recv_mutex);
                        flag += iguana_updatehdrs(coin); // creates block headers directly or from blockhashes
                    portable_mutex_unlock(&coin->recv_mutex);
                }
                if ( 0 && coin->blocks.recvblocks < coin->blocks.hwmheight-coin->chain->minconfirms )
                {
                    portable_mutex_lock(&coin->ramchain_mutex);
                        if ( iguana_updateramchain(coin) != 0 )
                            iguana_syncs(coin), flag++; // merge ramchain fragments into full ramchain
                        flag += iguana_processjsonQ(coin);
                    portable_mutex_unlock(&coin->ramchain_mutex);
                }
            }
        }
        if ( flag != 0 )
            printf("mainloop flag.%d\n",flag);
        if ( flag == 0 )
            usleep(10000);
    }
}
