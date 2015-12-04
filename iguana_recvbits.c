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

int64_t iguana_packetsallocated(struct iguana_info *coin) { return(coin->R.packetsallocated - coin->R.packetsfreed); };

uint8_t *iguana_decompress(struct iguana_info *coin,int32_t height,int32_t *datalenp,uint8_t *bits,int32_t numbits,int32_t origdatalen)
{
    uint32_t hdrlen,checklen;
    memcpy(&hdrlen,bits,sizeof(hdrlen));
    bits = &bits[sizeof(hdrlen)];
    *datalenp = 0;
    if ( (hdrlen & (1 << 31)) != 0 )
    {
        hdrlen ^= (1 << 31);
        if ( (hdrlen >> 3) == origdatalen )
        {
            *datalenp = origdatalen;
            return(bits);
        } else printf("\n>>>>>>>>> iguana_decompress.%d numbits.%d %d != origlen.%d\n",height,hdrlen,hdrlen>>3,origdatalen), getchar();
    }
    else if ( hconv_bitlen(hdrlen) == hconv_bitlen(numbits) )
    {
        if ( (checklen= ramcoder_decompress(coin->R.decompressed,sizeof(coin->R.decompressed),bits,hdrlen,coin->chain->rseed)) == origdatalen )
        {
            //printf("DECOMPRESSED %d to %d\n",hconv_bitlen(hdrlen),checklen);
            *datalenp = origdatalen;
            return(coin->R.decompressed);
        }
        else
        {
            printf("\n>>>>>>>>> iguana_decompress.%d hdrlen.%d checklen.%d != origdatalen.%d\n",height,hdrlen,checklen,origdatalen);
            int32_t j;
            for (j=0; j<hconv_bitlen(numbits); j++)
                printf("%02x ",bits[j]);
            printf("compressed.%d\n",numbits/8);
            getchar();
        }
    }
    else
    {
        printf("\n>>>>>>>>>> iguana_decompress.%d hdrlen.%d != numbits.%d\n",height,hdrlen,numbits);
        int32_t j;
        for (j=0; j<=numbits/8; j++)
            printf("%02x ",bits[j]);
        printf("compressed.%d\n",numbits/8);
        getchar();
    }
    return(0);
}

struct iguana_msgtx *iguana_validpending(struct iguana_info *coin,struct iguana_pending *ptr,struct iguana_block *space)
{
    struct iguana_block *checkblock; uint8_t *data; int32_t datalen,len; struct iguana_msgtx *tx = 0;
    *space = ptr->block;
    if ( coin->R.recvblocks == 0 || ptr->block.height >= coin->R.numwaitingbits )
    {
        printf("illegal pending height.%d vs %d\n",ptr->block.height,coin->R.numwaitingbits);
        return(0);
    }
    if ( ptr->origdatalen > 0 && ptr->block.height < coin->longestchain && ptr->block.height < coin->blocks.hwmheight )
    {
        if ( (checkblock= iguana_block(coin,space,ptr->block.height)) != 0 )
        {
            if ( iguana_blockcmp(coin,checkblock,space,1) == 0 )
            {
                data = iguana_decompress(coin,ptr->block.height,&datalen,ptr->data,ptr->datalen << 3,ptr->origdatalen);
                //printf("parsed.%d vs max.%d height.%d data.%p\n",coin->blocks.parsedblocks,coin->R.numwaitingbits,ptr->block.height,data);
                if ( data != 0 && iguana_setdependencies(coin,space) == ptr->block.height )
                {
                    if ( (tx= iguana_gentxarray(coin,&len,space,data,datalen)) != 0 && len == datalen )
                        return(tx);
                } else printf("iguana_validpending: error gentx block.%d\n",coin->blocks.parsedblocks);
            } else printf("iguana_validpending: error setting vars block.%d\n",ptr->block.height);
            if ( tx != 0 )
                iguana_freetx(tx,ptr->numtx);
        } else printf("iguana_validpending cant get checkblock %d vs hwmheight.%d\n",ptr->block.height,coin->blocks.hwmheight);
    }
    return(0);
}

void iguana_recvalloc(struct iguana_info *coin,int32_t numitems)
{
    int32_t numcheckpoints;
    coin->R.waitingbits = myrealloc('W',coin->R.waitingbits,coin->R.waitingbits==0?0:coin->R.numwaitingbits/8+1,numitems/8+1);
    coin->R.recvblocks = myrealloc('W',coin->R.recvblocks,coin->R.recvblocks==0?0:coin->R.numwaitingbits * sizeof(*coin->R.recvblocks),numitems * sizeof(*coin->R.recvblocks));
    coin->R.waitstart = myrealloc('W',coin->R.waitstart,coin->R.waitstart==0?0:coin->R.numwaitingbits * sizeof(*coin->R.waitstart),numitems * sizeof(*coin->R.waitstart));
    numcheckpoints = (numitems / IGUANA_HDRSCOUNT) + 1;
    coin->R.checkpoints = myrealloc('h',coin->R.checkpoints,coin->R.checkpoints==0?0:coin->R.numcheckpoints * sizeof(*coin->R.checkpoints),numcheckpoints * sizeof(*coin->R.checkpoints));
    coin->R.numcheckpoints = numcheckpoints;
    printf("realloc waitingbits.%d -> %d\n",coin->R.numwaitingbits,numitems);
    coin->R.numwaitingbits = numitems;
}

int32_t iguana_processrecv(struct iguana_info *coin)
{
    int32_t height; struct iguana_block space; struct iguana_msgtx *tx = 0;
    struct iguana_pending *ptr = 0; int32_t retval = -1;
    if ( coin->longestchain > coin->R.numwaitingbits-10000 )
        iguana_recvalloc(coin,coin->longestchain + 20000);
    height = coin->blocks.parsedblocks;
    if ( coin->R.recvblocks != 0 && height < coin->R.numwaitingbits )
    {
        if ( (ptr= coin->R.recvblocks[height]) != 0 )
        {
            //printf("iguana_processrecv height.%d %p\n",height,ptr);
            coin->R.recvblocks[height] = 0;
            if ( (tx= iguana_validpending(coin,ptr,&space)) != 0 )
            {
                retval = iguana_parseblock(coin,&space,tx,ptr->numtx);
                if ( space.L.numunspents+space.numvouts != coin->latest.dep.numunspents )
                    printf("block->firstvout+block->numvouts (%d+%d) != %d coin->latest.deps.numunspentinds\n",space.L.numunspents,space.numvouts,coin->latest.dep.numunspents), getchar();
                if ( retval < 0 )
                    printf("iguana_processrecv: error parsing block.%d tx.%p\n",ptr->block.height,tx);
                if ( tx != 0 )
                    iguana_freetx(tx,ptr->numtx);
            } else printf("error getting pending %d %p\n",height,ptr);
            if ( coin->R.maprecvdata == 0 )
            {
                coin->R.packetsfreed += ptr->allocsize;
                myfree(ptr,ptr->allocsize);
            }
        }
        else if ( time(NULL) > coin->parsetime+1 )
        {
            coin->parsetime = (uint32_t)time(NULL);
            printf("backstop.%d %s\n",height,bits256_str(iguana_blockhash(coin,height)));
            iguana_waitclear(coin,height);
            iguana_waitstart(coin,height);
            iguana_updatewaiting(coin,height+1,100);
        }
    }
    return(retval);
}

void iguana_gotblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *block,struct iguana_msgtx *tx,int32_t numtx,uint8_t *data,int32_t datalen)
{
    struct iguana_block space;
    //portable_mutex_lock(&coin->blocks.mutex);
    if ( addr != 0 )
    {
        if ( addr->pendblocks > 0 )
            addr->pendblocks--;
        addr->lastblockrecv = (uint32_t)time(NULL);
        addr->recvblocks += 1.;
        addr->recvtotal += datalen;
        iguana_waitclear(coin,block->height);
        if ( 1 && (rand() % 1000) == 0 )
            printf("%-15s pend.(%d %d) got block.%-6d recvblocks %-8.0f recvtotal %-10.0f\n",addr->ipaddr,addr->pendhdrs,addr->pendblocks,block->height,addr->recvblocks,addr->recvtotal);
    }
    if ( block->height >= coin->blocks.parsedblocks )
    {
        memset(&space,0,sizeof(space));
        if ( iguana_kvread(coin,coin->blocks.db,0,&space,(uint32_t *)&block->height) != 0 )
            iguana_mergeblock(&space,block);
        else printf("iguana_gotblock: cant read block.%d\n",block->height);
        iguana_recvblock(coin,addr,&space,tx,numtx,data,datalen);
        iguana_kvwrite(coin,coin->blocks.db,0,&space,(uint32_t *)&space.height);
    } // else printf("orphan %d block.%s from gotblockM\n",block->height,bits256_str(block->hash2));
    iguana_waitclear(coin,block->height);
    //portable_mutex_unlock(&coin->blocks.mutex);
}

int32_t iguana_recvblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *block,struct iguana_msgtx *tx,int32_t numtx,uint8_t *data,int32_t origdatalen)
{
    struct iguana_pending *ptr; int32_t allocsize,checklen,numbits; uint32_t datalen,hdrlen;
    if ( coin->R.recvblocks == 0 || coin->R.recvblocks[block->height] != 0 )
    {
        coin->sleeptime++;
        if ( coin->sleeptime > 10000 )
            coin->sleeptime = 10000;
        if ( 0 && addr != coin->peers.localaddr )
            printf("%s recv duplicate at height.%d sleepmillis %.3f\n",addr->ipaddr,block->height,(double)coin->sleeptime/1000.); // add validation/merging
    }
    else
    {
        coin->sleeptime *= .995;
        if ( coin->sleeptime < 1000 )
            coin->sleeptime = 1000;
        // validate block here
        datalen = origdatalen;
        hdrlen = (1 << 31) | (datalen << 3);
        coin->R.srcdatalen += datalen;
        if ( 0 && (numbits= ramcoder_compress(coin->R.compressed,sizeof(coin->R.compressed),data,datalen,coin->R.histo,coin->chain->rseed)) > 0 )
        {
            memset(coin->R.checkbuf,0,datalen);
            if ( (checklen= ramcoder_decompress(coin->R.checkbuf,sizeof(coin->R.checkbuf),coin->R.compressed,numbits,coin->chain->rseed)) == datalen )
            {
                if ( memcmp(coin->R.checkbuf,data,datalen) == 0 )
                {
                    hdrlen = numbits;
                    data = coin->R.compressed;
                    printf("height.%d datalen.%d -> numbits.%d %d compression ratio %.3f [%.4f]\n",block->height,datalen,numbits,hconv_bitlen(numbits),(double)datalen/hconv_bitlen(numbits),(double)coin->R.srcdatalen/(coin->R.compressedtotal+hconv_bitlen(numbits)+sizeof(hdrlen)));
                    datalen = hconv_bitlen(numbits);
                } else printf("ramcoder data datalen.%d compare error\n",datalen), getchar();
            }
            else printf("ramcoder codec error origdatalen.%d numbits.%d datalen. %d -> %d\n",origdatalen,numbits,datalen,checklen), getchar();
        } //else printf("ramcoder compress error %d -> numbits.%d\n",datalen,numbits), getchar();
        coin->R.compressedtotal += (datalen + sizeof(hdrlen));
        allocsize = (int32_t)(sizeof(*ptr) + datalen + sizeof(hdrlen));
        if ( coin->R.maprecvdata != 0 )
        {
            ptr = iguana_tmpalloc(coin,"recv",&coin->R.RSPACE,allocsize);
            if ( block->height > coin->R.RSPACE.maxheight )
                coin->R.RSPACE.maxheight = block->height;
            ptr->next = (int32_t)((long)iguana_tmpalloc(coin,"recv",&coin->R.RSPACE,0) - (long)ptr);
        }
        else
        {
            ptr = mycalloc('P',1,allocsize);
            coin->R.packetsallocated += allocsize;
        }
        ptr->allocsize = allocsize;
        ptr->datalen = datalen;
        memcpy(ptr->data,&hdrlen,sizeof(hdrlen));
        memcpy(&ptr->data[sizeof(hdrlen)],data,datalen);
        ptr->ipbits = addr != 0 ? addr->ipbits : 0;
        ptr->block = *block;
        ptr->numtx = numtx;
        ptr->origdatalen = origdatalen;
        if ( (rand() % 1000) == 0 )
            printf("%s recv.%d ptr.%p datalen.%d orig.%d %.3f | parsed.%d hwm.%d longest.%d | %d/%d elapsed %.2f\n",addr != 0 ? addr->ipaddr : "local",block->height,ptr,datalen,origdatalen,(double)origdatalen/datalen,coin->blocks.parsedblocks,coin->blocks.hwmheight,coin->longestchain,iguana_updatewaiting(coin,coin->blocks.parsedblocks,coin->width*10),coin->width*10,(double)(time(NULL)-coin->starttime)/60.);
        coin->R.recvblocks[block->height] = ptr;
    }
    return(0);
}

int32_t iguana_setwaitstart(struct iguana_info *coin,int32_t height)
{
    if ( coin->R.waitstart[height] == 0 )
        coin->R.numwaiting++;
    coin->R.waitstart[height] = (uint32_t)time(NULL);
    SETBIT(coin->R.waitingbits,height);
    return(coin->R.numwaiting);
}

struct iguana_peer *iguana_choosepeer(struct iguana_info *coin)
{
    int32_t i,j,r,iter; struct iguana_peer *addr;
    r = rand();
    portable_mutex_lock(&coin->peers.rankedmutex);
    if ( coin->peers.numranked > 0 )
    {
        for (j=0; j<coin->peers.numranked; j++)
        {
            i = (j + r) % IGUANA_MAXPEERS;
            if ( (addr= coin->peers.ranked[i]) != 0 && addr->pendblocks < IGUANA_MAXPENDING && addr->dead == 0 && addr->usock >= 0 )
            {
                portable_mutex_unlock(&coin->peers.rankedmutex);
                return(addr);
            }
        }
    }
    portable_mutex_unlock(&coin->peers.rankedmutex);
    for (iter=0; iter<2; iter++)
    {
        for (i=0; i<IGUANA_MAXPEERS; i++)
        {
            addr = &coin->peers.active[(i + r) % IGUANA_MAXPEERS];
            if ( addr->dead == 0 && addr->usock >= 0 && (iter == 1 || addr->pendblocks < IGUANA_MAXPENDING) )
                return(addr);
        }
    }
    return(0);
}

int32_t iguana_waitstart(struct iguana_info *coin,int32_t height)
{
    bits256 hash2;
    if ( height < coin->R.numwaitingbits && coin->R.recvblocks != 0 && coin->R.recvblocks[height] == 0 && GETBIT(coin->R.waitingbits,height) == 0 )
    {
        hash2 = iguana_blockhash(coin,height);
        return(iguana_queueblock(coin,height,hash2));
    } else if ( coin->R.recvblocks != 0 && height < coin->R.numwaitingbits )
        printf("iguana_waitstart ignore height.%d < %d, %p GETBIT.%d\n",height,coin->R.numwaitingbits,coin->R.recvblocks[height],GETBIT(coin->R.waitingbits,height));
    return(0);
}

int32_t iguana_waitclear(struct iguana_info *coin,int32_t height)
{
    if ( height < coin->R.numwaitingbits )
    {
        //printf("%d waitclear.%d parsed.%d\n",coin->R.numwaiting,height,coin->blocks.parsedblocks);
        if ( coin->R.numwaiting > 0 )
            coin->R.numwaiting--;
        coin->R.waitstart[height] = 0;
        CLEARBIT(coin->R.waitingbits,height);
        return(0);
    }
    return(-1);
}

void *filealloc(struct iguana_mappedptr *M,char *fname,struct iguana_memspace *mem,long size)
{
    //printf("mem->used %ld size.%ld | size.%ld\n",mem->used,size,mem->size);
    //printf("filemalloc.(%s) new space.%ld %s\n",fname,mem->size,mbstr(size));
    memset(M,0,sizeof(*M));
    mem->size = size;
    if ( iguana_mappedptr(0,M,mem->size,1,fname) == 0 )
    {
        printf("couldnt create mapped file.(%s)\n",fname);
        exit(-1);
    }
    mem->ptr = M->fileptr;
    mem->used = 0;
    return(M->fileptr);
}

void *iguana_memalloc(struct iguana_memspace *mem,long size,int32_t clearflag)
{
    void *ptr = 0;
    if ( (mem->used + size) > mem->size )
    {
        printf("alloc: (mem->used %ld + %ld size) %ld > %ld mem->size\n",mem->used,size,(mem->used + size),mem->size);
        while ( 1 )
            sleep(1);
    }
    ptr = (void *)((uint64_t)mem->ptr + (uint64_t)mem->used);
    mem->used += size;
    if ( size*clearflag != 0 )
        memset(ptr,0,size);
    if ( mem->alignflag != 0 && (mem->used & 0xf) != 0 )
        mem->used += 0x10 - (mem->used & 0xf);
    //printf(">>>>>>>>> USED alloc %ld used %ld alloc.%ld\n",size,mem->used,mem->size);
    return(ptr);
}

void *iguana_tmpalloc(struct iguana_info *coin,char *name,struct iguana_memspace *mem,long origsize)
{
    char fname[1024]; void *ptr; long size,i;
    portable_mutex_lock(&mem->mutex);
    if ( origsize != 0 && (mem->M.fileptr == 0 || (mem->used + origsize) > mem->size) )
    {
        if ( mem->M.fileptr != 0 && strcmp(name,"recv") == 0 )
        {
            //uint64_t allocated; int32_t n;
            //msync(mem->M.fileptr,mem->M.allocsize,MS_SYNC);
            if ( coin->R.numold > 0 )
            {
                for (i=0; i<coin->R.numold; i++)
                {
                    if ( coin->R.oldRSPACE[i].M.fileptr != 0 && coin->blocks.parsedblocks > coin->R.oldRSPACE[i].maxheight )
                    {
                        printf("PURGE.(%s) oldRSPACE[%ld] as coin->blocks.parsedblocks %d > %d coin->R.oldRSPACE[i].maxheight\n",coin->R.oldRSPACE[i].M.fname,i,coin->blocks.parsedblocks,coin->R.oldRSPACE[i].maxheight);
                        coin->R.RSPACE.openfiles--;
#ifdef __APPLE__
                        iguana_closemap(&coin->R.oldRSPACE[i].M);
                        iguana_removefile(coin->R.oldRSPACE[i].M.fname,0);
#endif
                        coin->R.oldRSPACE[i].M.fileptr = 0;
                    }
                }
            }
            coin->R.oldRSPACE = myrealloc('e',coin->R.oldRSPACE,coin->R.numold * sizeof(*coin->R.oldRSPACE),(coin->R.numold+1) * sizeof(*coin->R.oldRSPACE));
            coin->R.oldRSPACE[coin->R.numold++] = coin->R.RSPACE;
            coin->R.RSPACE.openfiles++;
            //iguana_closemap(&mem->M);
            //allocated = iguana_validaterecv(coin,&n,coin->R.RSPACE.M.fname);
            //printf("recvbits: %s validated.%d %s %lld\n",coin->R.RSPACE.M.fname,n,mbstr(allocated),(long long)allocated);
        } else coin->TMPallocated += origsize;
        memset(&mem->M,0,sizeof(mem->M));
        sprintf(fname,"tmp/%s/%s.%d",coin->symbol,name,mem->counter), iguana_compatible_path(fname);
        mem->counter++;
        if ( mem->size == 0 )
        {
            if ( strcmp(name,"recv") == 0 )
                mem->size = IGUANA_RSPACE_SIZE;// * ((strcmp(coinstr,"BTC") == 0) ? 8 : 1);
            else mem->size = (1024 * 1024 * 64);
        }
        if ( mem->size > origsize )
            size = mem->size;
        else size = origsize;
        if ( filealloc(&mem->M,fname,mem,size) == 0 )
        {
            printf("couldnt map tmpfile %s\n",fname);
            return(0);
        }
    }
    ptr = iguana_memalloc(mem,origsize,1);
    portable_mutex_unlock(&mem->mutex);
    return(ptr);
}

